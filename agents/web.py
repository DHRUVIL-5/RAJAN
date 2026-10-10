"""
RAJAN Web Agent
Web application security testing:
  - Tech fingerprinting
  - Directory & endpoint discovery
  - XSS (reflected) + injection sweep (LFI, SSTI, Open Redirect, CSRF)
  - SQL Injection (error-based + time-based blind)
  - IDOR / broken access control
  - SSRF (internal + cloud metadata)
  - Command Injection (time-based)
  - Authentication bypass (default credentials) + cookie flag checks
  - JavaScript file analysis (API keys, tokens, secrets)
  - SSL/TLS (certificate validity/expiry, outdated protocol support)

Scope-enforced on every request + rate limiting + dry-run support.
"""

import re
import ssl
import socket
import time
import datetime
import urllib.parse
import requests
import requests.exceptions
import urllib3

from agents.base import BaseAgent
from tools.toolmanager import ToolManager

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WebAgent(BaseAgent):
    def __init__(self, memory, llm, logger, session_id, target):
        super().__init__(memory, llm, logger, session_id, target)
        self.name = "WebAgent"
        self.base_url = f"https://{self.target}"
        self._base_checked = False
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "Mozilla/5.0 (RAJAN Scanner)"})
        self._session.verify = False  # handle self-signed certs

    # ── HTTP helpers (scope-enforced, rate-limited, dry-run aware) ──────────

    def _get(self, path="", params=None, timeout=8):
        url = path if str(path).startswith(("http://", "https://")) else f"{self.base_url}{path}"
        if not self.is_in_scope(url):
            return 0, "", {}
        if self.dry_run:
            self.logger.info(f"[DRY RUN] GET {url}", "Web")
            return 200, "<html>dry-run</html>", {}
        self._rate_limit()
        try:
            r = self._session.get(url, params=params, timeout=timeout,
                                   allow_redirects=False)
            return r.status_code, r.text[:16384], dict(r.headers)
        except requests.exceptions.HTTPError as e:
            # Return status code when available, otherwise log and return 0
            code = e.response.status_code if e.response else 0
            try:
                self.logger.warning(f"HTTP error GET {url}: {e}", "Web")
            except Exception:
                pass
            return code, "", {}
        except requests.exceptions.RequestException as e:
            # Network-level errors (connection, timeout, SSL)
            try:
                self.logger.warning(f"Request failed GET {url}: {e}", "Web")
            except Exception:
                pass
            return 0, "", {}
        except Exception as e:
            try:
                self.logger.error(f"Unexpected error GET {url}: {e}", "Web")
            except Exception:
                pass
            return 0, "", {}

    def _post(self, path="", data=None, timeout=8):
        url = f"{self.base_url}{path}"
        if not self.is_in_scope(url):
            return 0, "", {}
        if self.dry_run:
            self.logger.info(f"[DRY RUN] POST {url}", "Web")
            return 200, "", {}
        self._rate_limit()
        try:
            r = self._session.post(url, data=data or {}, timeout=timeout,
                                    allow_redirects=False)
            return r.status_code, r.text[:8192], dict(r.headers)
        except requests.exceptions.RequestException as e:
            try:
                self.logger.warning(f"Request failed POST {url}: {e}", "Web")
            except Exception:
                pass
            return 0, "", {}
        except Exception as e:
            try:
                self.logger.error(f"Unexpected error POST {url}: {e}", "Web")
            except Exception:
                pass
            return 0, "", {}

    def _resolve_base(self):
        """Pick https:// or http:// as the reachable base URL (once)."""
        if self._base_checked or self.dry_run:
            return
        self._base_checked = True
        code, _, _ = self._get("/", timeout=5)
        if code == 0:
            if self.base_url.startswith("https://"):
                alt = f"http://{self.target}"
            else:
                alt = f"https://{self.target}"
            code_alt, _, _ = self._get(alt + "/", timeout=5)
            if code_alt != 0:
                self.base_url = alt

    # ── Parameter / page helpers ────────────────────────────────────────────

    def _fetch_home(self):
        self._resolve_base()
        return self._get("/", timeout=8)

    def _discover_params(self):
        """Collect query parameters to test: those found in the target's own
        links/forms plus a small list of commonly injectable names."""
        code, body, _ = self._fetch_home()
        params = set()
        if code != 0:
            body = ""
        for url in re.findall(r"[^\s\"'<>]*\?[^\s\"'<>]+", body):
            qs = url.split("?", 1)[1]
            for pair in qs.split("&"):
                name = pair.split("=", 1)[0]
                if name and re.fullmatch(r"[A-Za-z0-9_.\-]{1,30}", name):
                    params.add(name)
        common = [
            "q", "s", "search", "query", "id", "p", "page", "file", "path",
            "include", "template", "tpl", "theme", "url", "link", "redirect",
            "next", "return", "dest", "img", "src", "host", "view", "action",
            "cmd", "exec", "download", "lang", "cat",
        ]
        return sorted(params | set(common))

    def _params_by_keyword(self, params, keywords):
        picked = [p for p in params
                  if any(k in p.lower() for k in keywords)]
        return picked

    def _check_cookie_flags(self):
        code, _, headers = self._fetch_home()
        if code == 0:
            return
        set_cookie = str(headers.get("Set-Cookie", "")).lower()
        if not set_cookie or "session" not in set_cookie:
            return
        if "httponly" not in set_cookie:
            self.add_finding(
                "Session Cookie Missing HttpOnly Flag", "MEDIUM",
                "A session cookie is set without the HttpOnly flag, allowing "
                "JavaScript (e.g. XSS) to read the session token.",
                self.base_url, f"Set-Cookie: {set_cookie[:200]}", "T1552"
            )
        if "secure" not in set_cookie:
            self.add_finding(
                "Session Cookie Missing Secure Flag", "LOW",
                "A session cookie is set without the Secure flag, allowing it "
                "to be sent over unencrypted HTTP.",
                self.base_url, f"Set-Cookie: {set_cookie[:200]}", "T1573"
            )

    # ── Task routing ────────────────────────────────────────────────────────

    def run_task(self, task_name):
        tl = (task_name or "").lower()
        if any(k in tl for k in ("ssl", "tls", "cert")):
            return self.ssl_tls_check()
        if any(k in tl for k in ("finger", "tech")):
            return self.tech_fingerprinting()
        if any(k in tl for k in ("dir", "endpoint", "discovery", "bust")):
            return self.directory_discovery()
        if any(k in tl for k in ("xss", "cross-site")):
            return self.xss_testing()
        if "command" in tl or "cmd" in tl:
            return self.command_injection_testing()
        if any(k in tl for k in ("sql", "sqli", "injection")):
            return self.sqli_testing()
        if any(k in tl for k in ("idor", "access control", "broken access")):
            return self.idor_testing()
        if "ssrf" in tl:
            return self.ssrf_testing()
        if any(k in tl for k in ("lfi", "traversal", "file inclusion")):
            return self.lfi_testing()
        if any(k in tl for k in ("ssti", "template")):
            return self.ssti_testing()
        if "csrf" in tl:
            return self.csrf_testing()
        if "redirect" in tl:
            return self.open_redirect_testing()
        if any(k in tl for k in ("auth", "session", "credential", "login")):
            return self.auth_testing()
        if any(k in tl for k in ("js ", "js file", "javascript", "secret")):
            return self.js_secret_scan()
        if any(k in tl for k in ("scan", "sweep", "check", "test", "vuln")):
            # Generic web vulnerability sweep
            self.tech_fingerprinting()
            self.xss_testing()
            self.sqli_testing()
            self.idor_testing()
            self.ssrf_testing()
            self.auth_testing()
            return "Web vulnerability sweep complete"
        # Default: fingerprint the target
        return self.tech_fingerprinting()

    # ── Individual checks ───────────────────────────────────────────────────

    def tech_fingerprinting(self):
        if not self.is_in_scope(self.target):
            return f"Target {self.target} out of scope — skipped"
        if self.dry_run:
            self.logger.info("[DRY RUN] tech fingerprinting simulated", "Web")
            return "Tech fingerprinting skipped (dry run)"
        code, body, headers = self._fetch_home()
        if code == 0:
            self.logger.info("Base URL unreachable — cannot fingerprint", "Web")
            return "Base URL unreachable — tech fingerprinting skipped"

        results = []
        server = headers.get("Server", "")
        if server:
            self.save_intel("tech", "server", server)
            self.logger.success(f"Server: {server}", "Web")
            results.append(f"Server: {server}")
        powered = headers.get("X-Powered-By", "")
        if powered:
            self.save_intel("tech", "powered_by", powered)
            self.logger.success(f"X-Powered-By: {powered}", "Web")
            results.append(f"Powered by: {powered}")

        body_l = body.lower()
        marker_map = {
            "wordpress": ["wp-content", "wp-login", "wp-includes", "wordpress"],
            "drupal": ["drupal.settings", "drupal", "paths/drupal"],
            "php": ["phpsessid"],
            "asp.net": ["asp.net", "__viewstate", "aspx"],
            "ruby on rails": ["csrf-token", "rails"],
            "node.js": ["express", "node.js"],
            "react": ["_next/static", "react"],
            "django": ["csrftoken"],
            "spring": ["x-powered-by: servlet", "jsessionid"],
        }
        for tech, markers in marker_map.items():
            if any(m in body_l for m in markers):
                self.save_intel("tech", tech, "detected")
                self.logger.success(f"Tech: {tech}", "Web")
                results.append(tech)

        generator = re.search(
            r'(?i)<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
            body
        )
        if generator:
            self.save_intel("tech", "generator", generator.group(1))
            results.append(f"Generator: {generator.group(1)}")

        # Cheap CMS/admin path probes
        for path, label in [
            ("/wp-login.php", "WordPress login"),
            ("/administrator", "Joomla admin"),
            ("/wp-admin", "WordPress admin"),
            ("/admin", "Admin panel"),
            ("/login", "Login page"),
        ]:
            c, b, _ = self._get(path)
            if c in (200, 301, 302):
                self.save_intel("endpoint", path, f"HTTP {c}")
                self.logger.success(f"{label} found at {path}", "Web")
                results.append(f"{label} at {path}")

        return "\n".join(results) if results else "No technologies detected"

    def directory_discovery(self):
        if not self.is_in_scope(self.target):
            return f"Target {self.target} out of scope — skipped"
        self.logger.info("Directory & endpoint discovery", "Web")
        self._resolve_base()

        # In dry-run _get() returns a synthetic 200 for everything, so a real
        # scan's status-based logic would "find" every path and log fake
        # CRITICAL findings (.git, .env). Simulate instead of pretending.
        if self.dry_run:
            self.logger.info(
                "[DRY RUN] directory discovery simulated (no real requests)", "Web")
            return "Directory discovery skipped (dry run)"

        common_paths = [
            "robots.txt", ".git/config", ".git/HEAD", ".env", ".htaccess",
            "admin", "login", "wp-login.php", "api", "api/v1",
            "backup.zip", "db.sql", "site.sql", "config.php", "test.php",
            "swagger.json", "openapi.json", "graphql", "debug", "phpinfo.php",
            "server-status", ".DS_Store", "web.config", "sitemap.xml",
            "old", "dev", "staging", "backup", "docs", "swagger-ui.html",
        ]

        found = []
        for p in common_paths:
            code, body, _ = self._get("/" + p)
            if code == 0:
                continue
            if code in (200, 301, 302):
                self.save_intel("endpoint", p, f"HTTP {code}")
                found.append(p)
                self.logger.success(f"Endpoint: /{p} (HTTP {code})", "Web")

            if p == ".git/config" and code == 200:
                self.add_finding(
                    "Git Repository Exposed (.git/config)", "CRITICAL",
                    "The target exposes its .git directory, allowing full "
                    "source code extraction with git-dumper.",
                    f"{self.base_url}/.git/config", body[:300], "T1083"
                )
            if p == ".env" and code == 200:
                self.add_finding(
                    "Sensitive File Exposed (.env)", "HIGH",
                    "An .env file is publicly accessible and may contain "
                    "hardcoded secrets and configuration.",
                    f"{self.base_url}/.env", body[:300], "T1552"
                )
            if p == "robots.txt" and code == 200:
                for disallow in re.findall(r'(?i)^disallow:\s*(\S+)', body, re.M):
                    self.save_intel("robots", disallow, "disallowed path")
                    self.logger.info(f"robots.txt disallows: {disallow}", "Web")

        self.logger.info(f"Found {len(found)} live endpoints", "Web")
        return f"Found {len(found)} endpoints: {', '.join(found[:10])}"

    def xss_testing(self):
        if not self.is_in_scope(self.target):
            return f"Target {self.target} out of scope — skipped"
        self.logger.info("Testing for reflected XSS", "Web")
        params = self._discover_params()
        probe = "__rajan_xss_%d" % int(time.time())
        payload = f"<script>{probe}</script>"
        found_any = False
        for name in params[:12]:
            code, body, _ = self._get("/", params={name: payload})
            if code in (200, 302, 403, 405) and payload in body:
                # Raw reflection of the unencoded payload
                self.add_finding(
                    f"Reflected XSS in parameter '{name}'", "HIGH",
                    f"User input in parameter '{name}' is reflected back in "
                    f"the HTML response without encoding.",
                    f"{self.base_url}/?{name}=<test>",
                    f"reflected payload: {payload}", "T1059.007"
                )
                found_any = True
        if not found_any:
            self.logger.info("No reflected XSS detected in top parameters", "Web")

        # Session cookie flags (XSS impact amplifier)
        self._check_cookie_flags()

        # Full injection sweep so the default run covers the rest of the
        # web attack surface (LFI, SSTI, Open Redirect, CSRF).
        self.lfi_testing()
        self.ssti_testing()
        self.open_redirect_testing()
        self.csrf_testing()
        return "XSS testing + injection sweep complete"

    def sqli_testing(self):
        if not self.is_in_scope(self.target):
            return f"Target {self.target} out of scope — skipped"
        self.logger.info("Testing for SQL injection", "Web")
        params = self._discover_params()
        error_keywords = [
            "sql syntax", "mysql_fetch", "warning: mysql", "ora-",
            "postgresql", "sqlite3::", "unterminated quoted",
            "syntax error", "odbc sql server", "jdbc.sql",
            "broken or missing", "pg_query",
        ]
        found_any = False
        for name in params[:10]:
            code, body, _ = self._get("/", params={name: "' OR '1'='1"})
            if code == 0:
                continue
            if any(k in body.lower() for k in error_keywords):
                self.add_finding(
                    f"SQL Injection (error-based) in parameter '{name}'", "CRITICAL",
                    f"Submitting a single quote in parameter '{name}' triggers "
                    f"a database error in the response.",
                    f"{self.base_url}/?{name}=' ",
                    f"error response contains: {body[:200]}", "T1190"
                )
                found_any = True
                break

        # Time-based blind — cap at 2 parameters to bound runtime
        for name in params[:2]:
            if self.dry_run:
                self.logger.info(f"[DRY RUN] time-based SQLi probe param={name}", "Web")
                continue
            base_code, _, _ = self._get("/", params={name: "1"}, timeout=8)
            if base_code == 0:
                continue
            t0 = time.time()
            self._get("/", params={name: "' AND SLEEP(5)-- "}, timeout=15)
            elapsed = time.time() - t0
            if elapsed >= 4.5:
                self.add_finding(
                    f"SQL Injection (time-based blind) in parameter '{name}'", "CRITICAL",
                    f"Time-based blind SQL injection: response delayed "
                    f"~{elapsed:.1f}s with SLEEP payload in parameter '{name}'.",
                    f"{self.base_url}/?{name}=' AND SLEEP(5)-- ",
                    f"delay observed: {elapsed:.1f}s", "T1190"
                )
                found_any = True
                break

        if not found_any:
            self.logger.info("No SQL injection detected in top parameters", "Web")
        return "SQL injection testing complete"

    def command_injection_testing(self):
        if not self.is_in_scope(self.target):
            return f"Target {self.target} out of scope — skipped"
        self.logger.info("Testing for command injection", "Web")
        params = self._discover_params()
        cmdy = self._params_by_keyword(
            params, ("cmd", "exec", "run", "command", "ping", "host", "ip")
        )
        found_any = False
        for name in (cmdy or params[:2])[:2]:
            if self.dry_run:
                self.logger.info(f"[DRY RUN] command injection probe param={name}", "Web")
                continue
            self._get("/", params={name: "1"}, timeout=8)
            t0 = time.time()
            self._get("/", params={name: "1; sleep 3"}, timeout=15)
            elapsed = time.time() - t0
            if elapsed >= 3.5:
                self.add_finding(
                    f"Command Injection (time-based) in parameter '{name}'", "CRITICAL",
                    f"Shell metacharacters in parameter '{name}' cause a "
                    f"~{elapsed:.1f}s delay (sleep payload executed).",
                    f"{self.base_url}/?{name}=1; sleep 3",
                    f"delay observed: {elapsed:.1f}s", "T1059"
                )
                found_any = True
                break
        if not found_any:
            self.logger.info("No command injection detected", "Web")
        return "Command injection testing complete"

    def idor_testing(self):
        if not self.is_in_scope(self.target):
            return f"Target {self.target} out of scope — skipped"
        self.logger.info("Testing for IDOR / broken access control", "Web")
        candidates = [
            "/api/users/1", "/api/items/1", "/api/orders/1",
            "/profile?id=1", "/item?id=1", "/account?id=1",
            "/user?id=1", "/download?id=1", "/invoice?id=1",
        ]
        found_any = False
        for url in candidates:
            code1, body1, _ = self._get(url)
            if code1 not in (200, 302):
                continue
            alt_url = url.replace("/1", "/99999999").replace("id=1", "id=99999999")
            code2, body2, _ = self._get(alt_url)
            if code2 in (200, 302) and len(body2) > 100 and body2 != body1:
                self.add_finding(
                    f"Potential IDOR — sequential ID access at {url}", "MEDIUM",
                    "Object at ID 1 and a non-existent ID 99999999 both return "
                    "responses without authentication. Sequential IDs may be "
                    "enumerable (broken access control).",
                    f"{self.base_url}{url}",
                    f"GET {url} → HTTP {code1}, GET {alt_url} → HTTP {code2}",
                    "T1087"
                )
                found_any = True
                break
        if not found_any:
            self.logger.info("No obvious IDOR patterns found", "Web")
        return "IDOR testing complete"

    def ssrf_testing(self):
        if not self.is_in_scope(self.target):
            return f"Target {self.target} out of scope — skipped"
        self.logger.info("Testing for SSRF", "Web")
        params = self._discover_params()
        urly = self._params_by_keyword(
            params, ("url", "link", "redirect", "to", "dest", "next", "return",
                     "src", "host", "img", "file", "download", "view")
        )
        found_any = False
        probes = [
            ("http://127.0.0.1:80/", "localhost"),
            ("http://169.254.169.254/latest/meta-data/", "cloud metadata"),
        ]
        for name in (urly or params[:5])[:5]:
            for value, label in probes:
                if self.dry_run:
                    self.logger.info(
                        f"[DRY RUN] SSRF probe param={name} value={value}", "Web")
                    continue
                code, body, _ = self._get("/", params={name: value}, timeout=10)
                markers = ["ami-id", "instance-id", "iam/security-credentials",
                           "latest/meta-data"]
                if any(m in body for m in markers):
                    self.add_finding(
                        f"SSRF — {label} reachable via parameter '{name}'", "CRITICAL",
                        f"The target fetches attacker-controlled URLs; "
                        f"reaching {value} returned cloud metadata content.",
                        f"{self.base_url}/?{name}={value}",
                        f"response contains metadata markers: {body[:200]}",
                        "T1552.005"
                    )
                    found_any = True
                    break
            if found_any:
                break
        if not found_any:
            self.logger.info("No SSRF to internal/metadata endpoints detected", "Web")
        return "SSRF testing complete"

    def lfi_testing(self):
        if not self.is_in_scope(self.target):
            return f"Target {self.target} out of scope — skipped"
        self.logger.info("Testing for LFI / path traversal", "Web")
        params = self._discover_params()
        filey = self._params_by_keyword(
            params, ("file", "page", "path", "include", "doc", "template", "tpl", "conf")
        )
        payloads = [
            "../../../../etc/passwd",
            "/etc/passwd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..\\..\\..\\windows\\win.ini",
        ]
        found_any = False
        for name in (filey or params[:4]):
            for pl in payloads:
                code, body, _ = self._get("/", params={name: pl}, timeout=8)
                if code == 0:
                    continue
                if "root:x:0:0" in body:
                    self.add_finding(
                        f"Local File Inclusion via parameter '{name}'", "CRITICAL",
                        "Path traversal payload in parameter "
                        f"'{name}' returned /etc/passwd contents.",
                        f"{self.base_url}/?{name}={pl}",
                        f"response contains /etc/passwd: {body[:200]}", "T1190"
                    )
                    found_any = True
                    break
                if "[fonts]" in body:
                    self.add_finding(
                        f"Windows Path Traversal via parameter '{name}'", "HIGH",
                        "Path traversal payload in parameter "
                        f"'{name}' returned Windows win.ini contents.",
                        f"{self.base_url}/?{name}={pl}",
                        f"response contains win.ini: {body[:200]}", "T1190"
                    )
                    found_any = True
                    break
            if found_any:
                break
        if not found_any:
            self.logger.info("No LFI / path traversal detected", "Web")
        return "LFI testing complete"

    def ssti_testing(self):
        if not self.is_in_scope(self.target):
            return f"Target {self.target} out of scope — skipped"
        self.logger.info("Testing for Server-Side Template Injection", "Web")
        params = self._discover_params()
        templaty = self._params_by_keyword(
            params, ("template", "tpl", "theme", "q", "query", "view")
        )
        probes = [
            ("{{7*7}}", "Jinja2/Twig SSTI"),
            ("${7*7}", "FreeMarker/Velocity SSTI"),
        ]
        found_any = False
        for name in (templaty or params[:4]):
            for payload, label in probes:
                code, body, _ = self._get("/", params={name: payload}, timeout=8)
                if code == 0:
                    continue
                # Vulnerable if the payload is evaluated to 49 and not echoed raw
                if payload not in body and re.search(r"(?<![\d.])49(?![\d.])", body):
                    self.add_finding(
                        f"Server-Side Template Injection in parameter '{name}'", "CRITICAL",
                        f"Template expression '{payload}' in parameter "
                        f"'{name}' was evaluated by the server ({label}). "
                        f"This typically leads to RCE.",
                        f"{self.base_url}/?{name}={payload}",
                        "response contains evaluated result 49", "T1059"
                    )
                    found_any = True
                    break
            if found_any:
                break
        if not found_any:
            self.logger.info("No SSTI detected", "Web")
        return "SSTI testing complete"

    def open_redirect_testing(self):
        if not self.is_in_scope(self.target):
            return f"Target {self.target} out of scope — skipped"
        self.logger.info("Testing for open redirects", "Web")
        params = self._discover_params()
        redirecty = self._params_by_keyword(
            params, ("url", "redirect", "next", "return", "dest", "goto",
                     "r", "continue", "forward")
        )
        evil = "https://rajan-evil.example"
        found_any = False
        for name in (redirecty or params[:3]):
            code, body, headers = self._get("/", params={name: evil})
            if code == 0:
                continue
            location = headers.get("Location", "")
            meta_redirect = re.search(
                r'(?i)(url|URL)=["\']?' + re.escape(evil), body)
            if evil in location or meta_redirect:
                self.add_finding(
                    f"Open Redirect via parameter '{name}'", "LOW",
                    f"Parameter '{name}' redirects to an arbitrary external "
                    f"URL, enabling phishing against the trusted domain.",
                    f"{self.base_url}/?{name}={evil}",
                    f"Location: {location} " +
                    ("" if location else "(meta-refresh redirect)"), "T1566"
                )
                found_any = True
                break
        if not found_any:
            self.logger.info("No open redirect detected", "Web")
        return "Open redirect testing complete"

    def csrf_testing(self):
        if not self.is_in_scope(self.target):
            return f"Target {self.target} out of scope — skipped"
        self.logger.info("Testing for CSRF token coverage", "Web")
        code, body, _ = self._fetch_home()
        if code == 0:
            return "Base URL unreachable — CSRF check skipped"
        forms = re.findall(r"(?i)<form[^>]*>", body)
        if not forms:
            self.logger.info("No forms found on base page", "Web")
            return "CSRF check complete (no forms)"
        token_field = re.search(
            r'(?i)(name|id)=["\'](_?(token|csrf|authenticity)[_\-a-z]*)', body)
        if not token_field:
            self.add_finding(
                f"CSRF — {len(forms)} form(s) without anti-CSRF token", "MEDIUM",
                "HTML forms on the target do not include an anti-CSRF token "
                "field, making state-changing actions vulnerable to cross-site "
                "request forgery.",
                self.base_url,
                f"forms found: {len(forms)}, no token field detected", "T1190"
            )
        else:
            self.logger.info("Anti-CSRF token field detected in forms", "Web")
        return "CSRF testing complete"

    def auth_testing(self):
        if not self.is_in_scope(self.target):
            return f"Target {self.target} out of scope — skipped"
        self.logger.info("Testing authentication & session handling", "Web")
        login_paths = [
            "/admin", "/admin/login", "/login", "/wp-login.php",
            "/administrator", "/dashboard/login",
        ]
        default_creds = [("admin", "admin"), ("admin", "password"), ("root", "root")]
        tested = False
        for path in login_paths:
            code, body, headers = self._get(path)
            if code not in (200, 301, 302):
                continue
            password_field = re.search(r'(?i)<input[^>]*type=["\']?password', body)
            if not password_field:
                continue
            form_action = re.search(r'(?i)<form[^>]*action=["\']([^"\']*)', body)
            action = form_action.group(1) if form_action else path
            if not action.startswith("http"):
                action = f"{self.base_url}{action}"

            for user, password in default_creds:
                if self.dry_run:
                    self.logger.info(
                        f"[DRY RUN] default credential attempt on {path}", "Web")
                    tested = True
                    break
                rcode, rbody, rheaders = self._post(
                    action,
                    data={"username": user, "user": user, "email": user,
                          "password": password, "pass": password},
                    timeout=8
                )
                if rcode == 0:
                    continue
                location = rheaders.get("Location", "").lower()
                success = (
                    rcode in (301, 302) and
                    any(k in location for k in ("admin", "dash", "panel", "home"))
                ) or (
                    rcode == 200 and 'type="password"' not in rbody.lower() and
                    any(k in rbody.lower() for k in ("logout", "dashboard", "welcome"))
                )
                if success:
                    self.add_finding(
                        f"Default Credentials Accepted on {path}", "CRITICAL",
                        f"Login form at {path} accepted default credentials "
                        f"({user}/{password}).",
                        f"{self.base_url}{path}",
                        f"POST {action} with {user}/{password} → "
                        f"HTTP {rcode} Location: {rheaders.get('Location', 'n/a')}",
                        "T1078"
                    )
                    tested = True
                    break
            if tested:
                break
        if not tested:
            self.logger.info("No login form found for default-credential check", "Web")

        # Session cookie flag checks
        self._check_cookie_flags()
        return "Authentication & session testing complete"

    def js_secret_scan(self):
        if not self.is_in_scope(self.target):
            return f"Target {self.target} out of scope — skipped"
        self.logger.info("Analyzing JavaScript files for secrets", "Web")
        code, body, _ = self._fetch_home()
        if code == 0:
            return "Base URL unreachable — JS analysis skipped"
        scripts = re.findall(r'(?i)<script[^>]+src=["\']([^"\']+)', body)
        js_urls = []
        for s in scripts[:6]:
            if s.startswith("//"):
                s = "https:" + s
            if not s.startswith("http"):
                s = urllib.parse.urljoin(self.base_url + "/", s)
            if s not in js_urls:
                js_urls.append(s)

        patterns = [
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
            (r"AIza[0-9A-Za-z_\-]{35}", "Google API Key"),
            (r"github_pat_[A-Za-z0-9_]{20,}", "GitHub Personal Access Token"),
            (r"sk_live_[A-Za-z0-9]{20,}", "Stripe Live Secret Key"),
            (r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
             "API Key"),
            (r"(?i)(secret|token|passwd|password)\s*[:=]\s*['\"][A-Za-z0-9_\-./+]{16,}['\"]",
             "Hardcoded Secret"),
        ]
        skip_markers = ("placeholder", "example", "xxxx", "changeme", "dummy",
                        "redacted", "your_", "<", "${")

        hits = []
        analyzed = 0
        for url in js_urls:
            if not self.is_in_scope(url):
                self.logger.info(f"Skipping out-of-scope JS: {url}", "Web")
                continue
            c, b, _ = self._get(url, timeout=8)
            if c == 0:
                continue
            analyzed += 1
            for pattern, label in patterns:
                for m in re.finditer(pattern, b):
                    snippet = m.group(0)
                    if any(skip in snippet.lower() for skip in skip_markers):
                        continue
                    hits.append((label, url, snippet[:120]))
                    break  # one hit per pattern per file is enough

        for label, url, snippet in hits:
            self.add_finding(
                f"Potential Hardcoded {label} in JavaScript", "HIGH",
                f"JavaScript file {url} contains a value that looks like a "
                f"{label}. Verify manually.",
                url, snippet, "T1552"
            )
        self.logger.info(
            f"Analyzed {analyzed} JS files, {len(hits)} potential secrets", "Web")
        return f"Analyzed {analyzed} JS files — {len(hits)} potential secrets found"

    def ssl_tls_check(self):
        if not self.is_in_scope(self.target):
            return f"Target {self.target} out of scope — skipped"
        self.logger.info("SSL/TLS configuration check", "Web")
        if self.dry_run:
            self.logger.info(f"[DRY RUN] TLS check on {self.target}:443", "Web")
            return "TLS check skipped (dry run)"

        results = []

        # 1. Certificate validity + protocol version
        cert_verified = False
        try:
            with socket.create_connection((self.target, 443), timeout=8) as raw:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(raw, server_hostname=self.target) as s:
                    version = s.version()
                    self.save_intel("tls", "version", version)
                    self.logger.success(f"TLS protocol: {version}", "Web")
                    results.append(f"TLS {version}")
                    cert_verified = True
                    not_after = s.getpeercert().get("notAfter", "")
                    if not_after:
                        try:
                            exp = datetime.datetime.strptime(
                                not_after, "%b %d %H:%M:%S %Y %Z")
                            days = (exp - datetime.datetime.now()).days
                            if days < 0:
                                self.add_finding(
                                    "TLS Certificate Expired", "MEDIUM",
                                    f"The TLS certificate for {self.target} "
                                    f"expired on {not_after}.",
                                    f"{self.target}:443", not_after, "T1573"
                                )
                            elif days < 30:
                                self.add_finding(
                                    "TLS Certificate Expiring Soon", "LOW",
                                    f"The TLS certificate for {self.target} "
                                    f"expires in {days} days ({not_after}).",
                                    f"{self.target}:443", not_after, "T1573"
                                )
                        except ValueError:
                            pass
        except ssl.SSLCertVerificationError as e:
            self.add_finding(
                "Invalid TLS Certificate", "MEDIUM",
                f"TLS certificate verification failed for {self.target}: {e}",
                f"{self.target}:443", str(e)[:200], "T1573"
            )
        except Exception:
            # Port closed or no TLS at all
            self.logger.info("No TLS service on port 443", "Web")
            return "No TLS service on port 443"

        if not cert_verified:
            try:
                with socket.create_connection((self.target, 443), timeout=8) as raw:
                    ctx = ssl._create_unverified_context()
                    with ctx.wrap_socket(raw, server_hostname=self.target) as s:
                        results.append(f"TLS {s.version()} (certificate not verified)")
            except Exception:
                pass

        # 2. Outdated protocol support (TLSv1.0 / TLSv1.1)
        legacy = [
            ("TLSv1.0", ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
        ]
        for label, maxver in legacy:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.maximum_version = maxver
                with socket.create_connection((self.target, 443), timeout=6) as raw:
                    with ctx.wrap_socket(raw, server_hostname=self.target):
                        self.add_finding(
                            f"Outdated TLS Version Supported ({label})", "MEDIUM",
                            f"Server {self.target} still accepts {label}. "
                            f"Clients should only allow TLS 1.2+.",
                            f"{self.target}:443",
                            f"handshake with max version {label} succeeded",
                            "T1573"
                        )
            except Exception:
                pass

        return "\n".join(results) if results else "TLS check complete"
