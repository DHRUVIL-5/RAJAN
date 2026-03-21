"""
RAJAN Web Agent
Web application vulnerability testing
XSS, SQLi, IDOR, SSRF, Auth bypass, Header analysis
"""

import urllib.request
import urllib.parse
import urllib.error

from agents.base import BaseAgent
from tools.toolmanager import ToolManager


class WebAgent(BaseAgent):
    def __init__(self, memory, llm, logger, session_id, target):
        super().__init__(memory, llm, logger, session_id, target)
        self.name = "WebAgent"
        self.base_url = f"https://{target}"

    def run_task(self, task_name):
        task_lower = task_name.lower()
        if "directory" in task_lower or "endpoint" in task_lower:
            return self.directory_discovery()
        elif "xss" in task_lower:
            return self.test_xss()
        elif "sql" in task_lower:
            return self.test_sqli()
        elif "fingerprint" in task_lower or "tech" in task_lower:
            return self.fingerprint()
        elif "js file" in task_lower or "secret" in task_lower:
            return self.analyze_js()
        elif "ssl" in task_lower or "tls" in task_lower:
            return self.check_ssl()
        elif "auth" in task_lower or "session" in task_lower:
            return self.test_auth()
        elif "idor" in task_lower or "access" in task_lower:
            return self.test_idor()
        elif "ssrf" in task_lower:
            return self.test_ssrf()
        return self.fingerprint()

    def _get(self, path="", timeout=8):
        try:
            url = f"{self.base_url}{path}"
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0 (RAJAN Scanner)"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read(8192).decode("utf-8", errors="ignore"), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, "", {}
        except Exception:
            return 0, "", {}

    def fingerprint(self):
        self.logger.info(f"Fingerprinting {self.base_url}", "Web")
        status, body, headers = self._get()
        if status == 0:
            self.logger.warning("Could not reach target over HTTPS", "Web")
            return "Unreachable"

        tech_hints = {
            "wp-content": "WordPress",
            "joomla": "Joomla",
            "drupal": "Drupal",
            "laravel": "Laravel",
            "django": "Django",
            "rails": "Ruby on Rails",
            "asp.net": "ASP.NET",
            "react": "React",
            "angular": "Angular",
            "vue": "Vue.js",
        }
        found_tech = []
        body_lower = body.lower()
        for hint, tech in tech_hints.items():
            if hint in body_lower:
                found_tech.append(tech)
                self.save_intel("tech", "framework", tech)
                self.logger.success(f"Detected: {tech}", "Web")

        return f"Status: {status} | Tech: {', '.join(found_tech) or 'Unknown'}"

    def directory_discovery(self):
        self.logger.info("Directory discovery", "Web")

        # Try gobuster/ffuf if available
        ok, out = ToolManager.run(
            "gobuster",
            ["dir", "-u", self.base_url, "-w",
             "/usr/share/wordlists/dirb/common.txt", "-q", "--no-error"],
            timeout=120
        )
        if ok and out:
            for line in out.splitlines():
                if "(Status: 2" in line or "(Status: 3" in line:
                    self.save_intel("endpoint", line.split()[0], "found")
                    self.logger.success(f"Found: {line.strip()}", "Web")
            return out

        # Fallback: manual common paths
        common_paths = [
            "/admin", "/login", "/dashboard", "/api", "/api/v1",
            "/api/v2", "/backup", "/config", "/.env", "/.git",
            "/robots.txt", "/sitemap.xml", "/swagger", "/graphql",
            "/wp-admin", "/phpmyadmin", "/uploads", "/files",
        ]
        found = []
        for path in common_paths:
            status, _, _ = self._get(path)
            if status in [200, 301, 302, 403]:
                found.append(f"{path} [{status}]")
                self.save_intel("endpoint", path, str(status))
                self.logger.success(f"Found: {path} → {status}", "Web")
                if path in ["/.env", "/.git", "/backup", "/config"]:
                    self.add_finding(
                        f"Sensitive path accessible: {path}",
                        "HIGH" if status == 200 else "MEDIUM",
                        f"Sensitive path {path} returned HTTP {status}",
                        f"{self.base_url}{path}", "", "T1083"
                    )
        return f"Found {len(found)} paths: {', '.join(found)}"

    def test_xss(self):
        self.logger.info("Testing for XSS", "Web")
        payloads = [
            "<script>alert('RAJAN-XSS')</script>",
            "'><img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ]
        # Get endpoints from memory
        endpoints = self.memory.get_intel(self.session_id, "endpoint")
        tested = 0
        for _, path, _ in endpoints[:5]:  # test first 5 endpoints
            for payload in payloads:
                encoded = urllib.parse.quote(payload)
                status, body, _ = self._get(f"{path}?q={encoded}&search={encoded}&id={encoded}")
                tested += 1
                if payload in body or "alert(" in body:
                    self.add_finding(
                        "Reflected XSS",
                        "HIGH",
                        f"Payload reflected in response without encoding",
                        f"{self.base_url}{path}",
                        f"Payload: {payload}",
                        "T1059.007"
                    )
                    break

        # Ask LLM for additional XSS vectors
        analysis = self.ask_llm(
            f"What are the most likely XSS attack vectors for a site at {self.target}? "
            f"Known tech: {self.memory.get_intel(self.session_id, 'tech')}. "
            f"Give 3 specific test suggestions."
        )
        self.logger.info(analysis, "Web")
        return f"XSS testing done. Tested {tested} param combinations."

    def test_sqli(self):
        self.logger.info("Testing for SQL injection", "Web")
        payloads = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "1' AND 1=1--"]
        error_signs = [
            "sql", "syntax", "mysql", "ora-", "postgresql",
            "sqlite", "warning:", "error in your sql"
        ]
        endpoints = self.memory.get_intel(self.session_id, "endpoint")
        for _, path, _ in endpoints[:5]:
            for payload in payloads:
                encoded = urllib.parse.quote(payload)
                status, body, _ = self._get(f"{path}?id={encoded}&user={encoded}")
                body_lower = body.lower()
                for sign in error_signs:
                    if sign in body_lower:
                        self.add_finding(
                            "Potential SQL Injection",
                            "CRITICAL",
                            f"SQL error message detected in response",
                            f"{self.base_url}{path}",
                            f"Payload: {payload} triggered: {sign}",
                            "T1190"
                        )
                        break
        return "SQLi testing complete"

    def analyze_js(self):
        self.logger.info("Analyzing JS files for exposed secrets", "Web")
        status, body, _ = self._get()
        js_files = []
        import re
        for match in re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', body):
            if not match.startswith("http"):
                match = f"{self.base_url}/{match.lstrip('/')}"
            js_files.append(match)

        secret_patterns = [
            ("api_key", r'(?i)api[_-]?key["\s]*[:=]["\s]*([A-Za-z0-9_\-]{20,})'),
            ("secret", r'(?i)secret["\s]*[:=]["\s]*([A-Za-z0-9_\-]{20,})'),
            ("password", r'(?i)password["\s]*[:=]["\s]*["\']([^"\']{6,})["\']'),
            ("token", r'(?i)token["\s]*[:=]["\s]*["\']([A-Za-z0-9_\-\.]{20,})["\']'),
            ("aws_key", r'AKIA[0-9A-Z]{16}'),
        ]

        found_secrets = 0
        for js_url in js_files[:10]:
            try:
                req = urllib.request.Request(
                    js_url,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                with urllib.request.urlopen(req, timeout=8) as r:
                    js_content = r.read(50000).decode("utf-8", errors="ignore")
                for name, pattern in secret_patterns:
                    matches = re.findall(pattern, js_content)
                    if matches:
                        found_secrets += 1
                        self.add_finding(
                            f"Exposed {name} in JavaScript file",
                            "CRITICAL",
                            f"Found potential {name} in {js_url}",
                            js_url, f"Value hint: {str(matches[0])[:20]}...", "T1552"
                        )
            except Exception:
                pass

        return f"Analyzed {len(js_files)} JS files, found {found_secrets} potential secrets"

    def check_ssl(self):
        self.logger.info("Checking SSL/TLS configuration", "Web")
        import ssl
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                __import__("socket").socket(), server_hostname=self.target
            ) as s:
                s.settimeout(5)
                s.connect((self.target, 443))
                cert = s.getpeercert()
                self.save_intel("ssl", "cert", str(cert)[:200])
                self.logger.success("SSL/TLS: Valid certificate", "Web")

                expire = cert.get("notAfter", "")
                self.logger.info(f"Expires: {expire}", "Web")
                return f"SSL OK. Expires: {expire}"
        except ssl.SSLError as e:
            self.add_finding(
                "SSL/TLS Configuration Issue",
                "MEDIUM",
                str(e),
                self.target, "", "T1573"
            )
            return f"SSL error: {e}"
        except Exception as e:
            return f"SSL check failed: {e}"

    def test_auth(self):
        self.logger.info("Testing authentication", "Web")
        hints = self.ask_llm(
            f"For a target at {self.target}, what authentication bypass techniques "
            f"and default credentials should be tested first? List 5 specific tests."
        )
        self.logger.info(hints, "Web")
        return "Auth analysis complete (manual verification required)"

    def test_idor(self):
        self.logger.info("Testing for IDOR", "Web")
        test_paths = [
            "/api/v1/users/1", "/api/v1/users/2",
            "/user/1", "/user/2",
            "/account/1", "/account/2",
            "/profile/1", "/profile/2",
        ]
        for path in test_paths:
            status, body, _ = self._get(path)
            if status == 200 and len(body) > 50:
                self.save_intel("endpoint", path, "200-responds")
                self.logger.warning(f"IDOR candidate: {path} → {status}", "Web")
        return "IDOR testing complete"

    def test_ssrf(self):
        self.logger.info("Testing for SSRF", "Web")
        ssrf_payloads = [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://169.254.169.254/latest/meta-data/",
        ]
        endpoints = self.memory.get_intel(self.session_id, "endpoint")
        for _, path, _ in endpoints[:3]:
            for payload in ssrf_payloads:
                encoded = urllib.parse.quote(payload)
                status, body, _ = self._get(f"{path}?url={encoded}&redirect={encoded}")
                if "169.254" in body or "instance-id" in body:
                    self.add_finding(
                        "SSRF — AWS Metadata Accessible",
                        "CRITICAL",
                        "SSRF payload returned AWS metadata response",
                        f"{self.base_url}{path}",
                        f"Payload: {payload}", "T1552.005"
                    )
        return "SSRF testing complete"
