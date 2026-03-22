"""
RAJAN Recon Agent
DNS enumeration, WHOIS, subdomain discovery
Uses requests throughout (standardized - no urllib mixing)
Scope-enforced on every network call
"""

import socket
import requests
import requests.exceptions

from agents.base import BaseAgent
from tools.toolmanager import ToolManager

# Shared session for connection reuse
_SESSION = requests.Session()
_SESSION.headers.update({"User-Agent": "Mozilla/5.0 (RAJAN Scanner)"})
_SESSION.verify = False  # handle self-signed certs

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ReconAgent(BaseAgent):
    def __init__(self, memory, llm, logger, session_id, target):
        super().__init__(memory, llm, logger, session_id, target)
        self.name = "ReconAgent"

    def run_task(self, task_name):
        tl = task_name.lower()
        if "dns" in tl or "whois" in tl:
            return self.dns_and_whois()
        elif "subdomain" in tl:
            return self.subdomain_discovery()
        return self.dns_and_whois()

    def _get(self, url, timeout=8):
        """Unified requests-based GET with scope check"""
        if not self.is_in_scope(url):
            return None
        try:
            r = _SESSION.get(url, timeout=timeout, allow_redirects=False)
            return r
        except Exception:
            return None

    def dns_and_whois(self):
        if not self.is_in_scope(self.target):
            return f"Target {self.target} out of scope — skipped"

        self.logger.info(f"DNS lookup on {self.target}", "Recon")
        results = []

        try:
            ip = socket.gethostbyname(self.target)
            self.save_intel("dns", "ip", ip)
            self.logger.success(f"IP: {ip}", "Recon")
            results.append(f"IP: {ip}")
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                self.save_intel("dns", "hostname", hostname)
                self.logger.success(f"Hostname: {hostname}", "Recon")
            except Exception:
                pass
        except Exception as e:
            self.logger.error(f"DNS failed: {e}", "Recon")
            return f"DNS failed: {e}"

        # WHOIS — increased limit to 2000 chars (Fix 6)
        ok, whois_out = ToolManager.run("whois", [self.target], timeout=15)
        if ok and whois_out:
            self.save_intel("whois", "raw", whois_out[:2000])  # was 500
            for line in whois_out.splitlines():
                for key in ["Registrar:", "Creation Date:", "Expiry Date:",
                            "Name Server:", "Abuse Contact:"]:
                    if key.lower() in line.lower():
                        self.logger.info(line.strip(), "Recon")
                        results.append(line.strip())

        # HTTP headers via requests (standardized - Fix 2)
        for scheme in ("https", "http"):
            url = f"{scheme}://{self.target}"
            if not self.is_in_scope(url):
                continue
            resp = self._get(url)
            if resp is None:
                continue
            server = resp.headers.get("Server", "")
            powered = resp.headers.get("X-Powered-By", "")
            if server:
                self.save_intel("tech", "server", server)
                self.logger.success(f"Server: {server}", "Recon")
                results.append(f"Server: {server}")
            if powered:
                self.save_intel("tech", "powered_by", powered)

            for h in ["X-Frame-Options", "Content-Security-Policy",
                       "Strict-Transport-Security", "X-Content-Type-Options"]:
                if h not in resp.headers:
                    self.add_finding(
                        f"Missing Security Header: {h}", "LOW",
                        f"HTTP response missing {h} header.", url, "", "T1190"
                    )
            break  # got a response, stop trying schemes

        return "\n".join(results)

    def subdomain_discovery(self):
        if not self.is_in_scope(self.target):
            return f"Target {self.target} out of scope — skipped"

        self.logger.info(f"Subdomain discovery on {self.target}", "Recon")
        found = []

        ok, out = ToolManager.run("subfinder", ["-d", self.target, "-silent"], timeout=60)
        if ok and out:
            for sub in out.splitlines():
                sub = sub.strip()
                if sub and self.is_in_scope(sub) and sub not in found:
                    found.append(sub)
                    self.save_intel("subdomain", sub, "found")
                    self.logger.success(f"Subdomain: {sub}", "Recon")

        common = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging",
            "test", "vpn", "portal", "app", "blog", "shop", "cdn",
            "cloud", "login", "dashboard", "mobile", "beta", "secure",
        ]
        for prefix in common:
            full = f"{prefix}.{self.target}"
            if not self.is_in_scope(full):
                continue
            try:
                ip = socket.gethostbyname(full)
                if full not in found:
                    found.append(full)
                    self.save_intel("subdomain", full, ip)
                    self.logger.success(f"Subdomain: {full} → {ip}", "Recon")
            except Exception:
                pass

        self.logger.info(f"Found {len(found)} in-scope subdomains", "Recon")
        return f"Found {len(found)} subdomains: {', '.join(found[:10])}"
