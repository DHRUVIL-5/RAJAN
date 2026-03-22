"""
RAJAN Recon Agent
DNS enumeration, WHOIS, subdomain discovery
Scope-enforced: every URL and subdomain checked before use
"""

import socket
import urllib.request

from agents.base import BaseAgent
from tools.toolmanager import ToolManager


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

    def dns_and_whois(self):
        self.logger.info(f"DNS lookup on {self.target}", "Recon")

        # Scope check — main target is always in scope, but log it
        if not self.is_in_scope(self.target):
            return f"Target {self.target} is out of scope — skipped"

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

        ok, whois_out = ToolManager.run("whois", [self.target], timeout=15)
        if ok and whois_out:
            self.save_intel("whois", "raw", whois_out[:500])
            for line in whois_out.splitlines():
                for key in ["Registrar:", "Creation Date:", "Expiry Date:", "Name Server:"]:
                    if key.lower() in line.lower():
                        self.logger.info(line.strip(), "Recon")
                        results.append(line.strip())

        # HTTP headers — scope checked
        url = f"https://{self.target}"
        if not self.is_in_scope(url):
            return "\n".join(results)

        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0 (RAJAN Scanner)"}
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
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
                    if not resp.headers.get(h):
                        self.add_finding(
                            f"Missing Security Header: {h}", "LOW",
                            f"HTTP response missing {h} header.",
                            url, "", "T1190"
                        )
        except Exception as e:
            self.logger.warning(f"HTTPS check failed: {e}", "Recon")

        return "\n".join(results)

    def subdomain_discovery(self):
        self.logger.info(f"Subdomain discovery on {self.target}", "Recon")
        found = []

        ok, out = ToolManager.run("subfinder", ["-d", self.target, "-silent"], timeout=60)
        if ok and out:
            for sub in out.splitlines():
                sub = sub.strip()
                if not sub:
                    continue
                # Scope check every discovered subdomain
                if not self.is_in_scope(sub):
                    continue
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
            # Scope check before resolving
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
