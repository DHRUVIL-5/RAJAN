"""
RAJAN Recon Agent
DNS enumeration, WHOIS, subdomain discovery
Inspired by Nebula's auto-chaining approach
"""

import socket
import urllib.request
import json

from agents.base import BaseAgent
from tools.toolmanager import ToolManager


class ReconAgent(BaseAgent):
    def __init__(self, memory, llm, logger, session_id, target):
        super().__init__(memory, llm, logger, session_id, target)
        self.name = "ReconAgent"

    def run_task(self, task_name):
        task_lower = task_name.lower()
        if "dns" in task_lower or "whois" in task_lower:
            return self.dns_and_whois()
        elif "subdomain" in task_lower:
            return self.subdomain_discovery()
        else:
            return self.dns_and_whois()

    def dns_and_whois(self):
        self.logger.info(f"DNS lookup on {self.target}", "Recon")
        results = []

        # IP resolution
        try:
            ip = socket.gethostbyname(self.target)
            self.save_intel("dns", "ip", ip)
            self.logger.success(f"IP: {ip}", "Recon")
            results.append(f"IP: {ip}")

            # Reverse DNS
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                self.save_intel("dns", "hostname", hostname)
                self.logger.success(f"Hostname: {hostname}", "Recon")
            except Exception:
                pass
        except Exception as e:
            self.logger.error(f"DNS failed: {e}", "Recon")
            return f"DNS failed: {e}"

        # WHOIS via tool
        ok, whois_out = ToolManager.run("whois", [self.target], timeout=15)
        if ok and whois_out:
            self.save_intel("whois", "raw", whois_out[:500])
            # Extract key fields
            for line in whois_out.splitlines():
                for key in ["Registrar:", "Creation Date:", "Expiry Date:", "Name Server:"]:
                    if key.lower() in line.lower():
                        val = line.strip()
                        self.logger.info(val, "Recon")
                        results.append(val)

        # Check HTTP headers
        try:
            url = f"https://{self.target}"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (RAJAN Scanner)"}
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
                    self.logger.success(f"X-Powered-By: {powered}", "Recon")

                # Check missing security headers
                security_headers = [
                    "X-Frame-Options",
                    "Content-Security-Policy",
                    "Strict-Transport-Security",
                    "X-Content-Type-Options",
                ]
                missing = []
                for h in security_headers:
                    if not resp.headers.get(h):
                        missing.append(h)
                if missing:
                    for h in missing:
                        self.add_finding(
                            f"Missing Security Header: {h}",
                            "LOW",
                            f"The HTTP response is missing the {h} header.",
                            f"https://{self.target}",
                            "",
                            "T1190"
                        )
        except Exception as e:
            self.logger.warning(f"HTTPS check failed: {e}", "Recon")

        return "\n".join(results)

    def subdomain_discovery(self):
        self.logger.info(f"Subdomain discovery on {self.target}", "Recon")
        found = []

        # Method 1: subfinder (if installed)
        ok, out = ToolManager.run("subfinder", ["-d", self.target, "-silent"], timeout=60)
        if ok and out:
            for sub in out.splitlines():
                sub = sub.strip()
                if sub:
                    found.append(sub)
                    self.save_intel("subdomain", sub, "found")
                    self.logger.success(f"Subdomain: {sub}", "Recon")

        # Method 2: brute force common names
        common = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging",
            "test", "vpn", "portal", "app", "blog", "shop", "cdn",
            "cloud", "login", "dashboard", "mobile", "beta", "secure",
        ]
        for sub in common:
            full = f"{sub}.{self.target}"
            try:
                ip = socket.gethostbyname(full)
                if full not in found:
                    found.append(full)
                    self.save_intel("subdomain", full, ip)
                    self.logger.success(f"Subdomain: {full} → {ip}", "Recon")
            except Exception:
                pass

        self.logger.info(f"Found {len(found)} subdomains", "Recon")
        return f"Found {len(found)} subdomains: {', '.join(found[:10])}"
