"""
RAJAN Bug Bounty Methodology
Complete checklist + platform guidance + report templates
"""

METHODOLOGIES = {
    "web": {
        "name": "Web Application Pentest",
        "phases": {
            "1_recon": {
                "name": "Reconnaissance",
                "tasks": [
                    "WHOIS & DNS lookup",
                    "Subdomain enumeration (subfinder, amass, dnsx)",
                    "Google dorking (site:, filetype:, inurl:)",
                    "Wayback Machine for old endpoints",
                    "GitHub/GitLab code leak search",
                    "Shodan/Censys for exposed services",
                    "LinkedIn for employee OSINT",
                    "Certificate transparency logs (crt.sh)",
                ],
            },
            "2_scan": {
                "name": "Scanning & Fingerprinting",
                "tasks": [
                    "Port scan (nmap -sV -sC target)",
                    "Web tech fingerprint (Wappalyzer, WhatWeb)",
                    "Directory discovery (gobuster, ffuf, feroxbuster)",
                    "API endpoint discovery",
                    "JS file analysis (LinkFinder)",
                    "SSL/TLS check (testssl.sh)",
                    "WAF detection (wafw00f)",
                ],
            },
            "3_auth": {
                "name": "Authentication Testing",
                "tasks": [
                    "Default credentials test",
                    "Username enumeration via error messages",
                    "Password reset flow analysis",
                    "Brute force protection check",
                    "2FA/MFA bypass attempts",
                    "OAuth misconfiguration",
                    "JWT token analysis",
                    "Session fixation/hijacking",
                    "Cookie flags (Secure, HttpOnly, SameSite)",
                ],
            },
            "4_vuln": {
                "name": "Vulnerability Testing",
                "tasks": [
                    "XSS (Reflected, Stored, DOM)",
                    "SQL Injection (manual + sqlmap)",
                    "Command Injection",
                    "Path Traversal / LFI / RFI",
                    "XXE (XML External Entity)",
                    "SSRF (Server-Side Request Forgery)",
                    "SSTI (Server-Side Template Injection)",
                    "Open Redirect",
                    "CSRF (token validation)",
                    "IDOR (Insecure Direct Object Reference)",
                    "Broken Access Control",
                    "Mass Assignment",
                    "File upload bypass",
                    "HTTP Request Smuggling",
                    "Business logic flaws",
                    "Rate limiting bypass",
                ],
            },
            "5_api": {
                "name": "API Security Testing",
                "tasks": [
                    "API endpoint enumeration",
                    "Unauthenticated API access",
                    "BOLA/IDOR in API",
                    "Mass assignment via API",
                    "Excessive data exposure",
                    "Function level auth issues",
                    "GraphQL introspection",
                    "API key exposure",
                    "Rate limiting on API",
                ],
            },
            "6_cloud": {
                "name": "Cloud Security",
                "tasks": [
                    "Public S3/GCS/Azure bucket check",
                    "Cloud metadata API via SSRF",
                    "Misconfigured IAM policies",
                    "Exposed cloud credentials in code",
                    "Subdomain takeover via cloud DNS",
                ],
            },
        },
    },
    "network": {
        "name": "Network Penetration Test",
        "phases": {
            "1_discovery": {
                "name": "Network Discovery",
                "tasks": [
                    "Host discovery (nmap -sn subnet)",
                    "Port scan all hosts",
                    "Service enumeration",
                    "OS fingerprinting",
                    "SMB enumeration (enum4linux)",
                    "SNMP enumeration",
                    "LDAP enumeration",
                ],
            },
            "2_exploit": {
                "name": "Exploitation",
                "tasks": [
                    "Check for EternalBlue (MS17-010)",
                    "Check for BlueKeep (CVE-2019-0708)",
                    "Default credentials on services",
                    "FTP anonymous login",
                    "Telnet access",
                    "Redis/MongoDB no-auth",
                    "Elasticsearch no-auth",
                ],
            },
        },
    },
}

PLATFORMS = {
    "hackerone": {
        "name": "HackerOne",
        "url": "https://hackerone.com",
        "report_format": """
## Summary
Brief 1-2 sentence description of the vulnerability.

## Steps to Reproduce
1. Go to [URL]
2. Click [action]
3. Observe [result]

## Impact
What can an attacker do with this?

## Supporting Material
[Screenshots, videos, PoC code]
""",
        "severity_scale": "Critical / High / Medium / Low / Informational",
        "tips": [
            "Always include PoC (proof of concept)",
            "Explain the business impact clearly",
            "Attach screenshots/video",
            "Check the program scope before reporting",
            "Avoid duplicate reports — search before submitting",
        ],
    },
    "bugcrowd": {
        "name": "Bugcrowd",
        "url": "https://bugcrowd.com",
        "severity_scale": "P1 (Critical) / P2 (High) / P3 (Medium) / P4 (Low) / P5 (Informational)",
        "tips": [
            "Follow the Bugcrowd Vulnerability Rating Taxonomy (VRT)",
            "Provide clear reproduction steps",
            "Include environment details",
        ],
    },
    "intigriti": {
        "name": "Intigriti",
        "url": "https://intigriti.com",
        "severity_scale": "Critical / High / Medium / Low / Exceptional",
        "tips": [
            "Check program-specific rules",
            "Document all test steps",
            "Include PoC code",
        ],
    },
}

SEVERITY_GUIDE = {
    "CRITICAL": {
        "cvss": "9.0-10.0",
        "examples": [
            "Unauthenticated RCE",
            "SQLi leading to full database dump",
            "Auth bypass to admin",
            "Exposed AWS keys with full access",
            "SSRF reading cloud metadata",
        ],
        "expected_bounty": "$1,000 - $100,000+",
    },
    "HIGH": {
        "cvss": "7.0-8.9",
        "examples": [
            "Authenticated RCE",
            "SQLi with limited data access",
            "Stored XSS affecting many users",
            "IDOR exposing sensitive user data",
            "Password reset token leak",
        ],
        "expected_bounty": "$500 - $10,000",
    },
    "MEDIUM": {
        "cvss": "4.0-6.9",
        "examples": [
            "Reflected XSS",
            "CSRF on sensitive actions",
            "Open redirect",
            "Missing security headers",
            "Username enumeration",
        ],
        "expected_bounty": "$100 - $1,000",
    },
    "LOW": {
        "cvss": "0.1-3.9",
        "examples": [
            "Missing security headers",
            "Rate limiting missing on non-sensitive endpoint",
            "Verbose error messages",
            "Outdated software versions (without confirmed vuln)",
        ],
        "expected_bounty": "$50 - $500",
    },
}


class BugBountyGuide:
    def __init__(self):
        self.methodologies = METHODOLOGIES
        self.platforms = PLATFORMS
        self.severity_guide = SEVERITY_GUIDE

    def print_checklist(self, methodology_type="web", target=""):
        method = self.methodologies.get(methodology_type, self.methodologies["web"])
        print(f"\n  ╔══════════════════════════════════════════════════════╗")
        print(f"  ║  RAJAN Bug Bounty Checklist: {method['name']:<24}║")
        if target:
            print(f"  ║  Target: {target:<46}║")
        print(f"  ╚══════════════════════════════════════════════════════╝\n")

        total = 0
        for phase_key, phase in method["phases"].items():
            print(f"  📋 Phase {phase_key[0]}: {phase['name']}")
            for task in phase["tasks"]:
                print(f"      [ ] {task}")
                total += 1
            print()

        print(f"  Total checks: {total}")
        print(f"  ⚠️  Only test within authorized scope!\n")

    def print_platform(self, platform="hackerone"):
        p = self.platforms.get(platform.lower())
        if not p:
            print(f"  Available platforms: {', '.join(self.platforms.keys())}")
            return
        print(f"\n  🎯 {p['name']} — {p['url']}")
        print(f"  Severity: {p['severity_scale']}")
        print(f"\n  Tips:")
        for tip in p.get("tips", []):
            print(f"    • {tip}")
        if "report_format" in p:
            print(f"\n  Report Template:{p['report_format']}")

    def assess_severity(self, description):
        desc_lower = description.lower()
        if any(kw in desc_lower for kw in ["rce", "remote code execution",
                                            "unauthenticated", "full access",
                                            "log4shell", "critical"]):
            return "CRITICAL"
        if any(kw in desc_lower for kw in ["sql injection", "auth bypass",
                                            "stored xss", "idor", "command injection",
                                            "path traversal", "lfi", "xxe", "ssti"]):
            return "HIGH"
        if any(kw in desc_lower for kw in ["reflected xss", "csrf", "open redirect",
                                            "ssrf", "information disclosure",
                                            "security misconfiguration"]):
            return "MEDIUM"
        return "LOW"

    def print_severity_guide(self):
        print("\n  📊 Severity Assessment Guide\n")
        for sev, data in self.severity_guide.items():
            colors = {"CRITICAL": "\033[91m", "HIGH": "\033[93m",
                      "MEDIUM": "\033[94m", "LOW": "\033[92m"}
            c = colors.get(sev, "")
            r = "\033[0m"
            print(f"  {c}■ {sev}{r} (CVSS {data['cvss']})")
            print(f"    Expected bounty: {data['expected_bounty']}")
            for ex in data["examples"][:3]:
                print(f"    • {ex}")
            print()
