"""
RAJAN MITRE ATT&CK Knowledge Base
Maps findings to MITRE tactics and techniques
Covers: Initial Access, Execution, Persistence, Privilege Escalation,
        Defense Evasion, Credential Access, Discovery, Lateral Movement,
        Collection, Exfiltration, Impact
"""

MITRE_TECHNIQUES = {
    # ── Initial Access ─────────────────────────────────────────
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversary exploits weakness in internet-facing software.",
        "examples": ["SQLi", "XXE", "RCE via vulnerable web app"],
        "detection": "Monitor for unexpected process execution, web application errors",
        "mitigation": "Patch management, WAF, input validation",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access / Persistence",
        "description": "Using stolen or default credentials to gain access.",
        "examples": ["Default admin:admin", "Stolen credentials", "Password spray"],
        "detection": "Failed login monitoring, unusual login times",
        "mitigation": "MFA, strong password policy, account lockout",
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Sending phishing messages to gain access.",
        "examples": ["Spear phishing email", "Malicious attachment"],
        "detection": "Email filtering, user training",
        "mitigation": "Anti-phishing training, DMARC/SPF/DKIM",
    },

    # ── Execution ──────────────────────────────────────────────
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Using scripts/commands to execute malicious code.",
        "examples": ["Command injection", "Shell upload", "Eval injection"],
        "detection": "Process monitoring, command-line logging",
        "mitigation": "Least privilege, input sanitization",
    },
    "T1059.007": {
        "name": "JavaScript — XSS/DOM",
        "tactic": "Execution",
        "description": "Malicious JS execution via XSS.",
        "examples": ["Reflected XSS", "Stored XSS", "DOM XSS"],
        "detection": "CSP headers, output encoding checks",
        "mitigation": "Content-Security-Policy, output encoding, HTTPOnly cookies",
    },

    # ── Credential Access ──────────────────────────────────────
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": "Finding credentials stored insecurely.",
        "examples": ["API keys in JS", ".env exposed", "Hardcoded passwords"],
        "detection": "Code scanning, file access monitoring",
        "mitigation": "Secret management tools, never hardcode credentials",
    },
    "T1552.005": {
        "name": "Cloud Instance Metadata API",
        "tactic": "Credential Access",
        "description": "SSRF to access cloud metadata and steal credentials.",
        "examples": ["SSRF → AWS 169.254.169.254", "GCP metadata API"],
        "detection": "Cloud audit logs, metadata API access monitoring",
        "mitigation": "IMDSv2 enforcement, network segmentation",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Trying many passwords to gain access.",
        "examples": ["Password spray", "Dictionary attack", "Credential stuffing"],
        "detection": "Failed login alerts, account lockout triggers",
        "mitigation": "MFA, account lockout, CAPTCHA, rate limiting",
    },

    # ── Discovery ──────────────────────────────────────────────
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Scanning for open ports and running services.",
        "examples": ["Nmap scan", "Port sweep", "Service enumeration"],
        "detection": "IDS/IPS alerts on port scans",
        "mitigation": "Firewall rules, network segmentation",
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "Enumerating files and directories on target.",
        "examples": ["Dir busting", "Backup file discovery", ".git exposed"],
        "detection": "Web server access logs, 404 spike detection",
        "mitigation": "Restrict directory listing, remove backup files",
    },
    "T1087": {
        "name": "Account Discovery",
        "tactic": "Discovery",
        "description": "Finding valid user accounts.",
        "examples": ["User enumeration via login error", "OSINT", "LinkedIn scraping"],
        "detection": "Auth log monitoring",
        "mitigation": "Generic error messages, rate limiting",
    },

    # ── Collection ─────────────────────────────────────────────
    "T1530": {
        "name": "Data from Cloud Storage",
        "tactic": "Collection",
        "description": "Accessing data from misconfigured cloud storage.",
        "examples": ["Public S3 bucket", "Open GCS bucket", "Azure blob"],
        "detection": "Cloud audit logs, public access monitoring",
        "mitigation": "Block public access, bucket policies, encryption",
    },

    # ── Exfiltration ───────────────────────────────────────────
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "description": "Using web services to exfiltrate data.",
        "examples": ["Data sent to attacker server", "DNS exfiltration"],
        "detection": "DLP, unusual outbound traffic",
        "mitigation": "Egress filtering, DLP tools",
    },

    # ── Impact ─────────────────────────────────────────────────
    "T1499": {
        "name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": "Making a service unavailable.",
        "examples": ["DoS via resource exhaustion", "ReDoS"],
        "detection": "Traffic anomaly detection",
        "mitigation": "Rate limiting, CDN, DDoS protection",
    },

    # ── Lateral Movement ───────────────────────────────────────
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "description": "Using RDP to move laterally.",
        "examples": ["BlueKeep", "RDP brute force"],
        "detection": "RDP connection logs",
        "mitigation": "Disable RDP if unused, NLA, MFA",
    },
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "tactic": "Lateral Movement",
        "description": "Using SMB for lateral movement.",
        "examples": ["EternalBlue", "Pass-the-hash"],
        "detection": "SMB traffic monitoring",
        "mitigation": "Disable SMBv1, segment networks",
    },
    "T1021.004": {
        "name": "SSH",
        "tactic": "Lateral Movement",
        "description": "Using SSH for lateral movement.",
        "examples": ["SSH key reuse", "Weak SSH credentials"],
        "detection": "SSH login monitoring",
        "mitigation": "Key-based auth only, disable root login",
    },

    # ── Defense Evasion ────────────────────────────────────────
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "description": "Using obfuscation to hide malicious content.",
        "examples": ["Base64 encoded payload", "Minified malicious JS"],
        "detection": "Content inspection",
        "mitigation": "Static analysis tools, sandboxing",
    },

    # ── Persistence ────────────────────────────────────────────
    "T1505.003": {
        "name": "Web Shell",
        "tactic": "Persistence",
        "description": "Uploading a web shell to maintain access.",
        "examples": ["PHP shell upload", "JSP webshell"],
        "detection": "File integrity monitoring, unusual file creation",
        "mitigation": "Disable file uploads or validate type/content",
    },

    # ── Privilege Escalation ───────────────────────────────────
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
        "description": "Bypassing access controls to gain higher privileges.",
        "examples": ["SUDO abuse", "SUID binary exploitation"],
        "detection": "Privilege use monitoring",
        "mitigation": "Least privilege, sudo auditing",
    },

    # ── Network ────────────────────────────────────────────────
    "T1573": {
        "name": "Encrypted Channel",
        "tactic": "Command and Control",
        "description": "Using encryption to hide C2 communications.",
        "examples": ["Weak SSL/TLS", "Self-signed cert"],
        "detection": "SSL inspection",
        "mitigation": "TLS 1.2+ only, valid certificates, HSTS",
    },
}


class MITREMapper:
    def __init__(self):
        self.db = MITRE_TECHNIQUES

    def get_technique(self, technique_id):
        return self.db.get(technique_id, None)

    def get_remediation(self, technique_id):
        t = self.db.get(technique_id, {})
        return t.get("mitigation", "Follow OWASP remediation guidelines.")

    def get_detection(self, technique_id):
        t = self.db.get(technique_id, {})
        return t.get("detection", "Monitor for anomalous activity.")

    def format_finding(self, technique_id):
        t = self.db.get(technique_id)
        if not t:
            return ""
        return (
            f"MITRE ATT&CK: {technique_id} — {t['name']}\n"
            f"Tactic: {t['tactic']}\n"
            f"Mitigation: {t['mitigation']}"
        )

    def get_all_by_tactic(self, tactic):
        return {
            tid: t for tid, t in self.db.items()
            if tactic.lower() in t["tactic"].lower()
        }

    def search(self, keyword):
        results = {}
        kw = keyword.lower()
        for tid, t in self.db.items():
            if (kw in t["name"].lower() or
                kw in t["description"].lower() or
                any(kw in ex.lower() for ex in t["examples"])):
                results[tid] = t
        return results

    def print_technique(self, technique_id):
        t = self.db.get(technique_id)
        if not t:
            print(f"  ❌ Technique {technique_id} not found")
            return
        print(f"\n  ╔══════════════════════════════════════════════════╗")
        print(f"  ║  {technique_id} — {t['name']:<40}║")
        print(f"  ╠══════════════════════════════════════════════════╣")
        print(f"  ║  Tactic    : {t['tactic']:<39}║")
        print(f"  ║  Desc      : {t['description'][:39]:<39}║")
        print(f"  ╚══════════════════════════════════════════════════╝")
        print(f"  Examples   : {', '.join(t['examples'])}")
        print(f"  Detection  : {t['detection']}")
        print(f"  Mitigation : {t['mitigation']}")
        print()
