"""
RAJAN Vulnerability Chain Analyzer
UNIQUE FEATURE — No other ethical hacking agent has this.

Takes all findings from a session and uses AI to identify
how vulnerabilities can be CHAINED together for higher impact.
Example: SSRF + Open Redirect + XSS = Account Takeover chain

This is what separates junior hackers from seniors — finding chains.
RAJAN does it automatically.
"""

from knowledge.mitre import MITREMapper


# Known high-impact vulnerability chains
KNOWN_CHAINS = [
    {
        "name": "Account Takeover via XSS + CSRF",
        "requires": ["xss", "csrf"],
        "impact": "CRITICAL",
        "description": "Stored XSS can steal CSRF tokens, enabling full account takeover.",
        "steps": [
            "Inject stored XSS payload that reads victim's CSRF token",
            "Use stolen token to perform CSRF attack on behalf of victim",
            "Change victim's email/password → full account takeover"
        ],
        "mitre": ["T1059.007", "T1185"],
    },
    {
        "name": "RCE Chain via SSRF + Cloud Metadata",
        "requires": ["ssrf", "cloud"],
        "impact": "CRITICAL",
        "description": "SSRF to AWS metadata → IAM credentials → full cloud compromise.",
        "steps": [
            "Use SSRF to reach http://169.254.169.254/latest/meta-data/",
            "Steal IAM role credentials from metadata API",
            "Use credentials to access S3 buckets, EC2, Lambda functions",
            "Potential full cloud account takeover"
        ],
        "mitre": ["T1552.005", "T1530"],
    },
    {
        "name": "Data Exfiltration via SQLi + File Read",
        "requires": ["sqli", "lfi"],
        "impact": "CRITICAL",
        "description": "SQLi with file read privilege can dump OS files + database.",
        "steps": [
            "Use UNION-based SQLi to read sensitive files (LOAD_FILE)",
            "Extract /etc/passwd, config files, source code",
            "Combine with database dump for full compromise"
        ],
        "mitre": ["T1190", "T1083"],
    },
    {
        "name": "Privilege Escalation via Default Creds + IDOR",
        "requires": ["default_creds", "idor"],
        "impact": "CRITICAL",
        "description": "Login with default creds, use IDOR to access admin functions.",
        "steps": [
            "Log in with default credentials (low-privilege account)",
            "Enumerate API endpoints with IDOR",
            "Access admin panel or other users' data via parameter manipulation"
        ],
        "mitre": ["T1078", "T1087"],
    },
    {
        "name": "Session Hijacking via XSS + Missing HTTPOnly",
        "requires": ["xss", "cookie"],
        "impact": "HIGH",
        "description": "XSS + missing HTTPOnly flag = cookie theft = session hijacking.",
        "steps": [
            "Find XSS vulnerability",
            "Confirm session cookie lacks HttpOnly flag",
            "Use XSS to steal document.cookie → hijack session"
        ],
        "mitre": ["T1059.007", "T1185"],
    },
    {
        "name": "Source Code Leak via .git + Hardcoded Secrets",
        "requires": ["git_exposed", "secrets"],
        "impact": "CRITICAL",
        "description": "Exposed .git directory allows full source dump → find hardcoded secrets.",
        "steps": [
            "Fetch /.git/config to confirm git directory exposed",
            "Use git-dumper to extract full repository",
            "Search source code for hardcoded API keys, passwords, DB creds"
        ],
        "mitre": ["T1083", "T1552"],
    },
    {
        "name": "Blind RCE via SSTI + WAF Bypass",
        "requires": ["ssti"],
        "impact": "CRITICAL",
        "description": "SSTI in template engine leads to server-side code execution.",
        "steps": [
            "Identify template engine (Jinja2, Twig, Freemarker, etc.)",
            "Craft engine-specific payload for RCE",
            "Execute system commands → full server compromise"
        ],
        "mitre": ["T1059", "T1190"],
    },
    {
        "name": "Open Redirect + Phishing Chain",
        "requires": ["open_redirect"],
        "impact": "MEDIUM",
        "description": "Open redirect on trusted domain used for phishing attacks.",
        "steps": [
            "Craft URL: https://trusted.com/redirect?url=https://evil.com",
            "Victim trusts the domain, clicks link",
            "Gets redirected to phishing/malware page"
        ],
        "mitre": ["T1566", "T1192"],
    },
    {
        "name": "Auth Bypass via SQL Injection",
        "requires": ["sqli", "auth"],
        "impact": "CRITICAL",
        "description": "SQLi in login form allows authentication bypass.",
        "steps": [
            "Inject ' OR '1'='1'-- into username field",
            "Backend query returns true → login bypassed",
            "Access admin panel or any account"
        ],
        "mitre": ["T1190", "T1078"],
    },
    {
        "name": "Data Breach via Exposed S3 + Sensitive Files",
        "requires": ["s3_exposed"],
        "impact": "CRITICAL",
        "description": "Public S3 bucket containing sensitive user/business data.",
        "steps": [
            "Access public S3 bucket URL",
            "List all objects (ListBucket permission)",
            "Download sensitive files: backups, user data, credentials"
        ],
        "mitre": ["T1530", "T1552"],
    },
]


def _normalize_findings(findings):
    """Convert finding titles to lowercase keyword tags"""
    tags = set()
    for f in findings:
        title = f.get("title", "").lower()
        desc = f.get("description", "").lower()
        combined = title + " " + desc

        if "xss" in combined or "cross-site scripting" in combined:
            tags.add("xss")
        if "sql" in combined or "sqli" in combined:
            tags.add("sqli")
        if "ssrf" in combined:
            tags.add("ssrf")
        if "lfi" in combined or "local file" in combined or "path traversal" in combined:
            tags.add("lfi")
        if "idor" in combined or "insecure direct" in combined:
            tags.add("idor")
        if "csrf" in combined:
            tags.add("csrf")
        if "ssti" in combined or "template injection" in combined:
            tags.add("ssti")
        if "open redirect" in combined:
            tags.add("open_redirect")
        if "default cred" in combined or "default password" in combined:
            tags.add("default_creds")
        if "s3" in combined and ("public" in combined or "exposed" in combined):
            tags.add("s3_exposed")
        if ".git" in combined and "exposed" in combined:
            tags.add("git_exposed")
        if "secret" in combined or "api key" in combined or "token" in combined:
            tags.add("secrets")
        if "cloud" in combined or "metadata" in combined:
            tags.add("cloud")
        if "cookie" in combined or "httponly" in combined or "session" in combined:
            tags.add("cookie")
        if "auth" in combined or "authentication" in combined:
            tags.add("auth")

    return tags


class ChainAnalyzer:
    def __init__(self, memory, llm, logger, session_id):
        self.memory = memory
        self.llm = llm
        self.logger = logger
        self.session_id = session_id
        self.mitre = MITREMapper()

    def _boost_chain_findings(self, findings, chain):
        """
        When a chain is confirmed, boost the severity of its constituent findings.
        Medium + Medium forming a Critical chain → both get boosted to High minimum.
        This makes the real impact visible in the report.
        """
        sev_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        chain_rank = sev_rank.get(chain["impact"], 3)
        boost_to = "HIGH" if chain_rank >= 3 else "MEDIUM"

        for finding in findings:
            title_lower = finding.get("title", "").lower()
            desc_lower = finding.get("description", "").lower()
            combined = title_lower + " " + desc_lower

            # Check if this finding is part of the chain
            is_member = any(req in combined for req in chain["requires"])
            if not is_member:
                continue

            current_sev = finding.get("severity", "LOW")
            if sev_rank.get(current_sev, 0) < sev_rank.get(boost_to, 0):
                # Update in DB
                try:
                    self.memory.conn.execute(
                        "UPDATE findings SET severity=?, description=? "
                        "WHERE id=? AND session_id=?",
                        (
                            boost_to,
                            finding["description"] +
                            f"\n[Chain Boost] Severity elevated to {boost_to} "
                            f"because this finding is part of chain: '{chain['name']}'",
                            finding["id"],
                            self.session_id
                        )
                    )
                    self.memory.conn.commit()
                    self.logger.info(
                        f"Chain boost: '{finding['title']}' "
                        f"{current_sev}→{boost_to} (chain: {chain['name']})",
                        "ChainAnalyzer"
                    )
                except Exception:
                    pass

    def analyze(self):
        """
        Main entry point — analyze all findings and find chains
        Returns list of discovered chains
        """
        findings = self.memory.get_findings(self.session_id)
        if not findings:
            self.logger.info("No findings to chain-analyze yet.", "ChainAnalyzer")
            return []

        self.logger.info(
            f"Analyzing {len(findings)} findings for vulnerability chains...",
            "ChainAnalyzer"
        )

        tags = _normalize_findings(findings)
        self.logger.info(f"Detected vulnerability types: {', '.join(tags)}", "ChainAnalyzer")

        # Find matching known chains
        matched_chains = []
        for chain in KNOWN_CHAINS:
            required = set(chain["requires"])
            if required.issubset(tags):
                matched_chains.append(chain)
                self.logger.finding(
                    f"Chain: {chain['name']}",
                    chain["impact"],
                    f"Requires: {', '.join(chain['requires'])}"
                )
                # Boost severity of constituent findings in the chain
                self._boost_chain_findings(findings, chain)

        # AI-powered chain discovery — finds chains not in hardcoded list
        finding_summary = [
            f"{f['title']} [{f['severity']}]" for f in findings
        ]
        ai_analysis = self.llm.quick_ask(
            f"You are a senior penetration tester. Given these vulnerabilities found on a target:\n"
            f"{chr(10).join(finding_summary)}\n\n"
            f"Identify any 2-4 step attack chains that combine these vulnerabilities "
            f"for higher impact. For each chain: name it, explain the steps, "
            f"and state the final impact. Be specific and technical. "
            f"If no chains possible, say so."
        )

        self.logger.info(f"\n  🔗 AI Chain Analysis:\n  {ai_analysis}", "ChainAnalyzer")

        # Save chains to memory
        for chain in matched_chains:
            self.memory.add_finding(
                self.session_id,
                f"[CHAIN] {chain['name']}",
                chain["impact"],
                f"Vulnerability chain: {chain['description']}\n"
                f"Steps: {' → '.join(chain['steps'])}",
                "Multiple locations",
                f"Requires: {', '.join(chain['requires'])}",
                chain["mitre"][0] if chain["mitre"] else "T1190"
            )

        return matched_chains

    def print_chains(self, chains):
        """Pretty print discovered chains"""
        from core.logger import Colors
        if not chains:
            print(f"\n  {Colors.YELLOW}No known vulnerability chains detected.{Colors.RESET}")
            print(f"  {Colors.DIM}This doesn't mean chains don't exist — check AI analysis above.{Colors.RESET}\n")
            return

        print(f"\n{Colors.BOLD}  ⛓️  Vulnerability Chains Discovered: {len(chains)}{Colors.RESET}\n")
        for i, chain in enumerate(chains, 1):
            sev_color = Colors.RED if chain["impact"] == "CRITICAL" else Colors.YELLOW
            print(f"  {Colors.BOLD}{i}. {chain['name']}{Colors.RESET}")
            print(f"     Impact: {sev_color}{chain['impact']}{Colors.RESET}")
            print(f"     {chain['description']}")
            print(f"     Steps:")
            for j, step in enumerate(chain["steps"], 1):
                print(f"       {j}. {step}")
            print()
