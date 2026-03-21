"""
RAJAN Deep Web Agent v3
XSS, SQLi, IDOR, SSRF, LFI, SSTI, Open Redirect, CSRF, Auth, SSL
"""

import urllib.request, urllib.parse, urllib.error, re, ssl, socket, time
from agents.base import BaseAgent
from tools.toolmanager import ToolManager
from knowledge.payloads import PayloadLibrary
from knowledge.mitre import MITREMapper


class WebAgent(BaseAgent):
    def __init__(self, memory, llm, logger, session_id, target):
        super().__init__(memory, llm, logger, session_id, target)
        self.name = "WebAgent"
        self.payloads = PayloadLibrary()
        self.mitre = MITREMapper()
        self.base_url = self._resolve_base_url()
        self.hdrs = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                     "Accept": "text/html,application/json,*/*"}

    def _resolve_base_url(self):
        for scheme in ("https", "http"):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                req = urllib.request.Request(f"{scheme}://{self.target}", headers={"User-Agent":"Mozilla/5.0"})
                urllib.request.urlopen(req, timeout=5, context=ctx)
                return f"{scheme}://{self.target}"
            except Exception:
                continue
        return f"https://{self.target}"

    def _ctx(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _get(self, path="", params=None, timeout=8):
        try:
            url = f"{self.base_url}{path}"
            if params: url += "?" + urllib.parse.urlencode(params)
            req = urllib.request.Request(url, headers=self.hdrs)
            with urllib.request.urlopen(req, timeout=timeout, context=self._ctx()) as r:
                return r.status, r.read(16384).decode("utf-8", errors="ignore"), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, "", {}
        except Exception:
            return 0, "", {}

    def _post(self, path="", data=None, timeout=8):
        try:
            url = f"{self.base_url}{path}"
            post_data = urllib.parse.urlencode(data or {}).encode()
            h = {**self.hdrs, "Content-Type": "application/x-www-form-urlencoded"}
            req = urllib.request.Request(url, data=post_data, headers=h)
            with urllib.request.urlopen(req, timeout=timeout, context=self._ctx()) as r:
                return r.status, r.read(8192).decode("utf-8", errors="ignore"), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, "", {}
        except Exception:
            return 0, "", {}

    def run_task(self, task_name):
        tl = task_name.lower()
        dispatch = [
            ("directory", self.directory_discovery), ("endpoint", self.directory_discovery),
            ("xss", self.test_xss), ("sql", self.test_sqli),
            ("fingerprint", self.fingerprint), ("tech", self.fingerprint),
            ("js file", self.analyze_js), ("secret", self.analyze_js),
            ("ssl", self.check_ssl), ("tls", self.check_ssl),
            ("auth", self.test_auth), ("idor", self.test_idor),
            ("ssrf", self.test_ssrf), ("lfi", self.test_lfi),
            ("redirect", self.test_open_redirect), ("csrf", self.test_csrf),
            ("ssti", self.test_ssti),
        ]
        for kw, fn in dispatch:
            if kw in tl:
                return fn()
        return self.fingerprint()

    def fingerprint(self):
        self.logger.info(f"Fingerprinting {self.base_url}", "Web")
        status, body, headers = self._get()
        if status == 0:
            self.logger.warning("Target unreachable", "Web"); return "Unreachable"
        server = headers.get("Server",""); powered = headers.get("X-Powered-By","")
        if server: self.save_intel("tech","server",server); self.logger.success(f"Server: {server}","Web")
        if powered: self.save_intel("tech","powered_by",powered)
        techs = {"WordPress":["wp-content"],"Joomla":["joomla"],"Drupal":["drupal"],
                 "Laravel":["laravel_session"],"Django":["csrfmiddlewaretoken"],
                 "React":["react","__NEXT_DATA__"],"Angular":["ng-version"],
                 "ASP.NET":["VIEWSTATE"],"PHP":[".php","PHPSESSID"],
                 "Spring":["JSESSIONID"],"Express":["X-Powered-By: Express"]}
        detected = []
        bl = body.lower()
        for tech, sigs in techs.items():
            if any(s.lower() in bl or s in str(headers) for s in sigs):
                detected.append(tech); self.save_intel("tech","framework",tech)
                self.logger.success(f"Detected: {tech}","Web")
        sec_headers = {"Content-Security-Policy":"T1059.007","X-Frame-Options":"T1059.007",
                       "Strict-Transport-Security":"T1573","X-Content-Type-Options":"T1027"}
        for h, mid in sec_headers.items():
            if not headers.get(h):
                self.add_finding(f"Missing Security Header: {h}","LOW",
                    f"HTTP response missing {h} header.",self.base_url,"",mid)
        return f"Status:{status} Tech:{', '.join(detected) or 'Unknown'}"

    def directory_discovery(self):
        self.logger.info("Directory discovery", "Web"); found = []
        ok, out = ToolManager.run("gobuster",
            ["dir","-u",self.base_url,"-w","/usr/share/wordlists/dirb/common.txt",
             "-q","--no-error","-t","20"],timeout=180)
        if ok and out:
            for line in out.splitlines():
                if "(Status: 2" in line or "(Status: 3" in line:
                    path = line.split()[0]; self.save_intel("endpoint",path,"found")
                    found.append(path); self.logger.success(f"Found: {line.strip()}","Web")
            return f"{len(found)} paths found"
        paths = ["/admin","/admin/login","/login","/dashboard","/api","/api/v1","/api/v2",
                 "/.env","/.git","/.git/config","/backup","/backup.zip","/db.sql",
                 "/config","/robots.txt","/sitemap.xml","/swagger","/graphql",
                 "/wp-admin","/wp-login.php","/phpmyadmin","/uploads",
                 "/actuator","/actuator/env","/server-status","/debug",
                 "/.well-known/security.txt","/console","/adminer.php"]
        for path in paths:
            status, body, _ = self._get(path)
            if status in (200,301,302,403):
                found.append(f"{path}[{status}]"); self.save_intel("endpoint",path,str(status))
                self.logger.success(f"Found: {path} → {status}","Web")
                if status == 200 and path in ["/.env","/.git/config","/backup.zip","/db.sql","/actuator/env"]:
                    self.add_finding(f"Sensitive File Exposed: {path}","CRITICAL",
                        f"Sensitive file at {path} publicly accessible.",
                        f"{self.base_url}{path}",f"HTTP 200","T1083")
        return f"{len(found)} endpoints found"

    def test_xss(self):
        self.logger.info("XSS testing","Web")
        payloads = self.payloads.get_payloads("xss","basic")[:5]
        endpoints = self.memory.get_intel(self.session_id,"endpoint")
        params = ["q","search","id","name","input","query","term"]
        tested = found = 0
        for _, path, _ in endpoints[:8]:
            for payload in payloads:
                for param in params[:3]:
                    status, body, _ = self._get(path, {param: payload})
                    tested += 1
                    if payload in body and status == 200:
                        self.add_finding(f"Reflected XSS — param '{param}'","HIGH",
                            "XSS payload reflected unsanitized in response.",
                            f"{self.base_url}{path}?{param}=",f"Payload:{payload[:60]}","T1059.007")
                        found += 1; break
        return f"XSS: {tested} tested, {found} found"

    def test_sqli(self):
        self.logger.info("SQL Injection testing","Web")
        det = self.payloads.get_payloads("sqli","detection")
        err_signs = ["sql syntax","mysql_fetch","ora-","postgresql","sqlite3",
                     "syntax error","you have an error in your sql","invalid query"]
        endpoints = self.memory.get_intel(self.session_id,"endpoint")
        tested = found = 0
        for _, path, _ in endpoints[:8]:
            for payload in det[:6]:
                for param in ["id","user","name","search","page"]:
                    status, body, _ = self._get(path, {param: payload})
                    tested += 1
                    if any(s in body.lower() for s in err_signs):
                        self.add_finding("SQL Injection — Error-Based","CRITICAL",
                            f"SQL error triggered via '{param}' param.",
                            f"{self.base_url}{path}",f"Param:{param} Payload:{payload[:50]}","T1190")
                        found += 1; break
            # Time-based
            for payload in self.payloads.get_payloads("sqli","blind_time")[:1]:
                t0 = time.time()
                self._get(path,{"id":payload})
                if time.time()-t0 >= 4.5:
                    self.add_finding("SQL Injection — Time-Based Blind","CRITICAL",
                        "Response delayed ~5s with time-based payload.",
                        f"{self.base_url}{path}",f"Payload:{payload[:50]}","T1190")
                    found += 1
        return f"SQLi: {tested} tested, {found} found"

    def analyze_js(self):
        self.logger.info("JS file secret analysis","Web")
        status, body, _ = self._get()
        js_files = re.findall(r'(?:src|href)=["\']([^"\']+\.js[^"\']*)["\']', body)
        js_urls = []
        for js in js_files:
            js_urls.append(js if js.startswith("http") else f"{self.base_url}/{js.lstrip('/')}")
        for p in ["/static/js/main.js","/assets/js/app.js","/bundle.js","/main.bundle.js"]:
            s,_,_ = self._get(p)
            if s == 200: js_urls.append(f"{self.base_url}{p}")
        patterns = [("API Key",r'(?i)api[_-]?key\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']'),
                    ("Secret",r'(?i)secret\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']'),
                    ("AWS Key",r'(AKIA[0-9A-Z]{16})'),
                    ("GitHub Token",r'(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})'),
                    ("Firebase",r'(AIza[0-9A-Za-z\-_]{35})'),
                    ("Private Key",r'-----BEGIN (RSA |EC )?PRIVATE KEY-----')]
        found = 0
        for js_url in js_urls[:15]:
            try:
                req = urllib.request.Request(js_url, headers=self.hdrs)
                with urllib.request.urlopen(req, timeout=8, context=self._ctx()) as r:
                    content = r.read(100000).decode("utf-8",errors="ignore")
                for name, pat in patterns:
                    if re.search(pat, content):
                        found += 1
                        self.add_finding(f"Exposed {name} in JavaScript","CRITICAL",
                            f"Hardcoded {name} in client-side JS.",js_url,"pattern matched","T1552")
            except Exception:
                pass
        return f"JS: {len(js_urls)} files analyzed, {found} secrets found"

    def check_ssl(self):
        self.logger.info("SSL/TLS check","Web")
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.target) as s:
                s.settimeout(5); s.connect((self.target,443))
                cert = s.getpeercert(); cipher = s.cipher(); version = s.version()
                self.save_intel("ssl","version",version); self.save_intel("ssl","cipher",str(cipher[0]))
                self.logger.success(f"TLS:{version} Cipher:{cipher[0]}","Web")
                if any(w in str(cipher[0]).upper() for w in ["RC4","DES","3DES","NULL"]):
                    self.add_finding("Weak SSL Cipher","HIGH",f"Weak cipher: {cipher[0]}",self.target,"","T1573")
                if version in ("TLSv1","TLSv1.1","SSLv3"):
                    self.add_finding(f"Outdated TLS: {version}","MEDIUM",
                        f"{version} is deprecated.",self.target,"","T1573")
                return f"SSL OK: {version}"
        except Exception as e:
            return f"SSL: {e}"

    def test_auth(self):
        self.logger.info("Auth testing","Web")
        endpoints = self.memory.get_intel(self.session_id,"endpoint")
        login_paths = [p for _,p,_ in endpoints if "login" in p or "admin" in p]
        creds = [("admin","admin"),("admin","password"),("admin","123456"),("root","root")]
        for path in login_paths[:3]:
            for user, pwd in creds[:3]:
                ps, pb, _ = self._post(path, {"username":user,"password":pwd,"user":user,"pass":pwd})
                if ps in (200,302) and any(kw in pb.lower() for kw in ["dashboard","logout","welcome"]):
                    self.add_finding(f"Default Creds Work: {user}:{pwd}","CRITICAL",
                        f"Login succeeded with default credentials.",
                        f"{self.base_url}{path}",f"{user}:{pwd}","T1078")
        analysis = self.ask_llm(f"Top 3 auth vulnerabilities to test on {self.target}?")
        self.logger.info(analysis,"Web")
        return "Auth testing done"

    def test_idor(self):
        self.logger.info("IDOR testing","Web")
        endpoints = self.memory.get_intel(self.session_id,"endpoint")
        paths = [p for _,p,_ in endpoints if "/api" in p or "/user" in p]
        paths += ["/api/v1/users/1","/api/v1/users/2","/user/1","/user/2"]
        responses = {}
        for path in paths[:10]:
            s, body, _ = self._get(path)
            if s == 200 and len(body) > 20:
                responses[path] = len(body)
        found = 0
        keys = list(responses.keys())
        for i in range(len(keys)-1):
            if abs(responses[keys[i]] - responses[keys[i+1]]) < 500:
                self.add_finding("Potential IDOR — Sequential IDs","HIGH",
                    "API returns data for sequential IDs without apparent auth.",
                    f"{self.base_url}{keys[i]}","Similar responses for ID 1 and 2","T1087")
                found += 1; break
        return f"IDOR: {found} candidates"

    def test_ssrf(self):
        self.logger.info("SSRF testing","Web")
        payloads = self.payloads.get_payloads("ssrf","basic")[:3] + \
                   self.payloads.get_payloads("ssrf","cloud_metadata")[:2]
        params = ["url","redirect","next","target","dest","link","uri","webhook","src"]
        endpoints = self.memory.get_intel(self.session_id,"endpoint")
        found = 0
        for _,path,_ in endpoints[:5]:
            for payload in payloads[:4]:
                for param in params[:4]:
                    _,body,_ = self._get(path, {param: payload})
                    if any(kw in body for kw in ["instance-id","ami-id","computeMetadata","local-ipv4"]):
                        self.add_finding("SSRF — Cloud Metadata Accessible","CRITICAL",
                            "SSRF fetched cloud metadata.",f"{self.base_url}{path}?{param}=",
                            f"Payload:{payload}","T1552.005")
                        found += 1
        return f"SSRF: {found} findings"

    def test_lfi(self):
        self.logger.info("LFI testing","Web")
        payloads = self.payloads.get_payloads("path_traversal","unix")[:5]
        params = ["file","page","include","path","template","view","doc"]
        endpoints = self.memory.get_intel(self.session_id,"endpoint")
        found = 0
        for _,path,_ in endpoints[:6]:
            for payload in payloads[:3]:
                for param in params[:4]:
                    _,body,_ = self._get(path, {param: payload})
                    if any(ind in body for ind in ["root:x:","nobody:","daemon:"]):
                        self.add_finding("Local File Inclusion (LFI)","CRITICAL",
                            f"/etc/passwd readable via '{param}'.",
                            f"{self.base_url}{path}",f"Payload:{payload}","T1083")
                        found += 1
        return f"LFI: {found} findings"

    def test_open_redirect(self):
        self.logger.info("Open Redirect testing","Web")
        payloads = self.payloads.get_payloads("open_redirect","payloads")[:4]
        params = ["redirect","url","next","return","to","dest","goto"]
        endpoints = self.memory.get_intel(self.session_id,"endpoint")
        found = 0
        for _,path,_ in endpoints[:5]:
            for payload in payloads[:3]:
                for param in params[:4]:
                    s,_,headers = self._get(path, {param: payload})
                    loc = headers.get("Location","")
                    if s in (301,302,303,307) and "evil.com" in loc:
                        self.add_finding("Open Redirect","MEDIUM",
                            f"Redirects to external URLs via '{param}'.",
                            f"{self.base_url}{path}",f"Location:{loc}","T1566")
                        found += 1
        return f"Open redirect: {found} findings"

    def test_csrf(self):
        self.logger.info("CSRF check","Web")
        endpoints = self.memory.get_intel(self.session_id,"endpoint")
        found = 0
        for _,path,_ in endpoints[:8]:
            s,body,_ = self._get(path)
            if s==200 and "<form" in body.lower() and 'method="post"' in body.lower():
                if not any(t in body.lower() for t in ["csrf","xsrf","_token","authenticity_token"]):
                    self.add_finding("Missing CSRF Token","MEDIUM",
                        f"POST form at {path} lacks CSRF protection.",
                        f"{self.base_url}{path}","POST form without csrf token","T1059.007")
                    found += 1
        return f"CSRF: {found} unprotected forms"

    def test_ssti(self):
        self.logger.info("SSTI testing","Web")
        payloads = self.payloads.get_payloads("ssti","detection")[:4]
        endpoints = self.memory.get_intel(self.session_id,"endpoint")
        found = 0
        for _,path,_ in endpoints[:5]:
            for payload in payloads:
                for param in ["name","template","q","input","msg"]:
                    _,body,_ = self._get(path, {param: payload})
                    if "49" in body and "7*7" in payload:
                        self.add_finding("SSTI — Template Expression Evaluated","CRITICAL",
                            "Server evaluates template expressions — potential RCE.",
                            f"{self.base_url}{path}",f"Payload:{payload} → '49' in response","T1059")
                        found += 1
        return f"SSTI: {found} findings"
