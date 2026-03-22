"""
RAJAN OSINT Agent
Google dorking, GitHub leaks, S3 bucket checks
Scope-enforced: only runs on in-scope targets
"""
import urllib.request
import urllib.parse
from agents.base import BaseAgent
from tools.toolmanager import ToolManager


class OSINTAgent(BaseAgent):
    def __init__(self, memory, llm, logger, session_id, target):
        super().__init__(memory, llm, logger, session_id, target)
        self.name = "OSINTAgent"

    def run_task(self, task_name):
        tl = task_name.lower()
        if "google" in tl or "dork" in tl:
            return self.google_dorks()
        elif "github" in tl or "code" in tl:
            return self.github_leak_check()
        elif "cloud" in tl or "s3" in tl:
            return self.cloud_bucket_check()
        return self.google_dorks()

    def google_dorks(self):
        if not self.is_in_scope(self.target):
            return f"Target {self.target} out of scope — skipped"

        self.logger.info(f"Generating Google dorks for {self.target}", "OSINT")
        dorks = [
            f'site:{self.target} filetype:env',
            f'site:{self.target} filetype:sql',
            f'site:{self.target} inurl:admin',
            f'site:{self.target} inurl:login',
            f'site:{self.target} "api_key" OR "secret" OR "password"',
            f'site:{self.target} filetype:log',
            f'site:{self.target} intitle:"index of"',
            f'site:{self.target} inurl:backup',
        ]
        for d in dorks:
            self.logger.info(f"  → {d}", "OSINT")
            self.save_intel("dork", d, "pending_manual_check")

        analysis = self.ask_llm(
            f"What are the best Google dork queries to find sensitive files "
            f"or admin panels for {self.target}? Give 5 targeted dorks."
        )
        self.logger.info(analysis, "OSINT")
        return f"Generated {len(dorks)} dorks"

    def github_leak_check(self):
        if not self.is_in_scope(self.target):
            return f"Target {self.target} out of scope — skipped"

        self.logger.info(f"GitHub leak search for {self.target}", "OSINT")
        domain_short = self.target.replace("www.", "").split(".")[0]
        searches = [
            f'"{self.target}" password',
            f'"{domain_short}" api_key',
            f'"{domain_short}" secret',
            f'"{self.target}" .env',
        ]
        for s in searches:
            url = f"https://github.com/search?q={urllib.parse.quote(s)}&type=code"
            self.logger.info(f"  → {url}", "OSINT")
            self.save_intel("github_search", s, url)
        return f"Generated {len(searches)} GitHub searches"

    def cloud_bucket_check(self):
        if not self.is_in_scope(self.target):
            return f"Target {self.target} out of scope — skipped"

        self.logger.info("Checking for exposed cloud buckets", "OSINT")
        domain_short = self.target.replace("www.", "").split(".")[0]
        buckets = [
            f"https://{domain_short}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{domain_short}",
            f"https://{domain_short}-backup.s3.amazonaws.com",
            f"https://{domain_short}-dev.s3.amazonaws.com",
            f"https://storage.googleapis.com/{domain_short}",
        ]
        for bucket_url in buckets:
            # Scope check: cloud buckets are external — only check if target is in name
            if domain_short not in bucket_url:
                continue
            try:
                req = urllib.request.Request(
                    bucket_url, headers={"User-Agent": "Mozilla/5.0"}
                )
                with urllib.request.urlopen(req, timeout=5) as r:
                    body = r.read(500).decode("utf-8", errors="ignore")
                    if "ListBucketResult" in body or "Contents" in body:
                        self.add_finding(
                            "Public S3 Bucket Exposed", "CRITICAL",
                            f"S3 bucket publicly accessible and listing files.",
                            bucket_url, "", "T1530"
                        )
            except Exception:
                pass
        return "Cloud bucket check complete"
