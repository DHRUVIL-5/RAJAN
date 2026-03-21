"""
RAJAN OSINT Agent
Google dorking, GitHub leaks, Shodan
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
        task_lower = task_name.lower()
        if "google" in task_lower or "dork" in task_lower:
            return self.google_dorks()
        elif "github" in task_lower or "code" in task_lower:
            return self.github_leak_check()
        elif "cloud" in task_lower or "s3" in task_lower:
            return self.cloud_bucket_check()
        return self.google_dorks()

    def google_dorks(self):
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
        self.logger.info("Google Dorks to manually check:", "OSINT")
        for d in dorks:
            self.logger.info(f"  → {d}", "OSINT")
            self.save_intel("dork", d, "pending_manual_check")

        analysis = self.ask_llm(
            f"What are the best Google dork queries to find sensitive files "
            f"or admin panels for {self.target}? Give 5 targeted dorks."
        )
        self.logger.info(analysis, "OSINT")
        return f"Generated {len(dorks)} dorks for manual verification"

    def github_leak_check(self):
        self.logger.info(f"Checking GitHub for {self.target} leaks", "OSINT")
        domain_short = self.target.replace("www.", "").split(".")[0]
        searches = [
            f'"{self.target}" password',
            f'"{domain_short}" api_key',
            f'"{domain_short}" secret',
            f'"{self.target}" .env',
        ]
        self.logger.info("GitHub search URLs to check manually:", "OSINT")
        for s in searches:
            url = f"https://github.com/search?q={urllib.parse.quote(s)}&type=code"
            self.logger.info(f"  → {url}", "OSINT")
            self.save_intel("github_search", s, url)

        return f"Generated {len(searches)} GitHub searches for manual verification"

    def cloud_bucket_check(self):
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
            try:
                req = urllib.request.Request(
                    bucket_url,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                with urllib.request.urlopen(req, timeout=5) as r:
                    body = r.read(500).decode("utf-8", errors="ignore")
                    if "ListBucketResult" in body or "Contents" in body:
                        self.add_finding(
                            "Public S3 Bucket Exposed",
                            "CRITICAL",
                            f"S3 bucket is publicly accessible and lists files",
                            bucket_url, "", "T1530"
                        )
            except Exception:
                pass
        return "Cloud bucket check complete"
