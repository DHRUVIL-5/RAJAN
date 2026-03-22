"""
RAJAN Cloud Agent
Cloud misconfiguration detection
Scope-enforced: only checks buckets belonging to the target domain
"""
import requests
import urllib3
from agents.base import BaseAgent

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CloudAgent(BaseAgent):
    def __init__(self, memory, llm, logger, session_id, target):
        super().__init__(memory, llm, logger, session_id, target)
        self.name = "CloudAgent"

    def run_task(self, task_name):
        return self.cloud_checks()

    def cloud_checks(self):
        if not self.is_in_scope(self.target):
            return f"Target {self.target} out of scope — skipped"

        self.logger.info("Running cloud security checks", "Cloud")
        base_name = self.target.replace("www.", "").split(".")[0]

        # Only check buckets that contain the target domain name
        checks = [
            f"https://{base_name}.s3.amazonaws.com",
            f"https://{base_name}-assets.s3.amazonaws.com",
            f"https://storage.googleapis.com/{base_name}",
            f"https://{base_name}.blob.core.windows.net",
        ]

        for url in checks:
            # Extra guard: only proceed if domain name is in URL
            if base_name not in url:
                continue
            try:
                r = requests.get(url, timeout=5, verify=False)
                body = r.text[:200]
                if any(kw in body for kw in
                       ["ListBucketResult", "Contents", "BlobServiceProperties"]):
                    self.add_finding(
                        "Public Cloud Storage Exposed", "CRITICAL",
                        f"Cloud storage at {url} is publicly accessible.",
                        url, "", "T1530"
                    )
            except Exception:
                pass

        analysis = self.ask_llm(
            f"What cloud-specific vulnerabilities and misconfigurations should "
            f"be checked for {self.target}? Give 5 specific checks."
        )
        self.logger.info(analysis, "Cloud")
        return "Cloud checks complete"
