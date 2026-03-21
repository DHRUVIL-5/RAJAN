"""RAJAN Cloud Agent"""
from agents.base import BaseAgent
import urllib.request


class CloudAgent(BaseAgent):
    def __init__(self, memory, llm, logger, session_id, target):
        super().__init__(memory, llm, logger, session_id, target)
        self.name = "CloudAgent"

    def run_task(self, task_name):
        return self.cloud_checks()

    def cloud_checks(self):
        self.logger.info("Running cloud security checks", "Cloud")
        domain_parts = self.target.replace("www.", "").split(".")
        base_name = domain_parts[0]

        # Check common misconfigs
        checks = [
            f"https://{base_name}.s3.amazonaws.com",
            f"https://{base_name}-assets.s3.amazonaws.com",
            f"https://storage.googleapis.com/{base_name}",
            f"https://{base_name}.blob.core.windows.net",
        ]
        for url in checks:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=5) as r:
                    body = r.read(200).decode("utf-8", errors="ignore")
                    if any(kw in body for kw in ["ListBucketResult", "Contents", "BlobServiceProperties"]):
                        self.add_finding(
                            "Public Cloud Storage Exposed",
                            "CRITICAL",
                            f"Cloud storage at {url} is publicly accessible",
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
