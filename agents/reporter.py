"""
RAJAN Reporter Agent v2 — Uses full knowledge base
Generates HTML + Markdown professional reports
"""
import os
from agents.base import BaseAgent
from knowledge.reporter_engine import save_reports


class ReporterAgent(BaseAgent):
    def __init__(self, memory, llm, logger, session_id, target):
        super().__init__(memory, llm, logger, session_id, target)
        self.name = "ReporterAgent"

    def run_task(self, task_name):
        return self.generate_report()

    def generate_report(self):
        self.logger.info("Generating HTML + Markdown pentest report", "Reporter")
        findings = self.memory.get_findings(self.session_id)
        intel = self.memory.get_intel(self.session_id)
        counts = self.memory.count_findings(self.session_id)
        session = self.memory.get_session(self.session_id) or {
            "target": self.target,
            "session_id": self.session_id,
            "scope": "",
        }

        md_file, html_file = save_reports(session, findings, intel, counts, self.llm)
        self.logger.success(f"Markdown report: {md_file}", "Reporter")
        self.logger.success(f"HTML report:     {html_file}", "Reporter")
        return html_file
