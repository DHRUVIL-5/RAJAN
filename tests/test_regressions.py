import csv
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from agents.scanner import ScannerAgent
from agents.web import WebAgent
from core.memory import Memory
from core.scope import ScopeEnforcer
from core.task_tree import TaskTree
from core.llm import LLMConnector
from core.logger import Logger
from core.exporter import Exporter
from knowledge.reporter_engine import save_reports
from rajan import RAJAN
from tools.toolmanager import ToolManager


class RegressionTests(unittest.TestCase):
    def test_scope_normalizes_urls_and_respects_boundaries(self):
        scope = ScopeEnforcer("https://example.com:443/path", "*.example.com")
        self.assertTrue(scope.is_in_scope("https://example.com:443/a"))
        self.assertTrue(scope.is_in_scope("https://api.example.com:8443"))
        self.assertFalse(scope.is_in_scope("https://example.com.attacker.test"))
        self.assertFalse(scope.is_in_scope("https://attacker.test"))

    def test_task_state_is_persisted_and_restored(self):
        with tempfile.TemporaryDirectory() as tmp:
            memory = Memory(os.path.join(tmp, "state.db"))
            sid = memory.create_session("example.com")
            tree = TaskTree("example.com", memory=memory, session_id=sid)
            tree.build_default_tree()
            first = tree.get_next_task()
            tree.mark_done(first, "ok")

            restored = TaskTree("example.com", memory=memory, session_id=sid)
            restored.build_default_tree()
            self.assertEqual(restored.tasks[0].status, "done")
            self.assertEqual(restored.tasks[0].result, "ok")
            self.assertNotEqual(restored.get_next_task().task_id, first.task_id)
            memory.close()

    def test_duplicate_findings_are_not_inserted(self):
        with tempfile.TemporaryDirectory() as tmp:
            memory = Memory(os.path.join(tmp, "findings.db"))
            sid = memory.create_session("example.com")
            self.assertTrue(memory.add_finding(sid, "XSS", "HIGH", "desc", "/search"))
            self.assertFalse(memory.add_finding(sid, "XSS", "HIGH", "desc", "/search"))
            finding = memory.get_findings(sid)[0]
            self.assertIn("confidence_score", finding)
            memory.close()

    def test_tool_manager_reports_nonzero_exit(self):
        completed = subprocess.CompletedProcess(["fake"], 3, "", "bad input")
        with patch.object(ToolManager, "check", return_value=True), patch(
            "tools.toolmanager.subprocess.run", return_value=completed
        ):
            ok, output = ToolManager.run("nmap", [])
        self.assertFalse(ok)
        self.assertIn("exit code 3", output)

    def test_cli_scope_parser_accepts_colon_and_equals(self):
        rajan = RAJAN.__new__(RAJAN)
        target, scope, mode = rajan._extract_scan_params(
            "scan example.com scope: *.example.com step by step"
        )
        self.assertEqual(target, "example.com")
        self.assertEqual(scope, "*.example.com")
        self.assertEqual(mode, "semi")
        self.assertEqual(
            rajan._extract_scan_params("scan example.com scope=example.com")[1],
            "example.com",
        )

    def test_dry_run_agents_do_not_probe_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            memory = Memory(os.path.join(tmp, "dry.db"))
            sid = memory.create_session("example.com")
            logger = Logger()
            scanner = ScannerAgent(memory, LLMConnector(), logger, sid, "example.com")
            scanner.dry_run = True
            self.assertIn("skipped", scanner.port_scan().lower())
            with patch("agents.web.requests.get", side_effect=AssertionError("network")):
                web = WebAgent(
                    memory, LLMConnector(), logger, sid, "example.com", dry_run=True
                )
            self.assertIn("skipped", web.analyze_js().lower())
            self.assertIn("skipped", web.check_ssl().lower())
            memory.close()

    def test_reports_escape_content_and_keep_output_inside_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                memory = Memory(os.path.join(tmp, "reports.db"))
                sid = memory.create_session("../../evil/<target>")
                memory.add_finding(
                    sid, "<script>alert(1)</script>", "HIGH",
                    "<img src=x onerror=alert(1)>", "https://example.com/?q=<x>", "<proof>",
                )
                session = memory.get_session(sid)
                findings = memory.get_findings(sid)
                md, html = save_reports(session, findings, memory.get_intel(sid), memory.count_findings(sid))
                self.assertTrue(os.path.abspath(md).startswith(os.path.abspath("reports")))
                self.assertTrue(os.path.abspath(html).startswith(os.path.abspath("reports")))
                with open(html, encoding="utf-8") as handle:
                    html_text = handle.read()
                self.assertNotIn("<script>alert(1)</script>", html_text)
                self.assertIn("&lt;script&gt;", html_text)
                memory.close()
            finally:
                os.chdir(old_cwd)

    def test_csv_contains_scoring_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_cwd = os.getcwd()
            os.chdir(tmp)
            try:
                memory = Memory(os.path.join(tmp, "csv.db"))
                sid = memory.create_session("example.com")
                memory.add_finding(
                    sid, "SQL Injection", "CRITICAL", "desc", "/id", "proof",
                    scoring={"cvss_score": 9.0, "confidence_score": 90,
                             "confidence_label": "CONFIRMED", "reliability": "HIGH"},
                )
                path = Exporter(memory, sid).export_csv()
                with open(path, newline="", encoding="utf-8") as handle:
                    header = next(csv.reader(handle))
                self.assertIn("CVSS", header)
                self.assertIn("Confidence", header)
                memory.close()
            finally:
                os.chdir(old_cwd)


if __name__ == "__main__":
    unittest.main()
