"""
RAJAN Self-Test & Auto-Update System
--selftest: verifies all components work correctly
--update:   checks GitHub for newer version
"""

import sys
import os
import urllib.request
import json


CURRENT_VERSION = "1.0.0"
GITHUB_REPO = "DHRUVIL-5/RAJAN"


def run_selftest():
    """Run comprehensive self-test — verifies everything works"""
    passed = 0
    failed = 0
    errors = []

    def test(name, fn):
        nonlocal passed, failed
        try:
            fn()
            print(f"  ✅ {name}")
            passed += 1
        except Exception as e:
            print(f"  ❌ {name} — {e}")
            errors.append(f"{name}: {e}")
            failed += 1

    print("\n╔══════════════════════════════════════════════════╗")
    print("║         RAJAN Self-Test v1.0.0                  ║")
    print("╚══════════════════════════════════════════════════╝\n")

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    # Core modules
    def test_memory():
        from core.memory import Memory
        m = Memory("memory/selftest_tmp.db")
        sid = m.create_session("test.com")
        m.add_finding(sid, "Test", "HIGH", "desc", "loc", "proof", "T1190")
        assert len(m.get_findings(sid)) == 1
        m.close()
        os.remove("memory/selftest_tmp.db")

    def test_llm_config():
        from core.llm import LLMConnector
        l = LLMConnector()
        assert len(l.PROVIDERS) == 6

    def test_llm_connectivity():
        """Test actual LLM API connection if configured"""
        from core.llm import LLMConnector
        l = LLMConnector()
        if not l.is_configured():
            print("  ⚠️  LLM not configured — skipping connectivity test")
            print("       Run: python3 rajan.py --setup")
            return
        # Try a minimal API call
        provider = l.config.get("provider_name", "Unknown")
        response = l.quick_ask("Reply with exactly: RAJAN_OK")
        assert response and len(response) > 0, "LLM returned empty response"
        print(f"       Provider: {provider} ✓")

    def test_logger():
        from core.logger import Logger
        lg = Logger()
        assert hasattr(lg, "info") and hasattr(lg, "finding")

    def test_task_tree():
        from core.task_tree import TaskTree
        tt = TaskTree("t.com")
        tasks = tt.build_default_tree()
        assert len(tasks) == 19

    def test_tool_manager():
        from tools.toolmanager import ToolManager
        avail = ToolManager.available_tools()
        assert len(avail) > 0
        ok, out = ToolManager.run("python3", ["--version"])
        assert ok

    def test_mitre():
        from knowledge.mitre import MITREMapper
        m = MITREMapper()
        assert m.get_technique("T1190") is not None
        assert len(m.db) >= 20

    def test_cve_db():
        from knowledge.cve_db import CVEDatabase
        db = CVEDatabase()
        assert db.get("CVE-2021-44228") is not None
        assert len(db.get_all_critical()) >= 10

    def test_payloads():
        from knowledge.payloads import PayloadLibrary
        lib = PayloadLibrary()
        assert len(lib.list_categories()) >= 10
        assert len(lib.get_payloads("xss", "basic")) >= 3

    def test_methodology():
        from knowledge.methodology import BugBountyGuide
        g = BugBountyGuide()
        assert g.assess_severity("sql injection") == "HIGH"
        assert g.assess_severity("rce unauthenticated") == "CRITICAL"

    def test_notifier():
        from core.notifier import Notifier
        n = Notifier()
        assert hasattr(n, "notify")

    def test_chain_analyzer():
        from core.chain_analyzer import ChainAnalyzer, _normalize_findings
        tags = _normalize_findings([
            {"title": "Reflected XSS", "description": "xss in param"},
            {"title": "Missing CSRF Token", "description": "no csrf"},
        ])
        assert "xss" in tags and "csrf" in tags

    def test_exporter():
        from core.exporter import Exporter
        from core.memory import Memory
        m = Memory("memory/selftest_exp.db")
        sid = m.create_session("test.com")
        m.add_finding(sid, "XSS", "HIGH", "desc", "loc", "", "T1059.007")
        e = Exporter(m, sid)
        fname = e.export_json()
        assert os.path.exists(fname)
        os.remove(fname)
        fname2 = e.export_csv()
        assert os.path.exists(fname2)
        os.remove(fname2)
        fname3 = e.export_txt()
        assert os.path.exists(fname3)
        os.remove(fname3)
        fname4 = e.export_hackerone()
        assert os.path.exists(fname4)
        os.remove(fname4)
        m.close()
        os.remove("memory/selftest_exp.db")

    def test_config():
        from core.config import Config
        c = Config()
        assert c.get("scan", "default_mode") in ("auto", "semi")
        assert c.get("version") is not None

    def test_report_engine():
        from core.memory import Memory
        from knowledge.reporter_engine import save_reports
        m = Memory("memory/selftest_rep.db")
        sid = m.create_session("test.com")
        m.add_finding(sid, "SQLi", "CRITICAL", "desc", "loc", "proof", "T1190")
        session = m.get_session(sid)
        findings = m.get_findings(sid)
        intel = m.get_intel(sid)
        counts = m.count_findings(sid)
        md, html = save_reports(session, findings, intel, counts)
        assert os.path.exists(md) and os.path.exists(html)
        os.remove(md); os.remove(html)
        m.close()
        os.remove("memory/selftest_rep.db")

    def test_agents():
        from core.memory import Memory
        from core.llm import LLMConnector
        from core.logger import Logger
        m = Memory("memory/selftest_agents.db")
        sid = m.create_session("t.com")
        llm = LLMConnector()
        lg = Logger()
        from agents.recon import ReconAgent
        from agents.scanner import ScannerAgent
        from agents.web import WebAgent
        from agents.osint import OSINTAgent
        from agents.exploit import ExploitAgent
        from agents.cloud import CloudAgent
        from agents.reporter import ReporterAgent
        for AgentCls in [ReconAgent, ScannerAgent, WebAgent, OSINTAgent,
                          ExploitAgent, CloudAgent, ReporterAgent]:
            a = AgentCls(m, llm, lg, sid, "t.com")
            assert hasattr(a, "run_task")
        m.close()
        os.remove("memory/selftest_agents.db")

    print("  Testing core modules...")
    test("Memory System", test_memory)
    test("LLM Config (6 providers)", test_llm_config)
    test("LLM API Connectivity", test_llm_connectivity)
    test("Logger", test_logger)
    test("Task Tree (19 tasks)", test_task_tree)
    test("Tool Manager", test_tool_manager)

    print("\n  Testing knowledge base...")
    test("MITRE ATT&CK (21 techniques)", test_mitre)
    test("CVE Database (19 CVEs)", test_cve_db)
    test("Payload Library (10 categories)", test_payloads)
    test("Methodology & Severity", test_methodology)

    print("\n  Testing Phase 4 features...")
    test("Config System", test_config)
    test("Chain Analyzer", test_chain_analyzer)
    test("Exporter (JSON/CSV/TXT/HackerOne)", test_exporter)
    test("Notifier", test_notifier)
    test("Report Engine (MD+HTML)", test_report_engine)
    test("All 7 Agents", test_agents)

    # Summary
    total = passed + failed
    print(f"\n{'═'*50}")
    if failed == 0:
        print(f"  🎉 ALL {total}/{total} TESTS PASSED — RAJAN is healthy!")
    else:
        print(f"  ⚠️  {passed}/{total} passed, {failed} failed")
        for err in errors:
            print(f"     ❌ {err}")
    print(f"{'═'*50}\n")

    return failed == 0


def check_update():
    """Check GitHub for newer version"""
    print(f"\n  🔍 Checking for updates...")
    print(f"  Current version: v{CURRENT_VERSION}")
    try:
        url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
        req = urllib.request.Request(url, headers={"User-Agent": "RAJAN-updater"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
            latest = data.get("tag_name", "").lstrip("v")
            if latest and latest != CURRENT_VERSION:
                print(f"  🆕 New version available: v{latest}")
                print(f"  Run: git pull to update")
                print(f"  Or:  https://github.com/{GITHUB_REPO}/releases/latest")
            else:
                print(f"  ✅ You are on the latest version!")
    except Exception:
        print(f"  ℹ️  Could not check for updates (no internet or API blocked)")
    print()
