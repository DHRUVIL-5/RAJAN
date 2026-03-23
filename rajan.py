#!/usr/bin/env python3
"""
██████╗  █████╗      ██╗ █████╗ ███╗   ██╗
██╔══██╗██╔══██╗     ██║██╔══██╗████╗  ██║
██████╔╝███████║     ██║███████║██╔██╗ ██║
██╔══██╗██╔══██║██   ██║██╔══██║██║╚██╗██║
██║  ██║██║  ██║╚█████╔╝██║  ██║██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝

RAJAN — AI Ethical Hacking Agent v1.1.0
Your intelligent cybersecurity partner 😎
github.com/DHRUVIL-5/RAJAN

⚠️  For AUTHORIZED use only. Always get permission first.
"""

import sys
import os
import argparse
import threading
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.llm import LLMConnector
from core.memory import Memory
from core.logger import Logger, Colors
from core.brain import Brain


BANNER = f"""
{Colors.RED}{Colors.BOLD}
██████╗  █████╗      ██╗ █████╗ ███╗   ██╗
██╔══██╗██╔══██╗     ██║██╔══██╗████╗  ██║
██████╔╝███████║     ██║███████║██╔██╗ ██║
██╔══██╗██╔══██║██   ██║██╔══██║██║╚██╗██║
██║  ██║██║  ██║╚█████╔╝██║  ██║██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
{Colors.RESET}{Colors.BOLD}
    AI Ethical Hacking Agent v1.1.0
    github.com/DHRUVIL-5/RAJAN
{Colors.RESET}{Colors.DIM}
    ⚠️  For AUTHORIZED use only!
{Colors.RESET}"""

DONATION_MSG = f"""
{Colors.YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  💛 Love RAJAN? Support the project!
     RAJAN is free & open source — kept alive by donations.
     Even $1 helps keep development going! 🙏
     ➜ github.com/DHRUVIL-5/RAJAN#support
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}
"""

HELP_TEXT = """
╔══════════════════════════════════════════════════════╗
║              RAJAN v1.1.0 — How to Talk to Me       ║
╠══════════════════════════════════════════════════════╣
║  🎯 SCANNING                                        ║
║  "scan example.com for vulnerabilities"             ║
║  "start bug bounty on target.com"                   ║
║  "pentest target.com scope: *.target.com"           ║
║                                                      ║
║  📚 KNOWLEDGE BASE                                  ║
║  "cve log4j" / "cve CVE-2021-44228"               ║
║  "payloads xss" / "payloads sqli" / "payloads ssrf"║
║  "mitre T1190" / "mitre ssrf"                      ║
║  "bug bounty checklist" / "severity guide"          ║
║  "what is XSS?" / "explain SSRF"                   ║
║                                                      ║
║  📊 SESSION & REPORTS                               ║
║  "show my findings" / "generate report"             ║
║  "sessions" / "resume last session"                 ║
║  "replay session" / "chain analysis"                ║
║  "export findings" / "export hackerone"             ║
║                                                      ║
║  🤖 AI & SETTINGS                                   ║
║  "what provider am I using?"                        ║
║  "edit my prompt" / "customize rajan"               ║
║  "check what tools I have"                          ║
║  "config" / "setup email notifications"             ║
║  "selftest" / "check for updates"                   ║
║                                                      ║
║  💬 WHILE RAJAN WORKS (prefix with !)              ║
║  !status  !stop  !resume  !report so far           ║
║  !focus on web   !skip   !quit                      ║
╚══════════════════════════════════════════════════════╝
"""


class RAJAN:
    def __init__(self):
        self.memory = Memory()
        self.llm = LLMConnector()
        self.logger = Logger()
        self.brain = None
        self.session_id = None
        self.autonomous_thread = None

    def boot(self):
        """Start RAJAN"""
        print(BANNER)

        # First time setup
        if not self.llm.is_configured():
            print(f"{Colors.CYAN}  👋 First time? Let's set up your AI brain!{Colors.RESET}\n")
            success = self.llm.setup_interactive()
            if not success:
                print("  ❌ Setup failed. Please try again.")
                sys.exit(1)
            print()

        print(DONATION_MSG)
        print(f"  {Colors.GREEN}✅ RAJAN is ready! Type 'help' to see what I can do.{Colors.RESET}")
        print(f"  {Colors.DIM}  LLM: {self.llm.config.get('provider_name', 'Unknown')}{Colors.RESET}\n")

    def run_cli(self, args):
        """CLI argument mode"""
        if args.setup:
            self.llm.setup_interactive()
            return

        if args.tools:
            from tools.toolmanager import ToolManager
            ToolManager.print_status()
            return

        if args.sessions:
            self._show_sessions()
            return

        if args.resume:
            self._resume_session(args.resume)
            return

        if args.replay:
            from core.replay import replay_session
            replay_session(self.memory, args.replay)
            return

        if args.notify_setup:
            from core.notifier import Notifier
            Notifier().setup_email()
            return

        if args.prompt:
            self.llm.update_system_prompt()
            return

        if args.selftest:
            from core.selftest import run_selftest
            run_selftest()
            return

        if args.update:
            from core.selftest import check_update
            check_update()
            return

        if args.config:
            from core.config import Config
            Config().interactive_setup()
            return

        if args.export:
            self._export_session(args.export)
            return

        if args.chain:
            self._run_chain_analysis()
            return

        if args.target:
            scope = args.scope or ""
            mode = "semi" if args.semi else "auto"
            if args.quick:
                print(f"  ⚡ Quick mode enabled")
            dry = getattr(args, 'dry_run', False)
            if dry:
                print(f"  🔍 DRY RUN mode — no real HTTP requests will be made")
            self._start_autonomous(args.target, scope, mode, dry_run=dry)
            return

        # Default: interactive
        self.interactive_loop()

    def interactive_loop(self):
        """Main NLP chat loop"""
        print(HELP_TEXT)
        self.session_id = self.memory.create_session("interactive")
        self.brain = Brain(self.memory, self.llm, self.logger, self.session_id)
        self.logger.session_id = self.session_id
        self.logger.memory = self.memory

        print(f"  {Colors.DIM}Type 'exit' to quit{Colors.RESET}\n")

        while True:
            try:
                user_input = input(
                    f"{Colors.BOLD}{Colors.GREEN}[RAJAN]>{Colors.RESET} "
                ).strip()

                if not user_input:
                    continue

                if user_input.lower() in ("exit", "quit", "bye"):
                    print(f"\n{Colors.GREEN}  RAJAN: Stay ethical. See you next time! 👋{Colors.RESET}\n")
                    break

                # Route based on NLP intent
                response = self._route(user_input)
                if response:
                    print(f"\n  {Colors.CYAN}RAJAN:{Colors.RESET} {response}\n")

            except KeyboardInterrupt:
                print(f"\n\n  {Colors.YELLOW}RAJAN: Use 'exit' to quit cleanly 😊{Colors.RESET}\n")
            except EOFError:
                break

    def _route(self, text):
        """NLP intent routing — understands natural language"""
        t = text.lower().strip()

        # Help
        if t in ("help", "?", "commands"):
            print(HELP_TEXT)
            return None

        # Tools status
        if any(kw in t for kw in ["tools", "what tools", "installed"]):
            from tools.toolmanager import ToolManager
            ToolManager.print_status()
            return None

        # Show sessions
        if any(kw in t for kw in ["sessions", "history", "past sessions"]):
            self._show_sessions()
            return None

        # Resume session
        if "resume" in t:
            parts = text.split()
            sid = parts[-1] if len(parts) > 1 and len(parts[-1]) == 8 else None
            if not sid:
                sid = self.memory.get_last_session()
            if sid:
                self._resume_session(sid)
            else:
                return "No previous sessions found."
            return None

        # Show findings
        if any(kw in t for kw in ["findings", "vulnerabilities", "what did you find", "results"]):
            self._show_findings()
            return None

        # Generate report
        if any(kw in t for kw in ["report", "generate report", "make report"]):
            self._generate_report()
            return None

        # Autonomous scan — detect target in message
        scan_keywords = [
            "scan", "hack", "test", "pentest", "bug bounty",
            "find vuln", "find vulnerability", "check for vuln",
            "start working on", "attack", "recon"
        ]
        if any(kw in t for kw in scan_keywords):
            target, scope, mode = self._extract_scan_params(text)
            if target:
                self._start_autonomous(target, scope, mode)
                return None
            else:
                return ("I'd love to help! Just tell me the target. Example:\n"
                        "  'scan example.com for vulnerabilities'\n"
                        "  'start bug bounty on target.com, scope: *.target.com'")

        # Session replay
        if "replay" in t:
            from core.replay import list_sessions_for_replay, replay_session
            sessions = list_sessions_for_replay(self.memory)
            if sessions:
                parts = text.split()
                sid = next((p for p in parts if len(p) == 8), None)
                if not sid:
                    try:
                        num = int(input("  Select session number: ").strip()) - 1
                        sid = sessions[num][0]
                    except Exception:
                        sid = sessions[0][0]
                speed_input = input("  Speed (1=normal, 2=fast, 0=instant): ").strip()
                speed = float(speed_input) if speed_input else 1.0
                replay_session(self.memory, sid, speed)
            return None

        # Chain analysis
        if any(kw in t for kw in ["chain", "chain analysis", "vulnerability chain", "attack chain"]):
            self._run_chain_analysis()
            return None

        # Export
        if "export" in t:
            fmt = "all"
            for f in ["json", "csv", "txt", "hackerone", "all"]:
                if f in t:
                    fmt = f
                    break
            self._export_session(fmt)
            return None

        # Config
        if any(kw in t for kw in ["config", "settings", "configure"]):
            from core.config import Config
            Config().interactive_setup()
            return None

        # System prompt customization
        if any(kw in t for kw in ["my prompt", "system prompt", "my persona",
                                   "edit prompt", "change prompt", "customize rajan"]):
            self.llm.update_system_prompt()
            return None

        # Show current provider/prompt info
        if any(kw in t for kw in ["what provider", "which ai", "what llm", "current provider"]):
            cfg = self.llm.config
            print(f"\n  Provider : {cfg.get('provider_name','Not set')}")
            print(f"  Model    : {cfg.get('model','Not set')}")
            user_p = cfg.get('user_system_prompt','')
            print(f"  Custom prompt: {user_p[:80] if user_p else '(none)'}\n")
            return None
            from core.selftest import run_selftest
            run_selftest()
            return None

        # Check for updates
        if any(kw in t for kw in ["update", "check update", "new version"]):
            from core.selftest import check_update
            check_update()
            return None

        # Email notification setup
        if "email" in t and ("setup" in t or "notify" in t or "notification" in t):
            from core.notifier import Notifier
            Notifier().setup_email()
            return None

        # CVE lookup
        if t.startswith("cve ") or "look up cve" in t:
            query = text.split(" ", 1)[-1].strip()
            from knowledge.cve_db import CVEDatabase
            db = CVEDatabase()
            db.print_search_results(query)
            return None

        # Payload library
        if t.startswith("payload") or t.startswith("payloads"):
            parts = text.split()
            from knowledge.payloads import PayloadLibrary
            lib = PayloadLibrary()
            if len(parts) > 1:
                lib.print_category(parts[1])
            else:
                lib.print_all()
            return None

        # MITRE lookup
        if t.startswith("mitre ") or "mitre attack" in t:
            parts = text.upper().split()
            tid = next((p for p in parts if p.startswith("T1")), None)
            from knowledge.mitre import MITREMapper
            m = MITREMapper()
            if tid:
                m.print_technique(tid)
            else:
                keyword = text.split(" ", 1)[-1]
                results = m.search(keyword)
                for tid, data in list(results.items())[:5]:
                    m.print_technique(tid)
            return None

        # Bug bounty checklist
        if any(kw in t for kw in ["bug bounty", "checklist", "methodology"]):
            from knowledge.methodology import BugBountyGuide
            guide = BugBountyGuide()
            target_hint = ""
            import re
            domains = re.findall(r'\b(?:[a-zA-Z0-9]+\.)+[a-zA-Z]{2,}\b', text)
            if domains:
                target_hint = domains[0]
            guide.print_checklist("web", target_hint)
            return None

        # Severity guide
        if "severity" in t and "guide" in t:
            from knowledge.methodology import BugBountyGuide
            BugBountyGuide().print_severity_guide()
            return None

        # LLM general chat
        self.logger.thinking("Processing your question...", "RAJAN")
        response = self.brain.chat(text, self.session_id)
        return response

    def _extract_scan_params(self, text):
        """Extract target, scope, mode from natural language"""
        import re
        target = None
        scope = ""
        mode = "auto"

        # Find domain/IP
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

        domains = re.findall(domain_pattern, text)
        ips = re.findall(ip_pattern, text)

        if domains:
            # Pick the most likely target (longest domain, or one after "on/for/scan")
            target = domains[0]
        elif ips:
            target = ips[0]

        # Extract scope
        scope_match = re.search(r'scope[:\s]+([^\s,]+)', text, re.IGNORECASE)
        if scope_match:
            scope = scope_match.group(1)

        # Check for semi-auto mode
        if any(kw in text.lower() for kw in ["step by step", "ask me", "semi", "manual"]):
            mode = "semi"

        return target, scope, mode

    def _start_autonomous(self, target, scope="", mode="auto", dry_run=False):
        """Start autonomous hacking session"""
        print(f"\n  {Colors.GREEN}RAJAN: Starting {'[DRY RUN] ' if dry_run else ''}autonomous session on {Colors.BOLD}{target}{Colors.RESET}")
        print(f"  {Colors.DIM}Scope: {scope or 'Full target'} | Mode: {mode}{Colors.RESET}")
        if dry_run:
            print(f"  {Colors.YELLOW}⚠️  Dry run — no real HTTP requests will be made{Colors.RESET}")
        print(f"\n  {Colors.YELLOW}💡 Interrupt commands: !status !stop !focus on [area]{Colors.RESET}\n")

        self.session_id = self.memory.create_session(target, scope)
        self.logger.session_id = self.session_id
        self.logger.memory = self.memory
        self.brain = Brain(self.memory, self.llm, self.logger, self.session_id)
        self.brain.dry_run = dry_run

        # Start autonomous work in background thread
        self.autonomous_thread = threading.Thread(
            target=self.brain.start_autonomous,
            args=(target, scope, mode),
            daemon=True
        )
        self.autonomous_thread.start()

        # Input thread — reads ! commands while brain works
        self._interrupt_input_loop()

    def _interrupt_input_loop(self):
        """Listen for ! interrupt commands while RAJAN works"""
        while self.autonomous_thread and self.autonomous_thread.is_alive():
            try:
                user_input = input("").strip()
                if user_input:
                    if self.brain:
                        self.brain.send_interrupt(user_input)
                    if user_input.lower() in ("!quit", "!exit"):
                        break
            except (KeyboardInterrupt, EOFError):
                if self.brain:
                    self.brain.running = False
                break
            except Exception:
                time.sleep(0.1)

        if self.autonomous_thread:
            self.autonomous_thread.join(timeout=5)

    def _resume_session(self, session_id):
        """Resume a previous session"""
        session = self.memory.get_session(session_id)
        if not session:
            print(f"  ❌ Session {session_id} not found")
            return
        print(f"\n  ✅ Resuming session: {session_id}")
        print(f"  Target: {session['target']}")
        print(f"  Started: {session['started_at']}\n")
        self.session_id = session_id
        self.brain = Brain(self.memory, self.llm, self.logger, session_id)
        self._start_autonomous(session["target"], session.get("scope", ""), "auto")

    def _show_sessions(self):
        sessions = self.memory.get_all_sessions()
        if not sessions:
            print("  No sessions found.")
            return
        print(f"\n  {'ID':<10} {'Target':<30} {'Status':<12} {'Started'}")
        print(f"  {'─'*70}")
        for sid, target, status, started in sessions:
            print(f"  {sid:<10} {target:<30} {status:<12} {started}")
        print()

    def _show_findings(self):
        if not self.session_id:
            sid = self.memory.get_last_session()
        else:
            sid = self.session_id
        if not sid:
            print("  No findings — start a scan first!")
            return
        findings = self.memory.get_findings(sid)
        if not findings:
            print("  No confirmed findings yet.")
            return
        for f in findings:
            self.logger.finding(f["title"], f["severity"], f.get("location", ""))

    def _generate_report(self):
        if not self.session_id:
            self.session_id = self.memory.get_last_session()
        if not self.session_id:
            print("  No session to report on. Run a scan first!")
            return
        from agents.reporter import ReporterAgent
        r = ReporterAgent(self.memory, self.llm, self.logger, self.session_id,
                          self.memory.get_session(self.session_id)["target"])
        filename = r.generate_report()
        print(f"\n  ✅ Report saved: {filename}\n")

    def _export_session(self, fmt="all"):
        sid = self.session_id or self.memory.get_last_session()
        if not sid:
            print("  No session to export. Run a scan first!")
            return
        from core.exporter import Exporter
        e = Exporter(self.memory, sid)
        if fmt == "all":
            files = e.export_all()
            for f, path in files.items():
                print(f"  ✅ {f.upper()}: {path}")
        elif fmt == "json":
            print(f"  ✅ JSON: {e.export_json()}")
        elif fmt == "csv":
            print(f"  ✅ CSV: {e.export_csv()}")
        elif fmt == "txt":
            print(f"  ✅ TXT: {e.export_txt()}")
        elif fmt == "hackerone":
            print(f"  ✅ HackerOne: {e.export_hackerone()}")
        print()

    def _run_chain_analysis(self):
        sid = self.session_id or self.memory.get_last_session()
        if not sid:
            print("  No session to analyze. Run a scan first!")
            return
        from core.chain_analyzer import ChainAnalyzer
        ca = ChainAnalyzer(self.memory, self.llm, self.logger, sid)
        chains = ca.analyze()
        ca.print_chains(chains)


def main():
    parser = argparse.ArgumentParser(
        description="RAJAN — AI Ethical Hacking Agent",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--target", "-t", metavar="TARGET",
                        help="Target domain/IP for autonomous scan")
    parser.add_argument("--scope", "-s", metavar="SCOPE",
                        help="Scope definition (e.g. *.example.com)")
    parser.add_argument("--semi", action="store_true",
                        help="Semi-auto mode (ask before each task)")
    parser.add_argument("--setup", action="store_true",
                        help="Configure RAJAN LLM settings")
    parser.add_argument("--tools", action="store_true",
                        help="Show installed tools status")
    parser.add_argument("--sessions", action="store_true",
                        help="List all past sessions")
    parser.add_argument("--resume", metavar="SESSION_ID",
                        help="Resume a previous session")
    parser.add_argument("--replay", metavar="SESSION_ID",
                        help="Replay a past session log")
    parser.add_argument("--notify-setup", action="store_true",
                        help="Setup email notifications")
    parser.add_argument("--selftest", action="store_true",
                        help="Run self-test to verify RAJAN is working")
    parser.add_argument("--update", action="store_true",
                        help="Check for newer RAJAN version")
    parser.add_argument("--config", action="store_true",
                        help="Open configuration settings")
    parser.add_argument("--export", metavar="FORMAT",
                        help="Export last session (json/csv/txt/hackerone/all)")
    parser.add_argument("--chain", action="store_true",
                        help="Run vulnerability chain analysis on last session")
    parser.add_argument("--quick", action="store_true",
                        help="Quick scan mode — only critical checks")
    parser.add_argument("--dry-run", action="store_true",
                        help="Simulate scan without making real HTTP requests (scope/demo testing)")
    parser.add_argument("--prompt", action="store_true",
                        help="Edit your custom personality/style instructions for RAJAN")

    args = parser.parse_args()

    rajan = RAJAN()
    rajan.boot()
    rajan.run_cli(args)


if __name__ == "__main__":
    main()
