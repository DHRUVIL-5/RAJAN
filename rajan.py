#!/usr/bin/env python3
"""
██████╗  █████╗      ██╗ █████╗ ███╗   ██╗
██╔══██╗██╔══██╗     ██║██╔══██╗████╗  ██║
██████╔╝███████║     ██║███████║██╔██╗ ██║
██╔══██╗██╔══██║██   ██║██╔══██║██║╚██╗██║
██║  ██║██║  ██║╚█████╔╝██║  ██║██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝

RAJAN — AI Ethical Hacking Agent v1.0.0
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
    AI Ethical Hacking Agent v1.0.0
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
║              RAJAN — How to Talk to Me              ║
╠══════════════════════════════════════════════════════╣
║  Just type naturally! Examples:                     ║
║                                                      ║
║  "scan example.com for vulnerabilities"             ║
║  "start bug bounty on target.com"                   ║
║  "what is XSS?"                                     ║
║  "generate a report"                                ║
║  "show my findings"                                 ║
║  "resume last session"                              ║
║  "check what tools I have"                          ║
║                                                      ║
║  During autonomous work, prefix with ! to chat:     ║
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

        if args.target:
            scope = args.scope or ""
            mode = "semi" if args.semi else "auto"
            self._start_autonomous(args.target, scope, mode)
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

    def _start_autonomous(self, target, scope="", mode="auto"):
        """Start autonomous hacking session"""
        print(f"\n  {Colors.GREEN}RAJAN: Starting autonomous session on {Colors.BOLD}{target}{Colors.RESET}")
        print(f"  {Colors.DIM}Scope: {scope or 'Full target'} | Mode: {mode}{Colors.RESET}")
        print(f"\n  {Colors.YELLOW}💡 While I work, type ! commands to interact:{Colors.RESET}")
        print(f"  {Colors.DIM}  !status  !stop  !resume  !report so far  !focus on [area]{Colors.RESET}\n")

        # Create session
        self.session_id = self.memory.create_session(target, scope)
        self.logger.session_id = self.session_id
        self.logger.memory = self.memory
        self.brain = Brain(self.memory, self.llm, self.logger, self.session_id)

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

    args = parser.parse_args()

    rajan = RAJAN()
    rajan.boot()
    rajan.run_cli(args)


if __name__ == "__main__":
    main()
