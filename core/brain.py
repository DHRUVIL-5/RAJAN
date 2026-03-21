"""
RAJAN Brain — ReACT Autonomous Engine
Reason → Act → Observe → Learn → Repeat
Inspired by CAI + PentestGPT + Agent Zero
Runs for hours autonomously with interrupt chat support
"""

import threading
import queue
import time
import datetime

from core.logger import Logger
from core.memory import Memory
from core.llm import LLMConnector
from core.task_tree import TaskTree


class Brain:
    def __init__(self, memory: Memory, llm: LLMConnector,
                 logger: Logger, session_id: str):
        self.memory = memory
        self.llm = llm
        self.logger = logger
        self.session_id = session_id

        # Interrupt chat queue — user can talk while RAJAN works
        self.chat_queue = queue.Queue()
        self.running = False
        self.paused = False
        self.current_task = None
        self.task_tree = None

    # ── Autonomous Session ────────────────────────────────

    def start_autonomous(self, target, scope="", mode="auto"):
        """
        Main autonomous loop — runs until all tasks done or user stops
        mode: 'auto' = runs everything, 'semi' = asks before each task
        """
        self.running = True
        self.paused = False

        session = self.memory.get_session(self.session_id)
        self.logger.start(f"Autonomous session started on: {target}", "RAJAN")
        self.logger.info(f"Scope: {scope or 'Full target'}", "RAJAN")
        self.logger.info(f"Mode: {'Auto 🤖' if mode == 'auto' else 'Semi-auto 🧑'}", "RAJAN")
        self.logger.divider()

        # Build task tree
        self.task_tree = TaskTree(target, scope, self.memory, self.session_id)
        tasks = self.task_tree.build_default_tree()
        total = len(tasks)
        self.logger.info(f"Task tree built — {total} tasks planned", "Brain")

        # Import agents
        from agents.recon import ReconAgent
        from agents.scanner import ScannerAgent
        from agents.web import WebAgent
        from agents.osint import OSINTAgent
        from agents.exploit import ExploitAgent
        from agents.cloud import CloudAgent
        from agents.reporter import ReporterAgent

        agent_map = {
            "recon":   ReconAgent(self.memory, self.llm, self.logger, self.session_id, target),
            "scanner": ScannerAgent(self.memory, self.llm, self.logger, self.session_id, target),
            "web":     WebAgent(self.memory, self.llm, self.logger, self.session_id, target),
            "osint":   OSINTAgent(self.memory, self.llm, self.logger, self.session_id, target),
            "exploit": ExploitAgent(self.memory, self.llm, self.logger, self.session_id, target),
            "cloud":   CloudAgent(self.memory, self.llm, self.logger, self.session_id, target),
            "reporter":ReporterAgent(self.memory, self.llm, self.logger, self.session_id, target),
        }

        # ── Main ReACT Loop ──
        while self.running and not self.task_tree.is_complete():

            # Check for interrupt messages from user
            self._process_chat_queue(agent_map, target)

            if self.paused:
                time.sleep(0.5)
                continue

            # REASON — what's next?
            task = self.task_tree.get_next_task()
            if not task:
                # All available tasks blocked by dependencies — wait
                time.sleep(1)
                continue

            # Mark running
            task.status = "running"
            self.current_task = task
            stats = self.task_tree.stats()

            self.logger.status_bar(
                target,
                stats["done"],
                stats["total"],
                len(self.memory.get_findings(self.session_id)),
            )

            # Semi-auto — ask permission
            if mode == "semi":
                self.logger.info(
                    f"Next task: [{task.agent.upper()}] {task.name}", "Brain"
                )
                answer = input(
                    f"\n  Run this task? (y/n/skip/stop): "
                ).strip().lower()
                if answer == "stop":
                    break
                elif answer in ("n", "skip"):
                    self.task_tree.mark_skipped(task)
                    continue

            # ACT — run the agent
            agent = agent_map.get(task.agent)
            if not agent:
                self.logger.warning(f"No agent for: {task.agent}", "Brain")
                self.task_tree.mark_skipped(task)
                continue

            self.logger.thinking(f"Running: [{task.agent.upper()}] {task.name}", "Brain")

            try:
                result = agent.run_task(task.name)
                self.task_tree.mark_done(task, result)
                self.logger.success(f"Task done: {task.name}", task.agent.upper())
            except Exception as e:
                self.task_tree.mark_failed(task, str(e))
                self.logger.error(f"Task failed: {task.name} — {e}", task.agent.upper())

            # Small breath between tasks
            time.sleep(0.5)

        # ── Session Complete ──
        self.running = False
        findings = self.memory.get_findings(self.session_id)
        counts = self.memory.count_findings(self.session_id)
        self.memory.update_session_status(self.session_id, "complete")

        self.logger.divider("═")
        self.logger.done("All tasks complete! Here's what RAJAN found:")
        self.logger.divider()

        if findings:
            for f in findings:
                self.logger.finding(f["title"], f["severity"], f["location"])
        else:
            self.logger.info("No confirmed vulnerabilities found this session.", "RAJAN")

        self.logger.info(
            f"Summary → Critical: {counts.get('CRITICAL',0)} | "
            f"High: {counts.get('HIGH',0)} | "
            f"Medium: {counts.get('MEDIUM',0)} | "
            f"Low: {counts.get('LOW',0)}", "RAJAN"
        )
        self.logger.info(f"Full log saved: {self.logger.log_file}", "RAJAN")

        # Notify user
        self._notify_done(target, findings)

    def _process_chat_queue(self, agent_map, target):
        """Handle interrupt messages from user while working"""
        try:
            while True:
                msg = self.chat_queue.get_nowait()
                self._handle_interrupt(msg, agent_map, target)
        except queue.Empty:
            pass

    def _handle_interrupt(self, msg, agent_map, target):
        """Process a chat message sent while RAJAN is working"""
        msg_lower = msg.lower().strip()
        self.logger.divider()
        self.logger.chat_msg(msg)

        # Built-in interrupt commands
        if msg_lower == "!stop":
            self.paused = True
            self.logger.info("⏸️  Paused. Type !resume to continue.", "RAJAN")
        elif msg_lower == "!resume":
            self.paused = False
            self.logger.info("▶️  Resuming autonomous work...", "RAJAN")
        elif msg_lower == "!status":
            self._print_status(target)
        elif msg_lower == "!report so far":
            self._print_findings_so_far()
        elif msg_lower.startswith("!focus on "):
            focus = msg_lower.replace("!focus on ", "").strip()
            self.logger.info(f"Shifting focus to: {focus}", "RAJAN")
            self._reprioritize(focus)
        elif msg_lower.startswith("!skip"):
            if self.current_task:
                self.task_tree.mark_skipped(self.current_task)
                self.logger.info(f"Skipping: {self.current_task.name}", "RAJAN")
        elif msg_lower == "!quit":
            self.running = False
            self.logger.info("Saving and quitting...", "RAJAN")
        else:
            # General question — ask LLM while pausing briefly
            was_paused = self.paused
            self.paused = True
            history = self.memory.get_chat_history(self.session_id, limit=10)
            history.append({"role": "user", "content": msg})
            response = self.llm.chat(history)
            self.memory.add_message(self.session_id, "user", msg)
            self.memory.add_message(self.session_id, "assistant", response)
            self.logger.info(response, "RAJAN")
            self.paused = was_paused

        self.logger.divider()

    def _print_status(self, target):
        if not self.task_tree:
            return
        stats = self.task_tree.stats()
        findings = self.memory.get_findings(self.session_id)
        counts = self.memory.count_findings(self.session_id)
        self.logger.info(
            f"Target: {target} | Tasks: {stats['done']}/{stats['total']} done | "
            f"Findings: {len(findings)} "
            f"(C:{counts.get('CRITICAL',0)} H:{counts.get('HIGH',0)} "
            f"M:{counts.get('MEDIUM',0)} L:{counts.get('LOW',0)})", "RAJAN"
        )
        if self.current_task:
            self.logger.info(f"Currently working on: {self.current_task.name}", "RAJAN")

    def _print_findings_so_far(self):
        findings = self.memory.get_findings(self.session_id)
        if not findings:
            self.logger.info("No confirmed findings yet.", "RAJAN")
            return
        for f in findings:
            self.logger.finding(f["title"], f["severity"], f["location"])

    def _reprioritize(self, focus_keyword):
        """Boost priority of tasks matching keyword"""
        if not self.task_tree:
            return
        for task in self.task_tree.tasks:
            if focus_keyword in task.name.lower() or focus_keyword in task.agent.lower():
                task.priority = 1  # highest priority
        self.logger.success(f"Tasks matching '{focus_keyword}' moved to top!", "Brain")

    def _notify_done(self, target, findings):
        """Terminal bell notification when done"""
        try:
            print("\a")  # terminal bell — works on Termux
        except Exception:
            pass
        print(f"\n{'🎉'*10}")
        print(f"  RAJAN finished working on: {target}")
        print(f"  Found {len(findings)} vulnerabilities!")
        print(f"{'🎉'*10}\n")

    # ── Interactive Chat (no autonomous session) ──────────

    def chat(self, user_input, session_id=None):
        """Simple interactive chat mode"""
        sid = session_id or self.session_id
        history = self.memory.get_chat_history(sid, limit=15)
        history.append({"role": "user", "content": user_input})
        response = self.llm.chat(history)
        self.memory.add_message(sid, "user", user_input)
        self.memory.add_message(sid, "assistant", response)
        return response

    def send_interrupt(self, message):
        """Called from input thread to interrupt autonomous session"""
        self.chat_queue.put(message)
