"""
RAJAN Brain — ReACT Autonomous Engine v2
- Dynamic planner (LLM adjusts tasks based on results)
- Feedback loop: Plan → Execute → Analyze → Re-plan
- Agent-to-Agent communication via shared message bus
- Hard scope enforcement
- Live ASCII progress visualization
- Confidence scoring on all findings
"""

import threading
import queue
import time

from core.logger import Logger
from core.memory import Memory
from core.llm import LLMConnector
from core.task_tree import TaskTree
from core.notifier import Notifier
from core.scope import ScopeEnforcer
from core.scoring import ScoringEngine


class Brain:
    def __init__(self, memory: Memory, llm: LLMConnector,
                 logger: Logger, session_id: str):
        self.memory = memory
        self.llm = llm
        self.logger = logger
        self.session_id = session_id
        self.chat_queue = queue.Queue()
        self.running = False
        self.paused = False
        self.current_task = None
        self.task_tree = None
        self.notifier = Notifier()
        self.scope = None
        self.scoring = ScoringEngine()
        self.agent_bus = {}      # Agent-to-Agent shared message bus
        self.feedback_cycle = 0  # Re-plan cycles completed

    # ── Autonomous Session ────────────────────────────────────

    def start_autonomous(self, target, scope="", mode="auto"):
        self.running = True
        self.paused = False
        self.scope = ScopeEnforcer(target, scope)

        self.logger.start(f"Autonomous session: {target}", "RAJAN")
        self.logger.info(f"Scope: {self.scope.describe()}", "RAJAN")
        self.logger.info(f"Mode: {'Auto 🤖' if mode=='auto' else 'Semi-auto 🧑'}", "RAJAN")
        self.logger.divider()

        # Build initial task tree
        self.task_tree = TaskTree(target, scope, self.memory, self.session_id)
        tasks = self.task_tree.build_default_tree()
        self.logger.info(f"Task tree built — {len(tasks)} tasks planned", "Brain")

        # Create agents with injected scope + bus + scoring
        from agents.recon import ReconAgent
        from agents.scanner import ScannerAgent
        from agents.web import WebAgent
        from agents.osint import OSINTAgent
        from agents.exploit import ExploitAgent
        from agents.cloud import CloudAgent
        from agents.reporter import ReporterAgent

        def make(cls):
            a = cls(self.memory, self.llm, self.logger, self.session_id, target)
            a.scope = self.scope
            a.agent_bus = self.agent_bus
            a.scoring = self.scoring
            return a

        agent_map = {
            "recon":    make(ReconAgent),
            "scanner":  make(ScannerAgent),
            "web":      make(WebAgent),
            "osint":    make(OSINTAgent),
            "exploit":  make(ExploitAgent),
            "cloud":    make(CloudAgent),
            "reporter": make(ReporterAgent),
        }

        # ── Main ReACT + Feedback Loop ──
        while self.running and not self.task_tree.is_complete():
            self._process_chat_queue(agent_map, target)
            if self.paused:
                time.sleep(0.5)
                continue

            task = self.task_tree.get_next_task()
            if not task:
                time.sleep(1)
                continue

            task.status = "running"
            self.current_task = task
            stats = self.task_tree.stats()
            findings_count = len(self.memory.get_findings(self.session_id))

            # Live visualization
            self._render_progress(target, stats, findings_count)

            # Semi-auto approval
            if mode == "semi":
                self.logger.info(f"Next: [{task.agent.upper()}] {task.name}", "Brain")
                ans = input("\n  Run? (y/n/skip/stop): ").strip().lower()
                if ans == "stop":
                    break
                elif ans in ("n", "skip"):
                    self.task_tree.mark_skipped(task)
                    continue

            agent = agent_map.get(task.agent)
            if not agent:
                self.task_tree.mark_skipped(task)
                continue

            self.logger.thinking(f"[{task.agent.upper()}] {task.name}", "Brain")

            try:
                result = agent.run_task(task.name)
                self.task_tree.mark_done(task, result or "")
                # Publish to agent bus (agent-to-agent comms)
                self.agent_bus[task.agent] = result or ""
                self._notify_other_agents(agent_map, task.agent, result)
                self.logger.success(f"Done: {task.name}", task.agent.upper())

                # Feedback loop — re-analyze and add tasks every 5 completions
                if stats.get("done", 0) > 0 and stats.get("done", 0) % 5 == 0:
                    self._feedback_replan(target, agent_map)

            except Exception as e:
                self.task_tree.mark_failed(task, str(e))
                self.logger.error(f"Failed: {task.name} — {e}", task.agent.upper())

            time.sleep(0.3)

        # ── Done ──
        self.running = False
        findings = self.memory.get_findings(self.session_id)
        counts = self.memory.count_findings(self.session_id)
        self.memory.update_session_status(self.session_id, "complete")

        self.logger.divider("═")
        self.logger.done("All tasks complete!")
        if findings:
            for f in findings:
                self.logger.finding(f["title"], f["severity"], f.get("location", ""))
        else:
            self.logger.info("No confirmed vulnerabilities found.", "RAJAN")
        self.logger.info(
            f"Critical:{counts.get('CRITICAL',0)} High:{counts.get('HIGH',0)} "
            f"Medium:{counts.get('MEDIUM',0)} Low:{counts.get('LOW',0)}", "RAJAN"
        )

        # Chain analysis
        try:
            from core.chain_analyzer import ChainAnalyzer
            ca = ChainAnalyzer(self.memory, self.llm, self.logger, self.session_id)
            chains = ca.analyze()
            ca.print_chains(chains)
        except Exception as e:
            self.logger.warning(f"Chain analysis: {e}", "RAJAN")

        self._notify_done(target, findings)

    # ── Feedback Loop: Re-plan based on results ───────────────

    def _feedback_replan(self, target, agent_map):
        """
        After every 5 completed tasks, ask LLM to analyze results
        and inject new tasks if needed. This is the feedback loop.
        Plan → Execute → Analyze → Re-plan
        """
        self.feedback_cycle += 1
        self.logger.thinking(
            f"Feedback cycle #{self.feedback_cycle} — analyzing results for re-planning...",
            "Brain"
        )

        # Summarize what we found so far
        findings = self.memory.get_findings(self.session_id)
        intel = self.memory.get_intel(self.session_id)
        findings_summary = [f"{f['title']} [{f['severity']}]" for f in findings[:8]]
        intel_summary = [f"{itype}/{key}:{value[:30]}" for _, itype, key, value, *_ in intel[:10]]

        analysis = self.llm.quick_ask(
            f"You are RAJAN's planner. Target: {target}\n"
            f"Findings so far: {findings_summary}\n"
            f"Intel gathered: {intel_summary}\n\n"
            f"Based on these results, what are 2-3 specific follow-up tests "
            f"that should be added to the scan queue right now? "
            f"Reply with a JSON list like: "
            f'[{{"task":"test name","agent":"web","priority":2}}]. '
            f"Only add tasks not already covered. If nothing new is needed, reply: []"
        )

        # Parse and inject new tasks
        try:
            import json, re
            match = re.search(r'\[.*?\]', analysis, re.DOTALL)
            if match:
                new_tasks = json.loads(match.group())
                for t in new_tasks[:3]:
                    if isinstance(t, dict) and "task" in t:
                        injected = self.task_tree.add_dynamic_task(
                            t["task"],
                            t.get("agent", "web"),
                            t.get("priority", 5)
                        )
                        self.logger.info(
                            f"Re-plan: added task '{t['task']}'", "Brain"
                        )
        except Exception:
            pass  # LLM returned non-JSON — skip

    # ── Agent-to-Agent Communication ─────────────────────────

    def _notify_other_agents(self, agent_map, sender_agent, result):
        """
        Share key discoveries across agents directly.
        E.g. recon finds subdomains → scanner gets them automatically.
        """
        if not result:
            return

        result_lower = str(result).lower()

        # Recon found subdomains → tell scanner + web
        if sender_agent == "recon" and "subdomain" in result_lower:
            for ag_name in ("scanner", "web"):
                if ag_name in agent_map:
                    agent_map[ag_name].agent_bus["recon_result"] = result
                    self.logger.info(
                        f"Agent bus: recon → {ag_name} (subdomain data shared)", "Brain"
                    )

        # Scanner found open ports → tell exploit
        if sender_agent == "scanner" and ("port" in result_lower or "open" in result_lower):
            if "exploit" in agent_map:
                agent_map["exploit"].agent_bus["scanner_result"] = result
                self.logger.info("Agent bus: scanner → exploit (port data shared)", "Brain")

        # Web found tech stack → tell exploit + scanner
        if sender_agent == "web" and any(
            kw in result_lower for kw in ["nginx", "apache", "wordpress", "php", "django"]
        ):
            if "exploit" in agent_map:
                agent_map["exploit"].agent_bus["web_result"] = result

    # ── Live Visualization ────────────────────────────────────

    def _render_progress(self, target, stats, findings_count=0):
        """ASCII progress visualization — shows task tree state live"""
        from core.logger import Colors
        total = stats.get("total", 1)
        done = stats.get("done", 0)
        failed = stats.get("failed", 0)
        pct = int((done / total) * 100) if total else 0
        bar_len = 30
        filled = int(bar_len * pct / 100)
        bar = f"{'█' * filled}{'░' * (bar_len - filled)}"

        current = self.current_task.name[:35] if self.current_task else "waiting..."
        agent_states = []
        for ag, result in self.agent_bus.items():
            agent_states.append(f"{ag}✓")

        print(
            f"\r{Colors.DIM}[{bar}] {pct}% | "
            f"✅{done} ❌{failed} 🔴{findings_count} | "
            f"▶ {current[:30]}{Colors.RESET}",
            end="", flush=True
        )

    # ── Interrupt Chat ────────────────────────────────────────

    def _process_chat_queue(self, agent_map, target):
        try:
            while True:
                msg = self.chat_queue.get_nowait()
                self._handle_interrupt(msg, agent_map, target)
        except queue.Empty:
            pass

    def _handle_interrupt(self, msg, agent_map, target):
        ml = msg.lower().strip()
        print()  # newline after progress bar
        self.logger.divider()
        self.logger.chat_msg(msg)

        if ml == "!stop":
            self.paused = True
            self.logger.info("⏸️  Paused. Type !resume to continue.", "RAJAN")
        elif ml == "!resume":
            self.paused = False
            self.logger.info("▶️  Resuming...", "RAJAN")
        elif ml == "!status":
            self._print_status(target)
        elif ml == "!report so far":
            self._print_findings_so_far()
        elif ml.startswith("!focus on "):
            self._reprioritize(ml.replace("!focus on ", "").strip())
        elif ml == "!skip" and self.current_task:
            self.task_tree.mark_skipped(self.current_task)
            self.logger.info(f"Skipped: {self.current_task.name}", "RAJAN")
        elif ml in ("!quit", "!exit"):
            self.running = False
            self.logger.info("Saving and quitting...", "RAJAN")
        else:
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
            f"{target} | Tasks:{stats['done']}/{stats['total']} | "
            f"Findings:{len(findings)} "
            f"C:{counts.get('CRITICAL',0)} H:{counts.get('HIGH',0)} "
            f"M:{counts.get('MEDIUM',0)} L:{counts.get('LOW',0)} | "
            f"Feedback cycles:{self.feedback_cycle}", "RAJAN"
        )
        if self.current_task:
            self.logger.info(f"Current: {self.current_task.name}", "RAJAN")
        if self.agent_bus:
            self.logger.info(f"Active agents: {', '.join(self.agent_bus.keys())}", "RAJAN")

    def _print_findings_so_far(self):
        findings = self.memory.get_findings(self.session_id)
        if not findings:
            self.logger.info("No confirmed findings yet.", "RAJAN")
            return
        for f in findings:
            self.logger.finding(f["title"], f["severity"], f.get("location", ""))

    def _reprioritize(self, keyword):
        if not self.task_tree:
            return
        for t in self.task_tree.tasks:
            if keyword in t.name.lower() or keyword in t.agent.lower():
                t.priority = 1
        self.logger.success(f"'{keyword}' tasks moved to top priority!", "Brain")

    def _notify_done(self, target, findings):
        self.notifier.notify(
            f"Scan Complete: {target}",
            f"Found {len(findings)} vulnerabilities. Check your report!",
            len(findings)
        )

    # ── Interactive Chat ──────────────────────────────────────

    def chat(self, user_input, session_id=None):
        sid = session_id or self.session_id
        history = self.memory.get_chat_history(sid, limit=15)
        history.append({"role": "user", "content": user_input})
        response = self.llm.chat(history)
        self.memory.add_message(sid, "user", user_input)
        self.memory.add_message(sid, "assistant", response)
        return response

    def send_interrupt(self, message):
        self.chat_queue.put(message)
