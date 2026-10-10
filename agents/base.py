"""
RAJAN Base Agent
All specialized agents inherit from this
Includes: scope enforcement, scoring, rate limiting, agent bus
"""

import time
import threading


class BaseAgent:
    _rate_lock = threading.Lock()
    _target_last_request = {}
    def __init__(self, memory, llm, logger, session_id, target):
        self.memory = memory
        self.llm = llm
        self.logger = logger
        self.session_id = session_id
        self.target = target
        self.name = "BaseAgent"
        # Injected by Brain at runtime
        self.scope = None
        self.agent_bus = {}
        self.scoring = None
        # Per-agent rate limiting — prevents ban on HackerOne/Intigriti
        self.request_delay = 1.0   # seconds between HTTP requests
        self.last_request_time = 0.0
        # Dry run mode — simulate without making real HTTP requests
        self.dry_run = False

    def _rate_limit(self):
        """Enforce a shared minimum delay for all agents targeting one host."""
        with self._rate_lock:
            now = time.time()
            last = self._target_last_request.get(self.target, 0.0)
            elapsed = now - last
            if elapsed < self.request_delay:
                time.sleep(self.request_delay - elapsed)
            now = time.time()
            self._target_last_request[self.target] = now
            self.last_request_time = now

    def set_rate_limit(self, delay_seconds):
        """Allow brain/user to adjust rate limit per session"""
        self.request_delay = delay_seconds

    def run_task(self, task_name):
        raise NotImplementedError

    def is_in_scope(self, url_or_host):
        """Hard scope check — returns False and logs if out of scope"""
        if self.scope is None:
            self.logger.warning(
                f"No scope configured — blocked: {url_or_host}", self.name
            )
            return False
        return self.scope.check(url_or_host, self.logger, self.name)

    def add_finding(self, title, severity, description, location="", proof="", mitre=""):
        """Save a confirmed finding with confidence scoring"""
        # Enrich with confidence score if scoring engine available
        if self.scoring:
            enriched = self.scoring.enrich_finding(
                title, severity, description, proof, has_poc=False
            )
            final_severity = enriched["severity"]
            final_proof = enriched["proof"]
        else:
            final_severity = severity
            final_proof = proof

        self.memory.add_finding(
            self.session_id, title, final_severity,
            description, location, final_proof, mitre
        )
        self.logger.finding(title, final_severity, location)

    def save_intel(self, intel_type, key, value):
        self.memory.save_intel(self.session_id, intel_type, key, value)

    def ask_llm(self, question):
        """Ask LLM a specific security question"""
        return self.llm.quick_ask(question)

    def add_dynamic_task(self, task_tree, name, priority=5):
        """Add a new task discovered during work. Returns the Task or None."""
        if not task_tree:
            return None
        # Map agent class name (e.g. "WebAgent") to its task-tree key ("web")
        agent_key = self.name[:-5].lower() if self.name.endswith("Agent") else self.name.lower()
        added = task_tree.add_dynamic_task(name, agent_key, priority)
        if added:
            self.logger.info(f"New task discovered: {name}", self.name)
        else:
            self.logger.info(
                f"Discarded duplicate/invalid dynamic task: {name}", self.name)
        return added
