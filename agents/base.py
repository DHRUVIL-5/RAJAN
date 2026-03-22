"""
RAJAN Base Agent
All specialized agents inherit from this
"""


class BaseAgent:
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

    def run_task(self, task_name):
        raise NotImplementedError

    def is_in_scope(self, url_or_host):
        """Hard scope check — returns False and logs if out of scope"""
        if self.scope is None:
            return True  # No scope set — allow all
        return self.scope.check(url_or_host, self.logger, self.name)

    def add_finding(self, title, severity, description, location="", proof="", mitre=""):
        """Save a confirmed finding with confidence scoring"""
        # Enrich with confidence score if scoring engine available
        if self.scoring:
            enriched = self.scoring.enrich_finding(
                title, severity, description, proof, has_poc=bool(proof)
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
        """Add a new task discovered during work"""
        if task_tree:
            task_tree.add_dynamic_task(name, self.name.lower(), priority)
            self.logger.info(f"New task discovered: {name}", self.name)
