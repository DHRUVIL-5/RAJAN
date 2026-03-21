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

    def run_task(self, task_name):
        """Override this in each agent"""
        raise NotImplementedError

    def add_finding(self, title, severity, description, location="", proof="", mitre=""):
        """Save a confirmed finding"""
        self.memory.add_finding(
            self.session_id, title, severity,
            description, location, proof, mitre
        )
        self.logger.finding(title, severity, location)

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
