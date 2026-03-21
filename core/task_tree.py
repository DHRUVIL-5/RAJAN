"""
RAJAN Task Tree
Plans the full attack/test strategy and tracks progress
Inspired by PentestGPT's task planning approach
"""


class Task:
    def __init__(self, task_id, name, agent, priority=5, depends_on=None):
        self.task_id = task_id
        self.name = name
        self.agent = agent
        self.priority = priority       # 1=highest, 10=lowest
        self.depends_on = depends_on or []
        self.status = "pending"        # pending, running, done, skipped, failed
        self.result = ""
        self.subtasks = []

    def add_subtask(self, task):
        self.subtasks.append(task)

    def is_ready(self, done_ids):
        """Check if all dependencies are done"""
        return all(dep in done_ids for dep in self.depends_on)


class TaskTree:
    def __init__(self, target, scope="", memory=None, session_id=""):
        self.target = target
        self.scope = scope
        self.memory = memory
        self.session_id = session_id
        self.tasks = []
        self.done_ids = set()
        self._id_counter = 0

    def _next_id(self):
        self._id_counter += 1
        return self._id_counter

    def build_default_tree(self):
        """Build full pentest task tree based on target"""
        # Phase 1 — Recon (no dependencies)
        t1 = Task(self._next_id(), "DNS enumeration & WHOIS", "recon", priority=1)
        t2 = Task(self._next_id(), "Subdomain discovery", "recon", priority=1)
        t3 = Task(self._next_id(), "OSINT — Google dorking", "osint", priority=2)
        t4 = Task(self._next_id(), "OSINT — GitHub/code leaks", "osint", priority=2)

        # Phase 2 — Scanning (depends on recon)
        t5 = Task(self._next_id(), "Port scan", "scanner",
                  priority=2, depends_on=[t1.task_id, t2.task_id])
        t6 = Task(self._next_id(), "Service & version detection", "scanner",
                  priority=2, depends_on=[t5.task_id])
        t7 = Task(self._next_id(), "Web tech fingerprinting", "web",
                  priority=3, depends_on=[t5.task_id])

        # Phase 3 — Web testing (depends on scanning)
        t8 = Task(self._next_id(), "Directory & endpoint discovery", "web",
                  priority=3, depends_on=[t7.task_id])
        t9 = Task(self._next_id(), "XSS testing", "web",
                  priority=3, depends_on=[t8.task_id])
        t10 = Task(self._next_id(), "SQL injection testing", "web",
                   priority=3, depends_on=[t8.task_id])
        t11 = Task(self._next_id(), "IDOR & access control testing", "web",
                   priority=4, depends_on=[t8.task_id])
        t12 = Task(self._next_id(), "SSRF testing", "web",
                   priority=4, depends_on=[t8.task_id])
        t13 = Task(self._next_id(), "Authentication & session testing", "web",
                   priority=4, depends_on=[t8.task_id])
        t14 = Task(self._next_id(), "JS file analysis for secrets", "web",
                   priority=3, depends_on=[t7.task_id])

        # Phase 4 — CVE & exploit research
        t15 = Task(self._next_id(), "CVE lookup for detected versions", "exploit",
                   priority=4, depends_on=[t6.task_id])
        t16 = Task(self._next_id(), "Known vulnerability check", "exploit",
                   priority=4, depends_on=[t15.task_id])

        # Phase 5 — Cloud & misc
        t17 = Task(self._next_id(), "Cloud/S3 bucket check", "cloud",
                   priority=5, depends_on=[t3.task_id])
        t18 = Task(self._next_id(), "SSL/TLS configuration check", "web",
                   priority=5, depends_on=[t5.task_id])

        # Phase 6 — Reporting (depends on everything)
        all_ids = [t.task_id for t in [t9,t10,t11,t12,t13,t14,t15,t16,t17,t18]]
        t19 = Task(self._next_id(), "Generate full report", "reporter",
                   priority=10, depends_on=all_ids)

        self.tasks = [t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,
                      t11,t12,t13,t14,t15,t16,t17,t18,t19]

        # Save to memory
        if self.memory and self.session_id:
            for t in self.tasks:
                self.memory.add_task(self.session_id, t.name, t.agent)

        return self.tasks

    def get_next_task(self):
        """Get highest priority ready task"""
        ready = [
            t for t in self.tasks
            if t.status == "pending" and t.is_ready(self.done_ids)
        ]
        if not ready:
            return None
        return min(ready, key=lambda t: t.priority)

    def mark_done(self, task, result=""):
        task.status = "done"
        task.result = result
        self.done_ids.add(task.task_id)

    def mark_failed(self, task, reason=""):
        task.status = "failed"
        task.result = reason
        self.done_ids.add(task.task_id)  # still add so dependents can run

    def mark_skipped(self, task):
        task.status = "skipped"
        self.done_ids.add(task.task_id)

    def stats(self):
        total = len(self.tasks)
        done = sum(1 for t in self.tasks if t.status == "done")
        failed = sum(1 for t in self.tasks if t.status == "failed")
        skipped = sum(1 for t in self.tasks if t.status == "skipped")
        pending = total - done - failed - skipped
        return {
            "total": total,
            "done": done,
            "failed": failed,
            "skipped": skipped,
            "pending": pending,
        }

    def is_complete(self):
        return all(t.status in ("done", "failed", "skipped") for t in self.tasks)

    def add_dynamic_task(self, name, agent, priority=5, depends_on=None):
        """Add task discovered during scanning (e.g. found new subdomain)"""
        t = Task(self._next_id(), name, agent, priority, depends_on)
        self.tasks.append(t)
        if self.memory and self.session_id:
            self.memory.add_task(self.session_id, name, agent)
        return t
