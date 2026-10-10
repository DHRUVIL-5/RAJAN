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
        self.db_id = None

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
        self.max_dynamic_tasks = 50

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
                t.db_id = self.memory.add_task(self.session_id, t.name, t.agent)

        return self.tasks

    def restore_previous_progress(self):
        """
        Resume support — after rebuilding the default tree for an existing
        session, restore completion state recorded by a previous run so RAJAN
        never repeats work it already did.
        Returns the number of tasks restored as done/skipped.
        """
        if not (self.memory and self.session_id):
            return 0
        try:
            rows = self.memory.get_tasks(self.session_id)
        except Exception:
            return 0
        # Keep the OLDEST row per (task, agent): on resume the tree build
        # inserts fresh 'pending' rows after the original ones.
        seen = {}
        for r in rows:
            key = (r.get("task", ""), r.get("agent", "") or "")
            if key not in seen:
                seen[key] = r
        restored = 0
        for t in self.tasks:
            r = seen.get((t.name, t.agent))
            if not r:
                continue
            st = (r.get("status") or "pending").lower()
            if st == "done" and t.status == "pending":
                t.status = "done"
                t.result = r.get("result") or ""
                self.done_ids.add(t.task_id)
                restored += 1
            elif st == "skipped" and t.status == "pending":
                t.status = "skipped"
                t.result = r.get("result") or ""
                self.done_ids.add(t.task_id)
                restored += 1
        return restored

    def get_next_task(self):
        """Get highest priority ready task"""
        # Failed or skipped prerequisites block descendants instead of
        # allowing them to run with invalid or missing inputs.
        by_id = {t.task_id: t for t in self.tasks}
        for task in self.tasks:
            if task.status == "pending" and any(
                by_id.get(dep) and by_id[dep].status in ("failed", "skipped")
                for dep in task.depends_on
            ):
                task.status = "skipped"
                task.result = "Blocked by failed or skipped prerequisite"

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
        if self.memory and task.db_id is not None:
            self.memory.update_task(task.db_id, "done", result)

    def mark_failed(self, task, reason=""):
        task.status = "failed"
        task.result = reason
        if self.memory and task.db_id is not None:
            self.memory.update_task(task.db_id, "failed", reason)
        # Failed tasks are deliberately not added to done_ids.

    def mark_skipped(self, task):
        task.status = "skipped"
        self.done_ids.add(task.task_id)
        if self.memory and task.db_id is not None:
            self.memory.update_task(task.db_id, "skipped", task.result)

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
        """Add a validated, non-duplicate task discovered during scanning."""
        allowed_agents = {"recon", "scanner", "web", "osint", "exploit", "cloud", "reporter"}
        if len(self.tasks) >= 19 + self.max_dynamic_tasks:
            return None
        name = str(name or "").strip()
        agent = str(agent or "").strip().lower()
        if not name or agent not in allowed_agents:
            return None
        normalized = " ".join(name.lower().split())
        if any(" ".join(t.name.lower().split()) == normalized for t in self.tasks):
            return None
        valid_ids = {t.task_id for t in self.tasks}
        depends_on = [d for d in (depends_on or []) if d in valid_ids]
        t = Task(self._next_id(), name, agent, priority, depends_on)
        self.tasks.append(t)
        if self.memory and self.session_id:
            t.db_id = self.memory.add_task(self.session_id, name, agent)
        return t
