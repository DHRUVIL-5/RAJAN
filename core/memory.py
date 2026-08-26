"""
RAJAN Memory System
Persistent SQLite-based memory — survives crashes and restarts.
Stores sessions, findings, chat history, learned intel, tasks, and logs.
"""

import datetime
import json
import os
import sqlite3
import threading
import uuid


class Memory:
    def __init__(self, db_path="memory/rajan.db"):
        self.db_path = db_path
        directory = os.path.dirname(db_path) or "."
        os.makedirs(directory, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(
            db_path, timeout=30, check_same_thread=False
        )
        self.conn.row_factory = None
        self._init_tables()

    def _init_tables(self):
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE,
                    target TEXT,
                    scope TEXT,
                    status TEXT DEFAULT 'active',
                    started_at TEXT,
                    ended_at TEXT,
                    notes TEXT
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    title TEXT,
                    severity TEXT,
                    description TEXT,
                    location TEXT,
                    proof TEXT,
                    mitre_technique TEXT,
                    status TEXT DEFAULT 'confirmed',
                    cvss_score REAL,
                    confidence_score INTEGER,
                    confidence_label TEXT,
                    reliability TEXT,
                    found_at TEXT
                );

                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    task_id TEXT,
                    task TEXT,
                    agent TEXT,
                    depends_on TEXT DEFAULT '[]',
                    status TEXT DEFAULT 'pending',
                    result TEXT,
                    created_at TEXT,
                    done_at TEXT,
                    UNIQUE(session_id, task_id)
                );

                CREATE TABLE IF NOT EXISTS chat_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    role TEXT,
                    content TEXT,
                    timestamp TEXT
                );

                CREATE TABLE IF NOT EXISTS intel (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    type TEXT,
                    key TEXT,
                    value TEXT,
                    found_at TEXT
                );

                CREATE TABLE IF NOT EXISTS task_priorities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    keyword TEXT,
                    priority INTEGER,
                    set_at TEXT
                );

                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    level TEXT,
                    agent TEXT,
                    message TEXT,
                    timestamp TEXT
                );
            """)
            self._migrate_tasks_table(cursor)
            self.conn.commit()

    def _migrate_tasks_table(self, cursor):
        """Add task metadata columns to databases created by older RAJAN versions."""
        columns = {
            row[1] for row in cursor.execute("PRAGMA table_info(tasks)").fetchall()
        }
        if "task_id" not in columns:
            cursor.execute("ALTER TABLE tasks ADD COLUMN task_id TEXT")
        if "depends_on" not in columns:
            cursor.execute("ALTER TABLE tasks ADD COLUMN depends_on TEXT DEFAULT '[]'")
        for column, definition in {
            "cvss_score": "REAL",
            "confidence_score": "INTEGER",
            "confidence_label": "TEXT",
            "reliability": "TEXT",
        }.items():
            if column not in {
                row[1] for row in cursor.execute("PRAGMA table_info(findings)").fetchall()
            }:
                cursor.execute(f"ALTER TABLE findings ADD COLUMN {column} {definition}")
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_tasks_session_task_id "
            "ON tasks(session_id, task_id)"
        )

    # ── Sessions ──────────────────────────────────────────

    def create_session(self, target, scope=""):
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock:
            for _ in range(5):
                session_id = str(uuid.uuid4())[:8]
                try:
                    self.conn.execute(
                        "INSERT INTO sessions "
                        "(session_id, target, scope, started_at) VALUES (?,?,?,?)",
                        (session_id, target, scope, now),
                    )
                    self.conn.commit()
                    return session_id
                except sqlite3.IntegrityError:
                    continue
        raise RuntimeError("Could not allocate a unique session ID")

    def get_session(self, session_id):
        with self._lock:
            cur = self.conn.execute(
                "SELECT * FROM sessions WHERE session_id=?", (session_id,)
            )
            row = cur.fetchone()
            if not row:
                return None
            cols = [d[0] for d in cur.description]
            return dict(zip(cols, row))

    def update_session_status(self, session_id, status):
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        terminal = status in {"complete", "failed", "stopped", "cancelled"}
        with self._lock:
            if terminal:
                self.conn.execute(
                    "UPDATE sessions SET status=?, ended_at=? WHERE session_id=?",
                    (status, now, session_id),
                )
            else:
                self.conn.execute(
                    "UPDATE sessions SET status=? WHERE session_id=?",
                    (status, session_id),
                )
            self.conn.commit()

    def get_all_sessions(self):
        with self._lock:
            cur = self.conn.execute(
                "SELECT session_id, target, status, started_at "
                "FROM sessions ORDER BY id DESC"
            )
            return cur.fetchall()

    def get_last_session(self, include_active=True):
        query = "SELECT session_id FROM sessions"
        params = ()
        if not include_active:
            query += " WHERE status != ?"
            params = ("active",)
        query += " ORDER BY id DESC LIMIT 1"
        with self._lock:
            cur = self.conn.execute(query, params)
            row = cur.fetchone()
            return row[0] if row else None

    # ── Findings ──────────────────────────────────────────

    def add_finding(self, session_id, title, severity, description,
                    location="", proof="", mitre="", scoring=None):
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        scoring = scoring or {}
        with self._lock:
            duplicate = self.conn.execute(
                "SELECT id FROM findings WHERE session_id=? AND title=? AND location=? LIMIT 1",
                (session_id, title, location),
            ).fetchone()
            if duplicate:
                return False
            self.conn.execute(
                """INSERT INTO findings
                   (session_id,title,severity,description,location,proof,
                    mitre_technique,cvss_score,confidence_score,confidence_label,
                    reliability,found_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    session_id, title, severity, description, location, proof, mitre,
                    scoring.get("cvss_score"), scoring.get("confidence_score"),
                    scoring.get("confidence_label"), scoring.get("reliability"), now,
                ),
            )
            self.conn.commit()
            return True

    def get_findings(self, session_id):
        with self._lock:
            cur = self.conn.execute(
                "SELECT * FROM findings WHERE session_id=? ORDER BY id",
                (session_id,),
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def count_findings(self, session_id):
        with self._lock:
            cur = self.conn.execute(
                "SELECT severity, COUNT(*) FROM findings "
                "WHERE session_id=? GROUP BY severity", (session_id,)
            )
            return dict(cur.fetchall())

    # ── Tasks ─────────────────────────────────────────────

    def add_task(self, session_id, task, agent="", task_id=None, depends_on=None):
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        task_id = str(task_id) if task_id is not None else None
        dependencies = json.dumps([str(x) for x in (depends_on or [])])
        with self._lock:
            if task_id is None:
                self.conn.execute(
                    "INSERT INTO tasks "
                    "(session_id,task,agent,depends_on,created_at) VALUES (?,?,?,?,?)",
                    (session_id, task, agent, dependencies, now),
                )
            else:
                self.conn.execute(
                    "INSERT OR IGNORE INTO tasks "
                    "(session_id,task_id,task,agent,depends_on,created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (session_id, task_id, task, agent, dependencies, now),
                )
            self.conn.commit()

    def get_tasks(self, session_id, status=None):
        with self._lock:
            if status:
                cur = self.conn.execute(
                    "SELECT * FROM tasks WHERE session_id=? AND status=? ORDER BY id",
                    (session_id, status),
                )
            else:
                cur = self.conn.execute(
                    "SELECT * FROM tasks WHERE session_id=? ORDER BY id", (session_id,)
                )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def update_task(self, task_id, status, result="", session_id=None):
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock:
            if session_id is None:
                query = "UPDATE tasks SET status=?, result=?, done_at=? WHERE id=?"
                params = (status, result, now, task_id)
            else:
                query = (
                    "UPDATE tasks SET status=?, result=?, done_at=? "
                    "WHERE session_id=? AND task_id=?"
                )
                params = (status, result, now, session_id, str(task_id))
            self.conn.execute(query, params)
            self.conn.commit()

    # ── Chat History ──────────────────────────────────────

    def add_message(self, session_id, role, content):
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock:
            self.conn.execute(
                "INSERT INTO chat_history "
                "(session_id,role,content,timestamp) VALUES (?,?,?,?)",
                (session_id, role, content, now),
            )
            self.conn.commit()

    def get_chat_history(self, session_id, limit=20):
        limit = max(1, int(limit))
        with self._lock:
            cur = self.conn.execute(
                "SELECT role, content FROM chat_history "
                "WHERE session_id=? ORDER BY id DESC LIMIT ?",
                (session_id, limit),
            )
            messages = [{"role": r, "content": c} for r, c in cur.fetchall()]
            return list(reversed(messages))

    # ── Intel ─────────────────────────────────────────────

    def save_intel(self, session_id, intel_type, key, value):
        """Save intel with deduplication under the same session."""
        with self._lock:
            cur = self.conn.execute(
                "SELECT id FROM intel WHERE session_id=? AND type=? AND key=? AND value=?",
                (session_id, intel_type, key, str(value)),
            )
            if cur.fetchone():
                return
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            self.conn.execute(
                "INSERT INTO intel (session_id,type,key,value,found_at) VALUES (?,?,?,?,?)",
                (session_id, intel_type, key, str(value), now),
            )
            self.conn.commit()

    def get_intel(self, session_id, intel_type=None):
        with self._lock:
            if intel_type:
                cur = self.conn.execute(
                    "SELECT type,key,value FROM intel "
                    "WHERE session_id=? AND type=? ORDER BY id",
                    (session_id, intel_type),
                )
            else:
                cur = self.conn.execute(
                    "SELECT type,key,value FROM intel WHERE session_id=? ORDER BY id",
                    (session_id,),
                )
            return cur.fetchall()

    # ── Logs ──────────────────────────────────────────────

    def add_log(self, session_id, level, message, agent="RAJAN"):
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock:
            self.conn.execute(
                "INSERT INTO logs (session_id,level,agent,message,timestamp) VALUES (?,?,?,?,?)",
                (session_id, level, agent, message, now),
            )
            self.conn.commit()

    def get_logs(self, session_id):
        with self._lock:
            cur = self.conn.execute(
                "SELECT level,agent,message,timestamp FROM logs "
                "WHERE session_id=? ORDER BY id", (session_id,)
            )
            return cur.fetchall()

    # ── Task priorities ──────────────────────────────────

    def save_priority(self, session_id, keyword, priority):
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._lock:
            self.conn.execute(
                "INSERT INTO task_priorities "
                "(session_id,keyword,priority,set_at) VALUES (?,?,?,?)",
                (session_id, keyword.lower(), priority, now),
            )
            self.conn.commit()

    def get_priorities(self, session_id):
        with self._lock:
            cur = self.conn.execute(
                "SELECT keyword, priority FROM task_priorities "
                "WHERE session_id=? ORDER BY id", (session_id,)
            )
            return cur.fetchall()

    def close(self):
        with self._lock:
            self.conn.close()
