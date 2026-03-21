"""
RAJAN Memory System
Persistent SQLite-based memory — survives crashes, phone restarts
Stores: sessions, findings, chat history, learned intel
"""

import sqlite3
import json
import os
import datetime


class Memory:
    def __init__(self, db_path="memory/rajan.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_tables()

    def _init_tables(self):
        cursor = self.conn.cursor()
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
                found_at TEXT
            );

            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                task TEXT,
                agent TEXT,
                status TEXT DEFAULT 'pending',
                result TEXT,
                created_at TEXT,
                done_at TEXT
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

            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                level TEXT,
                agent TEXT,
                message TEXT,
                timestamp TEXT
            );
        """)
        self.conn.commit()

    # ── Sessions ──────────────────────────────────────────

    def create_session(self, target, scope=""):
        import uuid
        session_id = str(uuid.uuid4())[:8]
        now = datetime.datetime.now().isoformat()
        self.conn.execute(
            "INSERT INTO sessions (session_id, target, scope, started_at) VALUES (?,?,?,?)",
            (session_id, target, scope, now)
        )
        self.conn.commit()
        return session_id

    def get_session(self, session_id):
        cur = self.conn.execute(
            "SELECT * FROM sessions WHERE session_id=?", (session_id,)
        )
        row = cur.fetchone()
        if not row:
            return None
        cols = [d[0] for d in cur.description]
        return dict(zip(cols, row))

    def update_session_status(self, session_id, status):
        now = datetime.datetime.now().isoformat()
        self.conn.execute(
            "UPDATE sessions SET status=?, ended_at=? WHERE session_id=?",
            (status, now, session_id)
        )
        self.conn.commit()

    def get_all_sessions(self):
        cur = self.conn.execute(
            "SELECT session_id, target, status, started_at FROM sessions ORDER BY id DESC"
        )
        return cur.fetchall()

    def get_last_session(self):
        cur = self.conn.execute(
            "SELECT session_id FROM sessions ORDER BY id DESC LIMIT 1"
        )
        row = cur.fetchone()
        return row[0] if row else None

    # ── Findings ──────────────────────────────────────────

    def add_finding(self, session_id, title, severity, description,
                    location="", proof="", mitre=""):
        now = datetime.datetime.now().isoformat()
        self.conn.execute(
            """INSERT INTO findings
               (session_id,title,severity,description,location,proof,mitre_technique,found_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (session_id, title, severity, description, location, proof, mitre, now)
        )
        self.conn.commit()

    def get_findings(self, session_id):
        cur = self.conn.execute(
            "SELECT * FROM findings WHERE session_id=? ORDER BY id",
            (session_id,)
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def count_findings(self, session_id):
        cur = self.conn.execute(
            "SELECT severity, COUNT(*) FROM findings WHERE session_id=? GROUP BY severity",
            (session_id,)
        )
        return dict(cur.fetchall())

    # ── Tasks ─────────────────────────────────────────────

    def add_task(self, session_id, task, agent=""):
        now = datetime.datetime.now().isoformat()
        self.conn.execute(
            "INSERT INTO tasks (session_id,task,agent,created_at) VALUES (?,?,?,?)",
            (session_id, task, agent, now)
        )
        self.conn.commit()

    def get_tasks(self, session_id, status=None):
        if status:
            cur = self.conn.execute(
                "SELECT * FROM tasks WHERE session_id=? AND status=?",
                (session_id, status)
            )
        else:
            cur = self.conn.execute(
                "SELECT * FROM tasks WHERE session_id=?", (session_id,)
            )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def update_task(self, task_id, status, result=""):
        now = datetime.datetime.now().isoformat()
        self.conn.execute(
            "UPDATE tasks SET status=?, result=?, done_at=? WHERE id=?",
            (status, result, now, task_id)
        )
        self.conn.commit()

    # ── Chat History ──────────────────────────────────────

    def add_message(self, session_id, role, content):
        now = datetime.datetime.now().isoformat()
        self.conn.execute(
            "INSERT INTO chat_history (session_id,role,content,timestamp) VALUES (?,?,?,?)",
            (session_id, role, content, now)
        )
        self.conn.commit()

    def get_chat_history(self, session_id, limit=20):
        cur = self.conn.execute(
            """SELECT role, content FROM chat_history
               WHERE session_id=? ORDER BY id DESC LIMIT ?""",
            (session_id, limit)
        )
        messages = [{"role": r, "content": c} for r, c in cur.fetchall()]
        return list(reversed(messages))

    # ── Intel ─────────────────────────────────────────────

    def save_intel(self, session_id, intel_type, key, value):
        now = datetime.datetime.now().isoformat()
        self.conn.execute(
            "INSERT INTO intel (session_id,type,key,value,found_at) VALUES (?,?,?,?,?)",
            (session_id, intel_type, key, str(value), now)
        )
        self.conn.commit()

    def get_intel(self, session_id, intel_type=None):
        if intel_type:
            cur = self.conn.execute(
                "SELECT type,key,value FROM intel WHERE session_id=? AND type=?",
                (session_id, intel_type)
            )
        else:
            cur = self.conn.execute(
                "SELECT type,key,value FROM intel WHERE session_id=?", (session_id,)
            )
        return cur.fetchall()

    # ── Logs ──────────────────────────────────────────────

    def add_log(self, session_id, level, message, agent="RAJAN"):
        now = datetime.datetime.now().isoformat()
        self.conn.execute(
            "INSERT INTO logs (session_id,level,agent,message,timestamp) VALUES (?,?,?,?,?)",
            (session_id, level, agent, message, now)
        )
        self.conn.commit()

    def get_logs(self, session_id):
        cur = self.conn.execute(
            "SELECT level,agent,message,timestamp FROM logs WHERE session_id=? ORDER BY id",
            (session_id,)
        )
        return cur.fetchall()

    def close(self):
        self.conn.close()
