"""
RAJAN Live Logger
Shows colored timestamped logs on screen while working
Also saves everything to log file
"""

import datetime
import os
import sys


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @staticmethod
    def supported():
        """Check if terminal supports colors"""
        return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class Logger:
    ICONS = {
        "info":     ("🔵", Colors.CYAN),
        "start":    ("🚀", Colors.GREEN),
        "success":  ("✅", Colors.GREEN),
        "warning":  ("⚠️ ", Colors.YELLOW),
        "error":    ("❌", Colors.RED),
        "finding":  ("🔴", Colors.RED + Colors.BOLD),
        "medium":   ("🟡", Colors.YELLOW),
        "low":      ("🟢", Colors.GREEN),
        "running":  ("🔧", Colors.BLUE),
        "thinking": ("🧠", Colors.MAGENTA),
        "chat":     ("💬", Colors.WHITE + Colors.BOLD),
        "done":     ("🏁", Colors.GREEN + Colors.BOLD),
    }

    def __init__(self, session_id="", log_dir="logs"):
        self.session_id = session_id
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = os.path.join(log_dir, f"session_{date_str}.log")
        self.use_color = Colors.supported()
        self.memory = None  # set externally if needed

    def _timestamp(self):
        return datetime.datetime.now().strftime("%H:%M:%S")

    def _write_file(self, level, agent, message):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] [{level.upper()}] [{agent}] {message}\n")

    def _print(self, level, message, agent="RAJAN", indent=0):
        icon, color = self.ICONS.get(level, ("ℹ️ ", Colors.WHITE))
        ts = self._timestamp()
        pad = "  " * indent

        if self.use_color:
            ts_str = f"{Colors.DIM}[{ts}]{Colors.RESET}"
            agent_str = f"{Colors.BOLD}{color}{agent}{Colors.RESET}"
            msg_str = f"{color}{message}{Colors.RESET}"
        else:
            ts_str = f"[{ts}]"
            agent_str = agent
            msg_str = message

        print(f"{ts_str} {icon} {pad}{agent_str} → {msg_str}")
        self._write_file(level, agent, message)

        if self.memory and self.session_id:
            try:
                self.memory.add_log(self.session_id, level, message, agent)
            except Exception:
                pass

    def info(self, msg, agent="RAJAN"):
        self._print("info", msg, agent)

    def start(self, msg, agent="RAJAN"):
        self._print("start", msg, agent)

    def success(self, msg, agent="RAJAN"):
        self._print("success", msg, agent)

    def warning(self, msg, agent="RAJAN"):
        self._print("warning", msg, agent)

    def error(self, msg, agent="RAJAN"):
        self._print("error", msg, agent)

    def running(self, cmd, agent="RAJAN"):
        self._print("running", f"Running: {cmd}", agent)

    def thinking(self, msg, agent="RAJAN"):
        self._print("thinking", msg, agent)

    def chat_msg(self, msg):
        self._print("chat", msg, "YOU")

    def finding(self, title, severity, location=""):
        sev = severity.upper()
        if sev == "CRITICAL":
            level, icon = "finding", "🔴"
        elif sev == "HIGH":
            level, icon = "finding", "🟠"
        elif sev == "MEDIUM":
            level, icon = "medium", "🟡"
        else:
            level, icon = "low", "🟢"

        msg = f"FINDING [{sev}] — {title}"
        if location:
            msg += f"\n           └─ Location: {location}"
        self._print(level, msg, "RAJAN")

    def divider(self, char="─", length=55):
        print(Colors.DIM + char * length + Colors.RESET)

    def status_bar(self, target, tasks_done, tasks_total, findings_count, status="RUNNING"):
        status_color = Colors.GREEN if status == "RUNNING" else Colors.YELLOW
        pct = int((tasks_done / tasks_total) * 100) if tasks_total else 0
        bar_len = 20
        filled = int(bar_len * pct / 100)
        bar = "█" * filled + "░" * (bar_len - filled)

        print()
        print(f"{Colors.BOLD}╔{'═'*53}╗{Colors.RESET}")
        print(f"{Colors.BOLD}║{Colors.RESET}  🎯 Target : {Colors.CYAN}{target:<38}{Colors.RESET}{Colors.BOLD}║{Colors.RESET}")
        print(f"{Colors.BOLD}║{Colors.RESET}  📊 Progress: [{Colors.GREEN}{bar}{Colors.RESET}] {pct}% ({tasks_done}/{tasks_total}){' '*5}{Colors.BOLD}║{Colors.RESET}")
        print(f"{Colors.BOLD}║{Colors.RESET}  🔴 Findings: {findings_count:<5} Status: {status_color}{status}{Colors.RESET}{' '*15}{Colors.BOLD}║{Colors.RESET}")
        print(f"{Colors.BOLD}╚{'═'*53}╝{Colors.RESET}")
        print()

    def done(self, msg="Session complete!"):
        self._print("done", msg, "RAJAN")
