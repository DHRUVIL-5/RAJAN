"""
RAJAN Session Replay
Replay any past session's log like a video — useful for review
"""

import time
import os
from core.logger import Colors


def replay_session(memory, session_id, speed=1.0):
    """
    Replay a past session's logs to screen
    speed: 1.0 = real time, 2.0 = 2x faster, 0 = instant
    """
    session = memory.get_session(session_id)
    if not session:
        print(f"  ❌ Session {session_id} not found")
        return

    logs = memory.get_logs(session_id)
    findings = memory.get_findings(session_id)
    counts = memory.count_findings(session_id)

    if not logs:
        print(f"  ℹ️  No logs found for session {session_id}")
        print(f"  This session may have been created before logging was enabled.")
        return

    print(f"\n{Colors.BOLD}{'═' * 55}")
    print(f"  🎬 RAJAN Session Replay")
    print(f"  Session: {session_id} | Target: {session.get('target','?')}")
    print(f"  Started: {session.get('started_at','?')}")
    print(f"  Speed: {speed}x")
    print(f"{'═' * 55}{Colors.RESET}\n")

    input("  Press Enter to start replay...")
    print()

    level_icons = {
        "info":    ("🔵", Colors.CYAN),
        "start":   ("🚀", Colors.GREEN),
        "success": ("✅", Colors.GREEN),
        "warning": ("⚠️ ", Colors.YELLOW),
        "error":   ("❌", Colors.RED),
        "finding": ("🔴", Colors.RED + Colors.BOLD),
        "medium":  ("🟡", Colors.YELLOW),
        "low":     ("🟢", Colors.GREEN),
        "running": ("🔧", Colors.BLUE),
        "thinking":("🧠", Colors.MAGENTA),
        "done":    ("🏁", Colors.GREEN + Colors.BOLD),
    }

    prev_ts = None
    for level, agent, message, timestamp in logs:
        # Simulate timing between log entries
        if speed > 0 and prev_ts and timestamp:
            try:
                from datetime import datetime
                fmt = "%Y-%m-%dT%H:%M:%S.%f" if "." in timestamp else "%Y-%m-%dT%H:%M:%S"
                t1 = datetime.fromisoformat(prev_ts.split(".")[0])
                t2 = datetime.fromisoformat(timestamp.split(".")[0])
                diff = (t2 - t1).total_seconds()
                if 0 < diff < 10:
                    time.sleep(min(diff / speed, 2.0))
            except Exception:
                time.sleep(0.1 / speed)

        icon, color = level_icons.get(level, ("ℹ️ ", Colors.WHITE))
        ts = timestamp.split("T")[-1].split(".")[0] if timestamp else "??:??:??"
        print(f"{Colors.DIM}[{ts}]{Colors.RESET} {icon} {color}{agent} → {message}{Colors.RESET}")
        prev_ts = timestamp

    # Final summary
    print(f"\n{Colors.BOLD}{'─' * 55}{Colors.RESET}")
    print(f"  🏁 Replay complete!")
    print(f"  Findings: {len(findings)} total")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cnt = counts.get(sev, 0)
        if cnt > 0:
            print(f"    {sev}: {cnt}")
    print()


def list_sessions_for_replay(memory):
    """Show sessions available for replay"""
    sessions = memory.get_all_sessions()
    if not sessions:
        print("  No sessions found.")
        return None

    print(f"\n  {'#':<4} {'ID':<10} {'Target':<30} {'Status':<12} {'Date'}")
    print(f"  {'─' * 70}")
    for i, (sid, target, status, started) in enumerate(sessions, 1):
        date = started.split("T")[0] if started else "?"
        status_icon = "✅" if status == "complete" else "🔄" if status == "active" else "⚠️"
        print(f"  {i:<4} {sid:<10} {target:<30} {status_icon} {status:<10} {date}")
    print()
    return sessions
