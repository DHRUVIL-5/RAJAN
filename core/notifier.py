"""
RAJAN Notification System
Termux push notification, terminal bell, email alert
Fires when autonomous session completes
"""

import os
import subprocess
import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


class Notifier:
    CONFIG_PATH = "memory/notify_config.json"

    def __init__(self):
        self.config = self._load()

    def _load(self):
        if os.path.exists(self.CONFIG_PATH):
            try:
                with open(self.CONFIG_PATH) as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save(self):
        os.makedirs("memory", exist_ok=True)
        with open(self.CONFIG_PATH, "w") as f:
            json.dump(self.config, f, indent=2)

    def is_termux(self):
        return "com.termux" in os.environ.get("PREFIX", "")

    def notify(self, title, message, findings_count=0):
        """Send all available notifications"""
        self._terminal_bell()
        self._print_banner(title, message, findings_count)
        if self.is_termux():
            self._termux_notify(title, message)
        if self.config.get("email_enabled"):
            self._email_notify(title, message)

    def _terminal_bell(self):
        """Works on Termux and most terminals"""
        try:
            print("\a", end="", flush=True)
        except Exception:
            pass

    def _print_banner(self, title, message, findings_count):
        from core.logger import Colors
        print(f"\n{Colors.GREEN}{Colors.BOLD}")
        print("╔" + "═" * 55 + "╗")
        print(f"║  🎉 {title:<50}║")
        print(f"║  {message:<53}║")
        if findings_count > 0:
            print(f"║  🔴 {findings_count} vulnerabilities found!{' ' * (35 - len(str(findings_count)))}║")
        print("╚" + "═" * 55 + "╝")
        print(f"{Colors.RESET}")

    def _termux_notify(self, title, message):
        """Android push notification via Termux:API"""
        try:
            subprocess.run(
                ["termux-notification",
                 "--title", f"RAJAN: {title}",
                 "--content", message,
                 "--icon", "security",
                 "--sound"],
                timeout=5, capture_output=True
            )
        except FileNotFoundError:
            pass  # termux-api not installed — silent fail
        except Exception:
            pass

    def _email_notify(self, title, message):
        """Email notification when session done"""
        try:
            cfg = self.config
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"RAJAN Alert: {title}"
            msg["From"] = cfg.get("email_from", "")
            msg["To"] = cfg.get("email_to", "")

            body = MIMEText(
                f"RAJAN Notification\n\n{title}\n{message}\n\n"
                f"-- RAJAN AI Ethical Hacking Agent\n"
                f"github.com/DHRUVIL-5/RAJAN",
                "plain"
            )
            msg.attach(body)

            with smtplib.SMTP_SSL(cfg.get("smtp_host", "smtp.gmail.com"), 465) as s:
                s.login(cfg.get("email_from", ""), cfg.get("email_pass", ""))
                s.sendmail(cfg["email_from"], cfg["email_to"], msg.as_string())
        except Exception:
            pass  # Email fails silently — never crash RAJAN

    def setup_email(self):
        """Interactive email notification setup"""
        print("\n  📧 Email Notification Setup")
        print("  (Gmail recommended — use App Password)\n")
        email_from = input("  Your email: ").strip()
        email_pass = input("  App password: ").strip()
        email_to = input("  Notify email (can be same): ").strip()
        if email_from and email_pass:
            self.config.update({
                "email_enabled": True,
                "email_from": email_from,
                "email_pass": email_pass,
                "email_to": email_to or email_from,
                "smtp_host": "smtp.gmail.com",
            })
            self._save()
            print("  ✅ Email notifications enabled!")
        else:
            print("  ❌ Setup cancelled")

    def disable_email(self):
        self.config["email_enabled"] = False
        self._save()
        print("  ✅ Email notifications disabled")
