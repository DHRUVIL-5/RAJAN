"""
RAJAN Config System
Persistent user settings — survives sessions
Stored in memory/config.json
"""

import json
import os


DEFAULT_CONFIG = {
    "version": "1.0.0",
    "llm": {},
    "scan": {
        "default_mode": "auto",       # auto / semi
        "timeout_per_task": 120,       # seconds
        "max_subdomains": 50,
        "quick_mode": False,
        "skip_ssl": False,
        "skip_cloud": False,
    },
    "output": {
        "report_format": "both",       # md / html / both
        "log_level": "info",           # info / debug
        "color": True,
    },
    "notify": {
        "terminal_bell": True,
        "termux_push": True,
        "email": False,
    },
    "ui": {
        "banner": True,
        "donation_msg": True,
        "tips": True,
    },
    "donation": {
        "btc": "",
        "eth": "",
        "usdt": "",
    }
}


class Config:
    PATH = "memory/config.json"

    def __init__(self):
        self._data = self._load()

    def _load(self):
        if os.path.exists(self.PATH):
            try:
                with open(self.PATH) as f:
                    saved = json.load(f)
                # Deep merge with defaults
                return self._merge(DEFAULT_CONFIG, saved)
            except Exception:
                pass
        return dict(DEFAULT_CONFIG)

    def _merge(self, base, override):
        result = dict(base)
        for k, v in override.items():
            if k in result and isinstance(result[k], dict) and isinstance(v, dict):
                result[k] = self._merge(result[k], v)
            else:
                result[k] = v
        return result

    def save(self):
        os.makedirs("memory", exist_ok=True)
        with open(self.PATH, "w") as f:
            json.dump(self._data, f, indent=2)

    def get(self, *keys, default=None):
        d = self._data
        for k in keys:
            if isinstance(d, dict) and k in d:
                d = d[k]
            else:
                return default
        return d

    def set(self, *keys_and_value):
        keys = keys_and_value[:-1]
        value = keys_and_value[-1]
        d = self._data
        for k in keys[:-1]:
            d = d.setdefault(k, {})
        d[keys[-1]] = value
        self.save()

    def interactive_setup(self):
        """Full interactive config setup"""
        from core.logger import Colors
        print(f"\n{Colors.BOLD}  ⚙️  RAJAN Configuration{Colors.RESET}\n")

        print("  [1] Scan Settings")
        print("  [2] Output Settings")
        print("  [3] Notification Settings")
        print("  [4] Donation Wallet (optional)")
        print("  [5] Show current config")
        print("  [0] Done\n")

        choice = input("  Choose: ").strip()

        if choice == "1":
            mode = input("  Default scan mode (auto/semi) [auto]: ").strip() or "auto"
            self.set("scan", "default_mode", mode)
            quick = input("  Enable quick mode by default? (y/n) [n]: ").strip().lower()
            self.set("scan", "quick_mode", quick == "y")
            print("  ✅ Scan settings saved!")

        elif choice == "2":
            fmt = input("  Report format (md/html/both) [both]: ").strip() or "both"
            self.set("output", "report_format", fmt)
            color = input("  Colored output? (y/n) [y]: ").strip().lower()
            self.set("output", "color", color != "n")
            print("  ✅ Output settings saved!")

        elif choice == "3":
            bell = input("  Terminal bell on completion? (y/n) [y]: ").strip().lower()
            self.set("notify", "terminal_bell", bell != "n")
            termux = input("  Termux push notification? (y/n) [y]: ").strip().lower()
            self.set("notify", "termux_push", termux != "n")
            print("  ✅ Notification settings saved!")

        elif choice == "4":
            print("  (Leave blank to skip)")
            btc = input("  BTC address: ").strip()
            eth = input("  ETH address: ").strip()
            usdt = input("  USDT address: ").strip()
            if btc: self.set("donation", "btc", btc)
            if eth: self.set("donation", "eth", eth)
            if usdt: self.set("donation", "usdt", usdt)
            print("  ✅ Wallet addresses saved!")

        elif choice == "5":
            self.print_config()

    def print_config(self):
        from core.logger import Colors
        print(f"\n{Colors.BOLD}  Current RAJAN Config:{Colors.RESET}")
        print(json.dumps(self._data, indent=4))
        print()
