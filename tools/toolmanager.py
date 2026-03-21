"""
RAJAN Tool Manager
Detects what security tools are installed
Never blocks — works with whatever is available
Termux-aware: uses termux-compatible alternatives
"""

import subprocess
import shutil
import platform
import os


class ToolManager:
    # Tool definitions: name → (command, install_hint, termux_install)
    TOOLS = {
        "nmap":      ("nmap",       "apt install nmap",              "pkg install nmap"),
        "gobuster":  ("gobuster",   "apt install gobuster",          "pkg install gobuster"),
        "ffuf":      ("ffuf",       "go install github.com/ffuf/ffuf@latest", "pkg install ffuf"),
        "sqlmap":    ("sqlmap",     "pip install sqlmap",            "pip install sqlmap"),
        "nuclei":    ("nuclei",     "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "pkg install nuclei"),
        "hydra":     ("hydra",      "apt install hydra",             "pkg install hydra"),
        "nikto":     ("nikto",      "apt install nikto",             "pkg install nikto"),
        "curl":      ("curl",       "apt install curl",              "pkg install curl"),
        "wget":      ("wget",       "apt install wget",              "pkg install wget"),
        "git":       ("git",        "apt install git",               "pkg install git"),
        "python3":   ("python3",    "apt install python3",           "pkg install python"),
        "whois":     ("whois",      "apt install whois",             "pkg install whois"),
        "dig":       ("dig",        "apt install dnsutils",          "pkg install dnsutils"),
        "subfinder": ("subfinder",  "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "pkg install subfinder"),
        "httpx":     ("httpx",      "go install github.com/projectdiscovery/httpx/cmd/httpx@latest", "pkg install httpx"),
        "amass":     ("amass",      "apt install amass",             "N/A on Termux"),
        "masscan":   ("masscan",    "apt install masscan",           "N/A on Termux"),
        "metasploit":("msfconsole", "apt install metasploit-framework", "N/A on Termux"),
    }

    _cache = {}

    @classmethod
    def check(cls, tool_name):
        """Check if a tool is installed — cached"""
        if tool_name in cls._cache:
            return cls._cache[tool_name]
        cmd = cls.TOOLS.get(tool_name, (tool_name,))[0]
        found = shutil.which(cmd) is not None
        cls._cache[tool_name] = found
        return found

    @classmethod
    def is_termux(cls):
        return "com.termux" in os.environ.get("PREFIX", "")

    @classmethod
    def run(cls, tool_name, args, timeout=60, capture=True):
        """
        Run a tool if installed.
        Returns (success, output) tuple.
        """
        if not cls.check(tool_name):
            hint = cls.install_hint(tool_name)
            return False, f"Tool '{tool_name}' not installed. Install: {hint}"

        cmd = [cls.TOOLS[tool_name][0]] + args
        try:
            result = subprocess.run(
                cmd,
                capture_output=capture,
                text=True,
                timeout=timeout
            )
            output = result.stdout + result.stderr
            return True, output.strip()
        except subprocess.TimeoutExpired:
            return False, f"Tool '{tool_name}' timed out after {timeout}s"
        except Exception as e:
            return False, f"Error running {tool_name}: {str(e)}"

    @classmethod
    def install_hint(cls, tool_name):
        if tool_name not in cls.TOOLS:
            return f"Unknown tool: {tool_name}"
        _, apt_cmd, termux_cmd = cls.TOOLS[tool_name]
        if cls.is_termux():
            return termux_cmd
        return apt_cmd

    @classmethod
    def available_tools(cls):
        """Return list of all installed tools"""
        return [name for name in cls.TOOLS if cls.check(name)]

    @classmethod
    def missing_tools(cls):
        """Return list of missing tools with install hints"""
        missing = []
        for name in cls.TOOLS:
            if not cls.check(name):
                missing.append((name, cls.install_hint(name)))
        return missing

    @classmethod
    def print_status(cls):
        """Print full tool availability status"""
        print("\n  📦 RAJAN Tool Status\n")
        for name in cls.TOOLS:
            installed = cls.check(name)
            icon = "✅" if installed else "❌"
            hint = "" if installed else f"  → {cls.install_hint(name)}"
            print(f"  {icon} {name:<15}{hint}")
        available = cls.available_tools()
        print(f"\n  {len(available)}/{len(cls.TOOLS)} tools available")
        if cls.is_termux():
            print("  📱 Termux environment detected")
        print()
