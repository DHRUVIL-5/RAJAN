#!/usr/bin/env python3
"""
RAJAN Smart Installer
Detects your environment and sets everything up automatically
Works on: Termux (Android), Kali Linux, Ubuntu, Parrot OS, macOS, Windows WSL
"""

import os
import sys
import subprocess
import platform


def detect_env():
    if "com.termux" in os.environ.get("PREFIX", ""):
        return "termux"
    system = platform.system().lower()
    if system == "linux":
        try:
            with open("/etc/os-release") as f:
                content = f.read().lower()
            if "kali" in content:
                return "kali"
            if "parrot" in content:
                return "parrot"
            if "ubuntu" in content or "debian" in content:
                return "ubuntu"
        except Exception:
            pass
        return "linux"
    if system == "darwin":
        return "macos"
    if system == "windows":
        return "windows"
    return "unknown"


def run(cmd, check=True):
    print(f"  → {cmd}")
    try:
        result = subprocess.run(
            cmd, shell=True, check=check,
            capture_output=True, text=True
        )
        if result.stdout.strip():
            print(f"    {result.stdout.strip()[:100]}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"    ⚠️  Command failed: {e}")
        return False


def install_python_deps():
    print("\n  📦 Installing Python dependencies...")
    deps = ["requests"]
    for dep in deps:
        run(f"{sys.executable} -m pip install {dep} --quiet")


def setup_termux():
    print("\n  📱 Termux environment detected!")
    print("  Installing Termux-compatible packages...\n")
    run("pkg update -y")
    run("pkg install -y python nmap curl wget git whois dnsutils")
    print("\n  ℹ️  Optional tools (install if you want more features):")
    print("    pkg install -y gobuster subfinder httpx nuclei")
    install_python_deps()


def setup_kali():
    print("\n  🐉 Kali Linux detected!")
    print("  Great! Most tools are already installed on Kali.\n")
    run("sudo apt update -qq")
    run("sudo apt install -y python3 python3-pip nmap gobuster curl wget whois dnsutils", check=False)
    install_python_deps()


def setup_ubuntu():
    print("\n  🐧 Ubuntu/Debian detected!")
    run("sudo apt update -qq")
    run("sudo apt install -y python3 python3-pip nmap curl wget whois dnsutils", check=False)
    install_python_deps()


def setup_macos():
    print("\n  🍎 macOS detected!")
    run("brew install python3 nmap curl wget", check=False)
    install_python_deps()


def setup_windows():
    print("\n  🪟 Windows detected! (WSL recommended)")
    print("  Installing Python deps only...")
    install_python_deps()


def create_dirs():
    dirs = ["memory", "sessions", "reports", "logs"]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    print("  ✅ Directories created")


def make_executable():
    try:
        os.chmod("rajan.py", 0o755)
        print("  ✅ rajan.py is now executable")
    except Exception:
        pass


def print_next_steps(env):
    print(f"""
{'═'*55}
  ✅ RAJAN Installation Complete!
{'═'*55}

  🚀 Start RAJAN:
     python3 rajan.py

  ⚡ Quick scan:
     python3 rajan.py --target example.com

  🔧 Setup LLM (first time):
     python3 rajan.py --setup

  📦 Check tools:
     python3 rajan.py --tools

{'═'*55}
  💛 Love RAJAN? Star us on GitHub!
     github.com/DHRUVIL-5/RAJAN
{'═'*55}
""")


def main():
    print("""
╔══════════════════════════════════════════════╗
║         RAJAN Smart Installer v1.0          ║
║    AI Ethical Hacking Agent                 ║
╚══════════════════════════════════════════════╝
""")
    env = detect_env()
    print(f"  🔍 Detected environment: {env.upper()}")

    create_dirs()

    handlers = {
        "termux": setup_termux,
        "kali":   setup_kali,
        "parrot": setup_kali,
        "ubuntu": setup_ubuntu,
        "linux":  setup_ubuntu,
        "macos":  setup_macos,
        "windows":setup_windows,
    }
    handlers.get(env, setup_ubuntu)()
    make_executable()
    print_next_steps(env)


if __name__ == "__main__":
    main()
