#!/usr/bin/env python3
"""
RAJAN Smart Installer
- Auto-detects environment (Termux, Kali, Ubuntu, macOS, Windows)
- Skips anything already installed — no re-downloading
- Only installs what's actually missing
"""

import os
import sys
import subprocess
import shutil
import platform


def detect_env():
    if "com.termux" in os.environ.get("PREFIX", ""):
        return "termux"
    system = platform.system().lower()
    if system == "linux":
        try:
            with open("/etc/os-release") as f:
                content = f.read().lower()
            if "kali" in content:      return "kali"
            if "parrot" in content:    return "parrot"
            if "ubuntu" in content:    return "ubuntu"
            if "debian" in content:    return "ubuntu"
        except Exception:
            pass
        return "linux"
    if system == "darwin":  return "macos"
    if system == "windows": return "windows"
    return "unknown"


def is_installed(cmd):
    """Check if a command is already available — skip if yes"""
    return shutil.which(cmd) is not None


def pip_installed(pkg):
    """Check if a Python package is already importable — skip if yes"""
    import importlib
    pkg_name = pkg.split(">=")[0].split("==")[0].strip().replace("-", "_")
    try:
        importlib.import_module(pkg_name)
        return True
    except ImportError:
        return False


def run_cmd(cmd, check=False):
    print(f"  → {cmd}")
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, check=check
        )
        if result.stdout.strip():
            print(f"    {result.stdout.strip()[:100]}")
        return result.returncode == 0
    except Exception as e:
        print(f"    ⚠️  {e}")
        return False


def install_pip_pkg(pkg, extra_args=""):
    """Install Python package only if not already present"""
    pkg_name = pkg.split(">=")[0].split("==")[0].strip()
    if pip_installed(pkg_name):
        print(f"  ✓ {pkg_name} already installed — skipping")
        return True
    print(f"  ↓ Installing {pkg_name}...")
    flags = "--break-system-packages --quiet"
    if extra_args:
        flags += f" {extra_args}"
    return run_cmd(f"{sys.executable} -m pip install {pkg} {flags}")


def install_system_pkg(pkg, pkg_manager, check_cmd=None):
    """Install system package only if not already present"""
    check = check_cmd or pkg
    if is_installed(check):
        print(f"  ✓ {pkg} already installed — skipping")
        return True
    print(f"  ↓ Installing {pkg}...")
    return run_cmd(f"{pkg_manager} {pkg} -y 2>/dev/null || true")


def install_python_deps():
    print("\n  📦 Python dependencies...")
    pkgs = ["requests", "rich", "urllib3"]
    for pkg in pkgs:
        install_pip_pkg(pkg)


def create_dirs():
    for d in ["memory", "sessions", "reports", "logs"]:
        os.makedirs(d, exist_ok=True)
    print("  ✅ Directories ready")


def make_executable():
    try:
        os.chmod("rajan.py", 0o755)
    except Exception:
        pass


def setup_termux():
    print("\n  📱 Termux detected\n")

    # System packages — skip if already installed
    termux_pkgs = [
        ("python",   "python3"),
        ("git",      "git"),
        ("nmap",     "nmap"),
        ("curl",     "curl"),
        ("wget",     "wget"),
        ("whois",    "whois"),
    ]
    missing = [p for p, c in termux_pkgs if not is_installed(c)]
    if missing:
        print(f"  ↓ Installing missing: {', '.join(missing)}")
        run_cmd(f"pkg update -y -q 2>/dev/null")
        for pkg, _ in termux_pkgs:
            if pkg in missing:
                install_system_pkg(pkg, "pkg install", pkg.replace("python", "python3"))
    else:
        print("  ✓ All system packages already installed")

    install_python_deps()

    optional = [("gobuster","gobuster"), ("subfinder","subfinder"),
                ("httpx","httpx"), ("nuclei","nuclei")]
    missing_opt = [p for p, c in optional if not is_installed(c)]
    if missing_opt:
        print(f"\n  ℹ️  Optional tools not installed (gives more features if added):")
        for pkg, _ in optional:
            if pkg in missing_opt:
                print(f"     pkg install {pkg}")


def setup_kali():
    print("\n  🐉 Kali Linux detected\n")
    kali_pkgs = [
        ("nmap",      "nmap"),
        ("gobuster",  "gobuster"),
        ("curl",      "curl"),
        ("wget",      "wget"),
        ("whois",     "whois"),
        ("dnsutils",  "dig"),
        ("python3",   "python3"),
        ("python3-pip","pip3"),
    ]
    missing = [p for p, c in kali_pkgs if not is_installed(c)]
    if missing:
        run_cmd("sudo apt update -qq 2>/dev/null")
        for pkg, check in kali_pkgs:
            if not is_installed(check):
                install_system_pkg(pkg, "sudo apt install", check)
    else:
        print("  ✓ All system packages already installed")
    install_python_deps()


def setup_ubuntu():
    print("\n  🐧 Ubuntu/Debian detected\n")
    pkgs = [
        ("nmap","nmap"), ("curl","curl"), ("wget","wget"),
        ("whois","whois"), ("dnsutils","dig"), ("python3","python3"),
    ]
    missing = [p for p, c in pkgs if not is_installed(c)]
    if missing:
        run_cmd("sudo apt update -qq 2>/dev/null")
        for pkg, check in pkgs:
            if not is_installed(check):
                install_system_pkg(pkg, "sudo apt install", check)
    else:
        print("  ✓ All system packages already installed")
    install_python_deps()


def setup_macos():
    print("\n  🍎 macOS detected\n")
    if not is_installed("brew"):
        print("  ⚠️  Homebrew not found — install from https://brew.sh")
    else:
        for pkg, check in [("nmap","nmap"),("curl","curl"),("wget","wget")]:
            install_system_pkg(pkg, "brew install", check)
    install_python_deps()


def setup_windows():
    print("\n  🪟 Windows detected (WSL recommended)\n")
    print("  ℹ️  For best results use WSL2 with Ubuntu or Kali")
    install_python_deps()


def print_summary(env):
    avail = []
    for tool in ["nmap","gobuster","ffuf","sqlmap","nuclei","subfinder",
                 "hydra","nikto","curl","wget","git","whois","dig"]:
        if is_installed(tool):
            avail.append(tool)

    print(f"""
{'═'*55}
  ✅ RAJAN Installation Complete!
  Environment: {env.upper()}
  Tools available: {len(avail)}/13
  Ready: {', '.join(avail[:6])}{'...' if len(avail)>6 else ''}
{'═'*55}

  🚀 Start RAJAN:
     python3 rajan.py

  ⚡ Autonomous scan:
     python3 rajan.py --target example.com --scope "*.example.com"

  🔧 First-time LLM setup:
     python3 rajan.py --setup

  🧪 Verify everything works:
     python3 rajan.py --selftest

{'═'*55}
  💛 Love RAJAN? Star us on GitHub!
     github.com/DHRUVIL-5/RAJAN
{'═'*55}
""")


def main():
    print("""
╔══════════════════════════════════════════════╗
║         RAJAN Smart Installer v1.0          ║
║  Skips already-installed tools — fast!      ║
╚══════════════════════════════════════════════╝
""")
    env = detect_env()
    print(f"  🔍 Environment: {env.upper()}")

    create_dirs()

    handlers = {
        "termux":  setup_termux,
        "kali":    setup_kali,
        "parrot":  setup_kali,
        "ubuntu":  setup_ubuntu,
        "linux":   setup_ubuntu,
        "macos":   setup_macos,
        "windows": setup_windows,
    }
    handlers.get(env, setup_ubuntu)()
    make_executable()
    print_summary(env)


if __name__ == "__main__":
    main()
