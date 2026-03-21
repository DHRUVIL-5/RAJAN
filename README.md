<div align="center">

```
██████╗  █████╗      ██╗ █████╗ ███╗   ██╗
██╔══██╗██╔══██╗     ██║██╔══██╗████╗  ██║
██████╔╝███████║     ██║███████║██╔██╗ ██║
██╔══██╗██╔══██║██   ██║██╔══██║██║╚██╗██║
██║  ██║██║  ██║╚█████╔╝██║  ██║██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
```

**AI Ethical Hacking Agent**

[![Version](https://img.shields.io/badge/Version-1.0.0-blue?style=for-the-badge)]()
[![Python](https://img.shields.io/badge/Python-3.8+-green?style=for-the-badge&logo=python)]()
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)]()
[![Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20Kali%20%7C%20Linux%20%7C%20macOS-red?style=for-the-badge)]()

*Your intelligent cybersecurity partner — talks naturally, works autonomously for hours* 😎

</div>

---

## ✨ What Makes RAJAN Different

- 🗣️ **Talk naturally** — "scan example.com for vulnerabilities" — no commands to memorize
- 🤖 **Fully autonomous** — give it a target, walk away, come back to a full report
- 💬 **Chat while it works** — interrupt with `!` commands anytime during a scan
- 📺 **Live logs** — see exactly what RAJAN is doing, in real time
- 📱 **Mobile-first** — runs on Android via Termux with minimal resources
- 🔌 **Any LLM** — Groq, OpenAI, Claude, OpenRouter, HuggingFace, Ollama (offline)
- 🛠️ **Tools optional** — works with or without external tools installed
- 💾 **Never loses progress** — SQLite memory survives crashes, resumes sessions

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/DHRUVIL-5/RAJAN.git
cd RAJAN

# Install (auto-detects your environment)
python3 setup.py

# Run
python3 rajan.py
```

### Termux (Android)
```bash
pkg install python git
git clone https://github.com/DHRUVIL-5/RAJAN.git
cd RAJAN
python3 setup.py
python3 rajan.py
```

---

## 💬 How to Use — Just Talk

```
[RAJAN]> scan example.com for vulnerabilities

[RAJAN]> start bug bounty on target.com, scope: *.target.com

[RAJAN]> what is SQL injection?

[RAJAN]> show my findings

[RAJAN]> generate a report

[RAJAN]> resume last session
```

### Autonomous Mode
```bash
# Start a full autonomous scan from CLI
python3 rajan.py --target example.com --scope *.example.com
```

RAJAN will work for hours on its own. While it works, you can still chat:
```
!status          → How many tasks done, findings so far
!stop            → Pause the scan
!resume          → Continue after pause
!report so far   → See findings discovered so far
!focus on web    → Shift priority to web testing
!skip            → Skip current task
!quit            → Save and exit cleanly
```

---

## 🧠 What RAJAN Does (Autonomous Task Tree)

```
Phase 1 — Recon
  ├── DNS enumeration & WHOIS
  ├── Subdomain discovery
  ├── OSINT — Google dorking
  └── OSINT — GitHub/code leak search

Phase 2 — Scanning
  ├── Port scan (20+ common ports)
  ├── Service & version detection
  └── Web tech fingerprinting

Phase 3 — Web Testing
  ├── Directory & endpoint discovery
  ├── XSS testing
  ├── SQL injection testing
  ├── IDOR & access control
  ├── SSRF testing
  ├── Authentication testing
  └── JS file secret analysis

Phase 4 — Exploit Research
  ├── CVE lookup for detected versions
  └── Known vulnerability check

Phase 5 — Cloud & SSL
  ├── S3/GCS/Azure bucket check
  └── SSL/TLS configuration check

Phase 6 — Report
  └── Auto-generate professional pentest report
```

---

## 🔌 Supported LLM Providers

| Provider | Free | Speed | Best For |
|----------|------|-------|----------|
| **Groq** ⭐ | ✅ Free | ⚡ Fastest | Recommended default |
| **OpenRouter** | ✅ Free models | ✅ Good | Many model options |
| **Ollama** | ✅ Offline | ⚠️ Device-dependent | Privacy / no internet |
| **OpenAI** | ❌ Paid | ✅ Great | GPT-4 power |
| **Claude** | ❌ Paid | ✅ Great | Best reasoning |
| **HuggingFace** | ✅ Free | ⚠️ Varies | Open source models |

---

## 📦 CLI Options

```bash
python3 rajan.py                          # Interactive mode
python3 rajan.py --target example.com    # Autonomous scan
python3 rajan.py --target t.com --semi   # Semi-auto (approve each task)
python3 rajan.py --scope *.example.com   # With scope
python3 rajan.py --setup                 # Configure LLM
python3 rajan.py --tools                 # Show installed tools
python3 rajan.py --sessions              # List past sessions
python3 rajan.py --resume <session-id>   # Resume session
```

---

## ⚠️ Legal Disclaimer

> **RAJAN is strictly for authorized and legal security testing only.**
>
> Only use RAJAN on systems you **own** or have **explicit written permission** to test.
> Unauthorized hacking is **illegal** and **unethical**.
> The creators are **not responsible** for any misuse of this tool.

---

## 💛 Support RAJAN

RAJAN is free and open source. If it helps you, consider supporting:

- ⭐ **Star this repo** — helps others discover RAJAN
- 💰 **Donate crypto** — keeps development going
  - *(Wallet addresses coming soon)*
- 🐛 **Report bugs** — open an issue
- 🤝 **Contribute** — PRs welcome!

---

## 📄 License

MIT License — Free to use for educational and authorized security testing.

---

<div align="center">

Made with ❤️ by **DHRUVIL-5**

</div>
