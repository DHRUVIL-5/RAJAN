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
[![Platform](https://img.shields.io/badge/Termux%20%7C%20Kali%20%7C%20Linux%20%7C%20macOS-red?style=for-the-badge)]()
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)]()

*Talk naturally. Work autonomously. Find vulnerabilities.* 😎

[🚀 Quick Start](#-quick-start) • [💬 Usage](#-usage) • [🧠 Features](#-features) • [💛 Support](#-support)

</div>

---

## 🔥 What is RAJAN?

RAJAN is an **AI-powered ethical hacking agent** that works like a real penetration tester. Give it a target, walk away, and come back to a full professional report. It thinks, plans, acts, and adapts — completely on its own.

> ⚠️ **For authorized security testing only. Always get written permission first.**

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🗣️ **Natural Language** | Just talk — "scan example.com for vulnerabilities" |
| 🤖 **Autonomous Mode** | Works for hours alone, notifies you when done |
| 💬 **Interrupt Chat** | Chat with RAJAN while it's working using `!` commands |
| 📺 **Live Logs** | See every action in real-time with timestamps |
| 🎬 **Session Replay** | Replay any past session like a video |
| 📱 **Mobile-First** | Runs on Android via Termux with minimal resources |
| 🔌 **Any LLM** | Groq (free), OpenAI, Claude, OpenRouter, HuggingFace, Ollama |
| 🛠️ **Tools Optional** | Works with or without external tools installed |
| 💾 **Never Loses Progress** | SQLite memory — resumes after crashes or restarts |
| 📊 **Professional Reports** | HTML + Markdown pentest reports auto-generated |
| 🛡️ **MITRE ATT&CK** | Every finding mapped to MITRE techniques |
| 🔔 **Notifications** | Termux push + terminal bell + email alerts |

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/DHRUVIL-5/RAJAN.git
cd RAJAN

# Smart install (auto-detects your environment)
python3 setup.py

# Run
python3 rajan.py
```

### 📱 Termux (Android)
```bash
pkg install python git
git clone https://github.com/DHRUVIL-5/RAJAN.git
cd RAJAN && python3 setup.py && python3 rajan.py
```

---

## 💬 Usage — Just Talk

```
[RAJAN]> scan example.com for vulnerabilities
[RAJAN]> start bug bounty on target.com, scope: *.target.com
[RAJAN]> what is SQL injection?
[RAJAN]> cve log4j
[RAJAN]> payloads xss
[RAJAN]> mitre T1190
[RAJAN]> bug bounty checklist
[RAJAN]> show my findings
[RAJAN]> generate report
[RAJAN]> replay session
[RAJAN]> resume last session
```

### 🤖 Autonomous Mode
```bash
python3 rajan.py --target example.com --scope *.example.com
```

While RAJAN works autonomously, interrupt it anytime:
```
!status          → Progress + findings so far
!stop            → Pause the scan
!resume          → Continue
!report so far   → Show current findings
!focus on web    → Shift priority to web testing
!skip            → Skip current task
!quit            → Save everything and exit
```

---

## 🧠 Autonomous Task Tree (19 Tasks)

```
Phase 1 — Recon:      DNS, WHOIS, Subdomains, OSINT, GitHub leaks
Phase 2 — Scanning:   Ports, Services, Web fingerprinting
Phase 3 — Web:        XSS, SQLi, IDOR, SSRF, LFI, SSTI, CSRF, Auth, SSL
Phase 4 — Exploits:   CVE matching, Known vulnerability analysis
Phase 5 — Cloud:      S3/GCS/Azure buckets, Metadata API
Phase 6 — Report:     HTML + Markdown professional report
```

---

## 📚 Built-in Knowledge Base

| Module | Content |
|--------|---------|
| 🛡️ MITRE ATT&CK | 21 mapped techniques |
| 🐛 CVE Database | 19 critical CVEs offline (Log4Shell, EternalBlue, etc.) |
| 💣 Payload Library | 10 categories, 80+ payloads (XSS, SQLi, SSRF, XXE, SSTI...) |
| 📋 Methodology | Bug bounty checklists + HackerOne/Bugcrowd/Intigriti guides |

---

## 🔌 Supported LLM Providers

| Provider | Free | Best For |
|----------|------|----------|
| **Groq** ⭐ | ✅ Free | Recommended — fastest |
| **OpenRouter** | ✅ Free models | Many model options |
| **Ollama** | ✅ Offline | Privacy / no internet |
| **OpenAI** | ❌ Paid | GPT-4 power |
| **Anthropic Claude** | ❌ Paid | Best reasoning |
| **HuggingFace** | ✅ Free | Open source models |

---

## 📦 CLI Reference

```bash
python3 rajan.py                           # Interactive NLP mode
python3 rajan.py --target example.com      # Autonomous scan
python3 rajan.py --target t.com --semi     # Semi-auto mode
python3 rajan.py --target t.com --scope *.t.com
python3 rajan.py --setup                   # Configure LLM
python3 rajan.py --tools                   # Tool status
python3 rajan.py --sessions                # Past sessions
python3 rajan.py --resume <session-id>     # Resume session
python3 rajan.py --replay <session-id>     # Replay session
python3 rajan.py --notify-setup            # Email notifications
```

---

## 🗂️ Project Structure

```
RAJAN/
├── rajan.py              ← Entry point (NLP + autonomous)
├── setup.py              ← Smart installer
├── core/
│   ├── brain.py          ← ReACT autonomous engine
│   ├── llm.py            ← Multi-LLM connector
│   ├── memory.py         ← SQLite persistent memory
│   ├── logger.py         ← Live colored log system
│   ├── task_tree.py      ← 19-task planning tree
│   ├── notifier.py       ← Termux + email notifications
│   └── replay.py         ← Session replay
├── agents/               ← 7 specialized agents
│   ├── recon.py          ← DNS, WHOIS, subdomains
│   ├── scanner.py        ← Port scanning
│   ├── web.py            ← XSS, SQLi, SSRF, LFI...
│   ├── osint.py          ← OSINT, Google dorks
│   ├── exploit.py        ← CVE lookup
│   ├── cloud.py          ← Cloud misconfigs
│   └── reporter.py       ← Report generation
├── tools/
│   └── toolmanager.py    ← Auto tool detection
└── knowledge/
    ├── mitre.py           ← MITRE ATT&CK DB
    ├── cve_db.py          ← CVE database
    ├── payloads.py        ← Payload library
    ├── methodology.py     ← Bug bounty guides
    └── reporter_engine.py ← HTML + MD reports
```

---

## 💛 Support RAJAN

RAJAN is **free and open source**. If it helps you:

- ⭐ **Star this repo** — helps others discover it
- 💰 **Donate** — keeps development going *(crypto wallets coming in v2)*
- 🐛 **Report bugs** — open an issue
- 🤝 **Contribute** — PRs welcome!

---

## ⚠️ Legal Disclaimer

> RAJAN is for **authorized and legal** security testing **only**.
> Only use on systems you **own** or have **explicit written permission** to test.
> Unauthorized hacking is **illegal**. Creators are **not responsible** for misuse.

---

## 📄 License

MIT License — Free for educational and authorized security testing.

---

<div align="center">

Made with ❤️ by **DHRUVIL-5**

*github.com/DHRUVIL-5/RAJAN*

</div>
