<div align="center">

```
██████╗  █████╗      ██╗ █████╗ ███╗   ██╗
██╔══██╗██╔══██╗     ██║██╔══██╗████╗  ██║
██████╔╝███████║     ██║███████║██╔██╗ ██║
██╔══██╗██╔══██║██   ██║██╔══██║██║╚██╗██║
██║  ██║██║  ██║╚█████╔╝██║  ██║██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝ ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
```

### AI-Powered Ethical Hacking Agent

[![Version](https://img.shields.io/badge/Version-1.1.0-blue?style=for-the-badge)]()
[![Python](https://img.shields.io/badge/Python-3.8+-green?style=for-the-badge&logo=python)]()
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)]()
[![Platform](https://img.shields.io/badge/Termux%20%7C%20Kali%20%7C%20Linux%20%7C%20macOS%20%7C%20Windows-red?style=for-the-badge)]()
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)]()

*Talk to it naturally. It works autonomously for hours. It thinks like a real pentester.*

[🚀 Install](#-installation) · [💬 Usage](#-usage) · [✨ Features](#-features) · [📚 Knowledge Base](#-knowledge-base) · [🔌 LLM Support](#-llm-support) · [💛 Support](#-support)

</div>

---

## What is RAJAN?

RAJAN is an AI-powered ethical hacking agent that automates the entire penetration testing workflow. Unlike traditional scanning tools that simply run commands, RAJAN **thinks**, **plans**, **adapts**, and **chains discoveries together** — exactly the way an experienced human pentester would.

You give it a target and a scope. RAJAN takes over from there — running reconnaissance, scanning ports, fingerprinting technologies, testing for dozens of vulnerability types, mapping findings to MITRE ATT&CK, identifying how vulnerabilities chain together for greater impact, and delivering a professional report when it's done. You can walk away and come back to results.

It runs entirely from the command line — on your Android phone via Termux, on Kali Linux, on any Linux system, macOS, or Windows WSL. No GUI needed. No Docker. No heavy setup. Just Python.

---

## ✨ Features

### 🤖 Autonomous Operation
RAJAN works completely on its own once you give it a target. It builds a plan, executes each task in the correct dependency order, and dynamically re-plans based on what it discovers. After every few completed tasks, RAJAN analyzes its own results and asks its AI brain whether new tests should be added — so if it discovers a WordPress install halfway through, it automatically adds WordPress-specific CVE checks to the queue. Sessions can run for hours unattended.

### 🗣️ Natural Language Interface
You don't need to memorize flags or commands. Just type what you want:
- *"scan example.com for vulnerabilities"*
- *"what is SSRF and how do I test for it?"*
- *"show me XSS payloads"*
- *"look up CVE-2021-44228"*
- *"generate a report"*

RAJAN understands your intent and routes it to the right module automatically.

### 💬 Interrupt Chat While Working
While RAJAN is running an autonomous scan, you can still talk to it at any time by prefixing your message with `!`. Ask it questions, redirect its focus, check progress, or pause it — all without stopping the scan.

### ⛓️ Vulnerability Chain Analyzer
This is what separates junior bug hunters from seniors — finding how multiple low-to-medium vulnerabilities **chain together** for critical impact. RAJAN automatically analyzes all discoveries and identifies attack chains. For example: SSRF + Cloud Metadata = credential theft. XSS + Missing HTTPOnly = session hijacking. `.git` exposed + hardcoded secrets = full source code and credentials leak. No other open-source ethical hacking agent does this automatically.

### 🎯 Hard Scope Enforcement
RAJAN strictly enforces the scope you define. If you set `--scope *.example.com`, every single agent checks every URL and hostname before making a request — out-of-scope targets are hard-blocked and logged. This is critical for bug bounty work where testing out-of-scope can get you banned from platforms like HackerOne. Wildcard patterns, subdomain matching, and full URL parsing are all supported.

### 📊 Confidence & Scoring System
Every vulnerability finding RAJAN reports includes a CVSS-style severity score, a confidence percentage (0–100%), and a reliability rating. Findings confirmed with a proof-of-concept get boosted confidence. Potential findings without evidence get flagged as low confidence for manual review. This eliminates false positives and makes reports immediately actionable for real-world use.

### 🤝 Agent-to-Agent Communication
RAJAN's specialized agents don't just take orders from a central controller — they share intelligence with each other through a message bus. When the recon agent discovers subdomains, it publishes them directly to the scanner and web agents. When the scanner finds open ports, the exploit agent is notified automatically. This makes the system feel alive and surfaces connections that a sequential approach would miss.

### 📺 Live Log System
Every action RAJAN takes is printed to the terminal in real time with timestamps, color-coded severity levels, and agent labels — plus a live inline progress bar showing tasks completed, findings discovered, and what's currently running. You can watch exactly what it's doing at any moment.

### 🎬 Session Replay
Replay any past session at any speed. Great for reviewing what happened, learning from the methodology, or demonstrating findings to a client or team.

### 💾 Persistent Memory
Everything is stored in a local SQLite database using WAL (Write-Ahead Logging) mode — which prevents locking issues during heavy multi-threaded scans, especially on Termux. Sessions survive crashes, phone restarts, and connection drops. Resume any interrupted session with a single command. RAJAN never repeats work it has already done.

### 📊 Professional Reports
Auto-generated reports in both Markdown and HTML with a dark professional theme. Includes executive summary (AI-written), risk summary table, full finding details with MITRE mappings, confidence scores, and remediation advice. Ready to send to clients or submit to bug bounty platforms.

### 📦 Multi-Format Export
Export findings as JSON (for automation), CSV (for spreadsheet analysis), plain TXT (paste anywhere), or pre-formatted HackerOne/Bugcrowd submission templates. All formats in one command.

### 🔔 Notifications
Terminal bell + Termux push notification (Android) + optional email alert when a long autonomous scan completes. You'll never miss a finished session.

### 🛠️ Fully Optional Tools
RAJAN detects which security tools are installed on your system and uses them when available. If `gobuster` isn't installed, it falls back to its own implementation. If `sqlmap` isn't there, it uses its built-in testing logic. It never blocks or crashes because of a missing tool — it adapts.

### ⚙️ Persistent Configuration
All your settings — preferred scan mode, report format, notification preferences, LLM choice — are saved between sessions in a local config file. Set it once, never configure again.

---

## 🛠️ Reliability and Safety Improvements

The current maintenance release includes several reliability improvements across the full workflow. Session tasks now persist stable IDs, dependencies, results, and status transitions, so `--resume` continues the original session instead of creating a duplicate session. Scope parsing now normalizes URLs, ports, trailing dots, and wildcard boundaries before every request. External-tool failures propagate their real exit codes, and the installer uses argument-list subprocess execution rather than a shell.

Findings are deduplicated per session and location while preserving CVSS, confidence, and reliability metadata in SQLite and CSV exports. Generated HTML reports escape target-controlled content, and report/export filenames are sanitized to remain inside the `reports/` directory. Hugging Face requests now receive the same compulsory RAJAN system prompt as the other providers. Dry-run mode now avoids DNS, sockets, HTTP requests, JavaScript fetches, TLS probes, cloud probes, and external scanning tools.

A standard-library regression suite covers these behaviors and can be run locally with:

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q .
```

GitHub Actions runs the same checks on Python 3.9, 3.11, and 3.12 for pushes and pull requests.

---

## 🚀 Installation

### Any System (Universal)
```bash
git clone https://github.com/DHRUVIL-5/RAJAN.git
cd RAJAN
python3 setup.py        # Auto-detects your environment and installs dependencies
python3 rajan.py        # Start RAJAN
```

### 📱 Android (Termux)
```bash
pkg install python git
git clone https://github.com/DHRUVIL-5/RAJAN.git
cd RAJAN
python3 setup.py
python3 rajan.py
```

### 🐉 Kali Linux / Parrot OS
```bash
git clone https://github.com/DHRUVIL-5/RAJAN.git
cd RAJAN
python3 setup.py
python3 rajan.py
```

The smart installer (`setup.py`) automatically detects whether you're on Termux, Kali, Ubuntu, Parrot, macOS, or Windows — and installs the right packages for your environment.

---

## 💬 Usage

### Interactive Mode (Recommended)
```bash
python3 rajan.py
```
Just start RAJAN and talk to it. It understands natural language.

### Autonomous Scan (CLI)
```bash
# Full autonomous scan
python3 rajan.py --target example.com

# With scope restriction (enforced across all agents)
python3 rajan.py --target example.com --scope "*.example.com"

# Ask before each task (learning mode)
python3 rajan.py --target example.com --semi
```

### While RAJAN Works — Interrupt Commands
Type these anytime during an autonomous scan (no need to stop it):
```
!status          → Progress, tasks done, findings, active agents, re-plan cycles
!stop            → Pause the scan
!resume          → Continue after pause
!report so far   → Show all findings discovered so far
!focus on web    → Shift priority to web application testing
!focus on cloud  → Shift priority to cloud security checks
!skip            → Skip the current task and move to next
!quit            → Save everything cleanly and exit
```

### Natural Language Examples
```
scan example.com for vulnerabilities
start bug bounty on target.com, scope: *.target.com
what is SQL injection?
explain SSRF with examples
cve log4j
cve CVE-2021-44228
cve confluence
cve moveit
payloads xss
payloads sqli
payloads ssrf
mitre T1190
mitre command injection
bug bounty checklist
severity guide
show my findings
generate report
export findings
export hackerone
chain analysis
replay session
resume last session
check what tools I have
setup email notifications
config
selftest
```

---

## 🧠 Autonomous Task Flow

When you start a scan, RAJAN builds and executes a task plan in the correct dependency order. The plan is not static — as results come in, the AI brain analyzes discoveries and dynamically injects follow-up tasks:

```
Reconnaissance
  ├─ DNS enumeration, WHOIS lookup, reverse DNS
  ├─ Subdomain discovery (subfinder + brute force)
  ├─ OSINT — Google dorking, Wayback Machine
  └─ GitHub / GitLab code leak search

Scanning & Fingerprinting
  ├─ Port scan (20+ common ports, multithreaded)
  ├─ Service and version detection (nmap)
  └─ Web technology fingerprinting

Web Application Testing
  ├─ Directory and endpoint discovery
  ├─ XSS — Reflected, Stored, DOM (manual + tool)
  ├─ SQL Injection — Error, Union, Time-based Blind
  ├─ IDOR — Sequential ID enumeration
  ├─ SSRF — Internal + Cloud metadata endpoints
  ├─ LFI / Path Traversal — Unix + Windows
  ├─ SSTI — Jinja2, Twig, Freemarker detection
  ├─ Open Redirect — 7 parameter variants
  ├─ CSRF — Form token validation
  ├─ Authentication bypass — Default credentials
  ├─ JavaScript file analysis — API keys, tokens, secrets
  └─ SSL/TLS — Ciphers, versions, certificate expiry

Exploit Research
  ├─ CVE matching against detected technology versions
  └─ AI-powered known vulnerability analysis

Cloud Security
  ├─ S3 / GCS / Azure blob public access check
  └─ Cloud metadata API via SSRF

Vulnerability Chain Analysis
  └─ Automatically identifies how findings combine for higher impact

Dynamic Re-planning (Feedback Loop)
  └─ LLM analyzes results every few tasks and injects new tests if needed

Report Generation
  └─ HTML + Markdown professional report with confidence scores
```

---

## 📚 Knowledge Base

RAJAN ships with a built-in offline knowledge base — no internet required for lookups.

### 🛡️ MITRE ATT&CK Database
21 techniques mapped across all tactics: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, and Impact. Every finding RAJAN discovers is automatically tagged with its MITRE technique ID.

```
[RAJAN]> mitre T1190
[RAJAN]> mitre ssrf
[RAJAN]> mitre credential access
```

### 🐛 CVE Database (Offline + Live)
37 CVEs stored locally — works with no internet. When a CVE isn't in the local database, RAJAN automatically falls back to a live NVD API lookup. Local coverage includes: Log4Shell, Spring4Shell, EternalBlue, BlueKeep, SMBGhost, Heartbleed, Shellshock, Ghostcat, Drupalgeddon, WordPress RCE, Grafana Path Traversal, GitLab RCE, Confluence RCE, Exchange ProxyLogon/ProxyShell, Citrix ADC, Pulse Secure, VMware vCenter, F5 BIG-IP, Fortinet Auth Bypass, MOVEit SQLi, PaperCut RCE, Kubernetes privilege escalation, Jenkins RCE, Apache Struts, WebLogic, and more.

```
[RAJAN]> cve log4j
[RAJAN]> cve CVE-2022-26134
[RAJAN]> cve confluence
[RAJAN]> cve moveit
```

### 💣 Payload Library
80+ payloads across 10 categories: XSS (basic, filter bypass, cookie stealing, DOM), SQL Injection (detection, UNION, blind time-based, error-based), SSRF (basic, cloud metadata, bypass), Path Traversal (Unix, Windows), XXE, Command Injection, LFI, Open Redirect, SSTI, and JWT attacks.

```
[RAJAN]> payloads xss
[RAJAN]> payloads sqli
[RAJAN]> payloads ssrf
[RAJAN]> payloads ssti
```

### 📋 Bug Bounty Methodology
Complete checklists for web app and network pentesting across 6 phases (Recon, Scanning, Authentication, Vulnerability Testing, API Security, Cloud). Platform-specific guidance for HackerOne, Bugcrowd, and Intigriti including severity scoring guides.

```
[RAJAN]> bug bounty checklist
[RAJAN]> severity guide
```

---

## 🔌 LLM Support

RAJAN works with any of these providers — your choice during first run. RAJAN tests your API connection before each scan begins. You can also use any OpenAI-compatible endpoint not listed here via the Custom provider option.

| Provider | Free | Best For |
|----------|------|----------|
| **Groq** ⭐ | ✅ Free key | Recommended — fastest, Llama 3.3 / DeepSeek |
| **Puter.js** 🆓 | ✅ No key needed | 500+ models free — GPT-4o, Claude, Gemini, DeepSeek |
| **OpenRouter** | ✅ Free models | Many models, free tier available |
| **Ollama** | ✅ Fully offline | Privacy-first, no data sent anywhere |
| **Google Gemini** | ✅ Free tier | Gemini 1.5 Flash / Pro |
| **Mistral AI** | ✅ Free tier | Open-source Mistral models |
| **Together AI** | ✅ $25 credit | Llama, Mixtral, DeepSeek |
| **LM Studio** | ✅ Local | OpenAI-compatible local server |
| **OpenAI** | ❌ Paid | GPT-4o for maximum accuracy |
| **Anthropic Claude** | ❌ Paid | Best reasoning for complex targets |
| **HuggingFace** | ✅ Free tier | Open source inference API |
| **Custom** | Any | Any OpenAI-compatible API endpoint |

Switch providers anytime: `python3 rajan.py --setup`

### 💬 Dual System Prompt
RAJAN uses two layered system prompts:
- **Core prompt** (compulsory): Defines RAJAN's identity, CLI context, hacking expertise — always active, cannot be removed
- **Your custom addon** (optional): Add your own instructions on top — language preference, focus area, response style, etc.

```bash
python3 rajan.py --prompt          # Edit your custom addon prompt
python3 rajan.py --setup           # Change AI provider
```

Examples of user addons: `"Always respond in Spanish"` · `"Focus only on bug bounty, skip network tests"` · `"Be very brief, one paragraph max"`

---

## 📦 Full CLI Reference

```bash
python3 rajan.py                              # Interactive NLP mode
python3 rajan.py --target <domain/IP>         # Start autonomous scan
python3 rajan.py --target t.com --scope "*.t.com"  # With scope enforcement
python3 rajan.py --target t.com --semi        # Semi-auto (approve each task)
python3 rajan.py --target t.com --quick       # Quick mode (critical checks only)
python3 rajan.py --setup                      # Configure LLM provider
python3 rajan.py --config                     # Open settings
python3 rajan.py --tools                      # Show installed security tools
python3 rajan.py --sessions                   # List all past sessions
python3 rajan.py --resume <session-id>        # Resume an interrupted session
python3 rajan.py --replay <session-id>        # Watch a past session replay
python3 rajan.py --chain                      # Vulnerability chain analysis
python3 rajan.py --export json                # Export last session as JSON
python3 rajan.py --export hackerone           # HackerOne submission templates
python3 rajan.py --export all                 # All export formats at once
python3 rajan.py --notify-setup               # Setup email notifications
python3 rajan.py --selftest                   # Verify RAJAN is working correctly
python3 rajan.py --update                     # Check for newer version
python3 rajan.py --prompt                     # Edit your custom personality/style for RAJAN
python3 rajan.py --dry-run --target t.com    # Simulate scan without real HTTP requests
```

---

## 🗂️ Project Structure

```
RAJAN/
├── rajan.py                   ← Entry point — NLP chat + CLI + autonomous launcher
├── setup.py                   ← Smart installer (Termux / Kali / Ubuntu / macOS / Windows)
│
├── core/
│   ├── brain.py               ← ReACT engine with feedback loop + agent-to-agent comms
│   ├── llm.py                 ← Multi-LLM connector (6 providers, connectivity verified)
│   ├── memory.py              ← SQLite persistent memory (WAL mode, thread-safe)
│   ├── logger.py              ← Live colored terminal log system with progress bar
│   ├── task_tree.py           ← Task planning, dependency resolution, dynamic injection
│   ├── scope.py               ← Hard scope enforcer (wildcard + subdomain matching)
│   ├── scoring.py             ← Confidence + CVSS scoring on every finding
│   ├── chain_analyzer.py      ← Vulnerability chain discovery (10 known + AI-powered)
│   ├── config.py              ← Persistent user configuration system
│   ├── exporter.py            ← Multi-format export (JSON, CSV, TXT, HackerOne)
│   ├── notifier.py            ← Termux push + terminal bell + email notifications
│   ├── replay.py              ← Session replay at variable speed
│   └── selftest.py            ← 15-check self-test including LLM connectivity
│
├── agents/
│   ├── base.py                ← Base agent (scope enforcement + scoring built in)
│   ├── recon.py               ← DNS, WHOIS, subdomain discovery, security header analysis
│   ├── scanner.py             ← Multithreaded port scanner with risk assessment
│   ├── web.py                 ← XSS, SQLi, IDOR, SSRF, LFI, SSTI, CSRF, Auth, SSL, JS
│   ├── osint.py               ← Google dorking, GitHub leaks, S3 bucket checks
│   ├── exploit.py             ← CVE matching against 37 known vulnerabilities
│   ├── cloud.py               ← Cloud misconfiguration detection
│   └── reporter.py            ← HTML + Markdown professional report generation
│
├── tools/
│   └── toolmanager.py         ← Auto-detects installed tools, Termux-aware, never blocks
│
├── knowledge/
│   ├── mitre.py               ← MITRE ATT&CK database (21 techniques)
│   ├── cve_db.py              ← Offline CVE database (37 CVEs + NVD live fallback)
│   ├── payloads.py            ← Payload library (10 categories, 80+ payloads)
│   ├── methodology.py         ← Bug bounty checklists + platform guides
│   └── reporter_engine.py     ← HTML dark-theme + Markdown report templates
│
├── memory/                    ← Auto-created: sessions, config, LLM settings (WAL mode)
├── reports/                   ← Auto-created: all generated reports and exports
└── logs/                      ← Auto-created: full session log files
```

---

## 💛 Support RAJAN

RAJAN is completely free and open source. If it helps your work:

- ⭐ **Star this repo** — it helps others in the security community find RAJAN
- 🐛 **Report bugs** — open an issue on GitHub
- 🤝 **Contribute** — pull requests are welcome
- 💰 **Donate crypto** — keeps active development going *(wallet addresses coming soon)*

---

## ⚖️ Legal & Ethical Disclaimer

**This project is intended strictly for educational purposes and authorized security testing only.**

The developer does not promote, support, or condone any illegal or unauthorized activities. Users are solely responsible for ensuring they have explicit written permission before using this tool on any system or network. Penetration testing without authorization is illegal in most jurisdictions and can result in criminal prosecution.

Any misuse of this software is the sole responsibility of the user. The developer assumes no liability and is not responsible for any misuse or damage caused by this tool.

**Always get written permission before testing. Stay legal. Stay ethical.**

---

## 📄 License

MIT License — Free to use, modify, and distribute for educational and authorized security testing purposes.

---

<div align="center">

Made with ❤️ by **DHRUVIL-5**

[github.com/DHRUVIL-5/RAJAN](https://github.com/DHRUVIL-5/RAJAN)

</div>
