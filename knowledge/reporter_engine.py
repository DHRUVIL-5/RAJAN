"""
RAJAN Report Engine — Phase 3
Generates professional reports in Markdown AND HTML
"""

import datetime
import os

from knowledge.mitre import MITREMapper
from knowledge.methodology import BugBountyGuide


def generate_html_report(session, findings, intel, counts):
    mitre = MITREMapper()
    date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    target = session.get("target", "Unknown")

    sev_colors = {
        "CRITICAL": "#ff4444",
        "HIGH": "#ff8800",
        "MEDIUM": "#ffcc00",
        "LOW": "#44bb44",
    }
    sev_bg = {
        "CRITICAL": "#fff0f0",
        "HIGH": "#fff8f0",
        "MEDIUM": "#fffdf0",
        "LOW": "#f0fff0",
    }

    findings_html = ""
    for i, f in enumerate(findings, 1):
        sev = f["severity"].upper()
        color = sev_colors.get(sev, "#888")
        bg = sev_bg.get(sev, "#fff")
        mitre_info = mitre.get_technique(f.get("mitre_technique", ""))
        mitre_section = ""
        if mitre_info:
            mitre_section = f"""
            <div class="mitre-box">
                <strong>🛡️ MITRE ATT&CK:</strong> {f.get('mitre_technique','')} —
                {mitre_info['name']} ({mitre_info['tactic']})<br>
                <strong>Remediation:</strong> {mitre_info['mitigation']}
            </div>"""

        findings_html += f"""
        <div class="finding" style="border-left: 5px solid {color}; background: {bg};">
            <div class="finding-header">
                <span class="finding-num">#{i}</span>
                <span class="finding-title">{f['title']}</span>
                <span class="severity-badge" style="background:{color}">{sev}</span>
            </div>
            <table class="finding-table">
                <tr><td><strong>Location</strong></td><td>{f.get('location','N/A')}</td></tr>
                <tr><td><strong>Description</strong></td><td>{f['description']}</td></tr>
                <tr><td><strong>Proof/PoC</strong></td><td><code>{f.get('proof','N/A')}</code></td></tr>
            </table>
            {mitre_section}
        </div>"""

    intel_html = ""
    intel_by_type = {}
    for row in intel:
        if len(row) == 5:
            _, itype, key, value, _ = row
        else:
            itype, key, value = row
        intel_by_type.setdefault(itype, []).append(f"<tr><td>{key}</td><td>{value[:80]}</td></tr>")
    for itype, rows in intel_by_type.items():
        intel_html += f"""
        <h3>{itype.upper()}</h3>
        <table class="intel-table">
            <tr><th>Key</th><th>Value</th></tr>
            {''.join(rows[:15])}
        </table>"""

    risk_chart = ""
    for sev, col in sev_colors.items():
        cnt = counts.get(sev, 0)
        width = min(cnt * 40, 300)
        risk_chart += f"""
        <div class="risk-row">
            <span class="risk-label" style="color:{col}">{sev}</span>
            <div class="risk-bar" style="width:{width}px;background:{col}"></div>
            <span class="risk-count">{cnt}</span>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RAJAN Report — {target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; }}
  .header {{ background: linear-gradient(135deg, #161b22, #1f2937);
             padding: 40px; border-bottom: 3px solid #f85149; }}
  .header h1 {{ color: #f85149; font-size: 2.5em; letter-spacing: 2px; }}
  .header .subtitle {{ color: #8b949e; margin-top: 8px; font-size: 1.1em; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(3,1fr);
                gap: 15px; padding: 30px; background: #161b22; }}
  .meta-card {{ background: #21262d; border-radius: 8px; padding: 20px;
                border: 1px solid #30363d; }}
  .meta-card .label {{ color: #8b949e; font-size: 0.85em; text-transform: uppercase; }}
  .meta-card .value {{ color: #e6edf3; font-size: 1.3em; font-weight: bold; margin-top: 5px; }}
  .section {{ padding: 30px; }}
  .section h2 {{ color: #58a6ff; border-bottom: 1px solid #30363d;
                 padding-bottom: 10px; margin-bottom: 20px; }}
  .section h3 {{ color: #79c0ff; margin: 20px 0 10px; }}
  .risk-row {{ display: flex; align-items: center; gap: 15px; margin: 8px 0; }}
  .risk-label {{ width: 90px; font-weight: bold; }}
  .risk-bar {{ height: 22px; border-radius: 4px; min-width: 5px; }}
  .risk-count {{ font-weight: bold; font-size: 1.2em; }}
  .finding {{ border-radius: 8px; padding: 20px; margin: 15px 0;
              border: 1px solid #30363d; }}
  .finding-header {{ display: flex; align-items: center; gap: 15px; margin-bottom: 15px; }}
  .finding-num {{ background: #30363d; border-radius: 50%; width: 30px; height: 30px;
                  display: flex; align-items: center; justify-content: center;
                  font-weight: bold; font-size: 0.85em; color: #8b949e; }}
  .finding-title {{ flex: 1; font-size: 1.15em; font-weight: bold; color: #e6edf3; }}
  .severity-badge {{ padding: 4px 12px; border-radius: 20px; font-size: 0.8em;
                     font-weight: bold; color: white; }}
  .finding-table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
  .finding-table td {{ padding: 8px 12px; border-bottom: 1px solid #30363d; vertical-align: top; }}
  .finding-table td:first-child {{ width: 130px; color: #8b949e; white-space: nowrap; }}
  .mitre-box {{ background: #1c2128; border-radius: 6px; padding: 12px;
                margin-top: 12px; font-size: 0.9em; border: 1px solid #388bfd44; }}
  .intel-table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
  .intel-table th {{ background: #21262d; padding: 10px; text-align: left;
                     border-bottom: 2px solid #30363d; color: #58a6ff; }}
  .intel-table td {{ padding: 8px 10px; border-bottom: 1px solid #21262d; }}
  code {{ background: #1c2128; padding: 2px 6px; border-radius: 4px;
          font-family: monospace; font-size: 0.9em; color: #a5d6ff; }}
  .footer {{ background: #161b22; padding: 30px; text-align: center;
             color: #8b949e; border-top: 1px solid #30363d; margin-top: 40px; }}
  .disclaimer {{ background: #2d1f1f; border: 1px solid #f8514944; border-radius: 8px;
                 padding: 15px; margin: 20px 30px; color: #f0a0a0; font-size: 0.9em; }}
  @media(max-width:768px) {{
    .meta-grid {{ grid-template-columns: 1fr; }}
    .header h1 {{ font-size: 1.8em; }}
  }}
</style>
</head>
<body>

<div class="header">
  <h1>🔐 RAJAN</h1>
  <div class="subtitle">AI Ethical Hacking Agent — Penetration Test Report</div>
</div>

<div class="meta-grid">
  <div class="meta-card">
    <div class="label">Target</div>
    <div class="value">{target}</div>
  </div>
  <div class="meta-card">
    <div class="label">Date</div>
    <div class="value">{date}</div>
  </div>
  <div class="meta-card">
    <div class="label">Total Findings</div>
    <div class="value" style="color:#f85149">{len(findings)}</div>
  </div>
  <div class="meta-card">
    <div class="label">Session ID</div>
    <div class="value" style="font-size:1em">{session.get('session_id','N/A')}</div>
  </div>
  <div class="meta-card">
    <div class="label">Scope</div>
    <div class="value" style="font-size:1em">{session.get('scope','Full target')}</div>
  </div>
  <div class="meta-card">
    <div class="label">Critical / High</div>
    <div class="value" style="color:#f85149">
      {counts.get('CRITICAL',0)} / {counts.get('HIGH',0)}
    </div>
  </div>
</div>

<div class="disclaimer">
  ⚠️ <strong>Legal Notice:</strong> This report was generated by RAJAN for
  <strong>authorized security testing only</strong>. All testing was performed
  within the defined scope with explicit permission.
</div>

<div class="section">
  <h2>📊 Risk Summary</h2>
  {risk_chart}
</div>

<div class="section">
  <h2>🔴 Findings ({len(findings)} total)</h2>
  {findings_html if findings_html else '<p style="color:#8b949e">No confirmed vulnerabilities found.</p>'}
</div>

<div class="section">
  <h2>🔍 Intelligence Gathered</h2>
  {intel_html if intel_html else '<p style="color:#8b949e">No intel recorded.</p>'}
</div>

<div class="section">
  <h2>📋 Methodology</h2>
  <p>This assessment followed a structured approach:</p>
  <ol style="margin-top:15px;padding-left:20px;line-height:2">
    <li>Passive Reconnaissance (DNS, WHOIS, OSINT, Google dorking)</li>
    <li>Active Scanning (Port scan, service detection, web fingerprinting)</li>
    <li>Web Application Testing (XSS, SQLi, IDOR, SSRF, LFI, auth bypass)</li>
    <li>API & Cloud Security (S3 buckets, metadata API, JWT)</li>
    <li>Exploit Validation (CVE matching, PoC confirmation)</li>
    <li>Report Generation (this document)</li>
  </ol>
</div>

<div class="footer">
  <p><strong>RAJAN — AI Ethical Hacking Agent</strong></p>
  <p style="margin-top:8px">
    <a href="https://github.com/DHRUVIL-5/RAJAN" style="color:#58a6ff">
      github.com/DHRUVIL-5/RAJAN
    </a>
  </p>
  <p style="margin-top:8px;font-size:0.85em">Generated: {date}</p>
</div>

</body>
</html>"""
    return html


def generate_markdown_report(session, findings, intel, counts, llm=None):
    date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    target = session.get("target", "Unknown")
    mitre = MITREMapper()

    sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}

    # Executive summary
    if llm and findings:
        exec_summary = llm.quick_ask(
            f"Write a 3-sentence executive summary for a penetration test on {target}. "
            f"Findings include: {[f['title'] for f in findings[:5]]}. Be professional."
        )
    else:
        exec_summary = (
            f"Security assessment of {target} completed on {date}. "
            f"A total of {len(findings)} vulnerabilities were identified. "
            f"Immediate remediation is recommended for Critical and High severity findings."
        )

    md = f"""# 🔐 RAJAN Penetration Test Report

> **Generated by RAJAN — AI Ethical Hacking Agent**
> github.com/DHRUVIL-5/RAJAN

---

## 📋 Executive Summary

**Target:** `{target}`
**Date:** {date}
**Session ID:** {session.get('session_id','N/A')}
**Scope:** {session.get('scope','Full target')}

{exec_summary}

---

## 📊 Risk Summary

| Severity | Count | CVSS Range |
|----------|-------|------------|
| 🔴 Critical | {counts.get('CRITICAL',0)} | 9.0 – 10.0 |
| 🟠 High | {counts.get('HIGH',0)} | 7.0 – 8.9 |
| 🟡 Medium | {counts.get('MEDIUM',0)} | 4.0 – 6.9 |
| 🟢 Low | {counts.get('LOW',0)} | 0.1 – 3.9 |
| **Total** | **{len(findings)}** | |

---

## 🔴 Findings

"""
    if not findings:
        md += "_No confirmed vulnerabilities were found during this assessment._\n\n"
    else:
        for i, f in enumerate(findings, 1):
            sev = f["severity"].upper()
            emoji = sev_emoji.get(sev, "⚪")
            mitre_id = f.get("mitre_technique", "")
            mitre_info = mitre.get_technique(mitre_id)
            remediation = mitre_info["mitigation"] if mitre_info else "Follow OWASP guidelines."

            md += f"""### {i}. {f['title']} {emoji}

| Field | Detail |
|-------|--------|
| **Severity** | {sev} |
| **Location** | `{f.get('location','N/A')}` |
| **MITRE ATT&CK** | [{mitre_id}]({f'https://attack.mitre.org/techniques/{mitre_id.replace(".","/")}'}) |
| **Found at** | {f.get('found_at','N/A')} |

**Description:** {f['description']}

**Proof/PoC:** `{f.get('proof','N/A')}`

**Remediation:** {remediation}

---

"""

    md += """## 🔍 Intelligence Gathered

"""
    intel_by_type = {}
    for row in intel:
        if len(row) == 5:
            _, itype, key, value, _ = row
        else:
            itype, key, value = row
        intel_by_type.setdefault(itype, []).append(f"| `{key}` | `{value[:80]}` |")

    for itype, rows in intel_by_type.items():
        md += f"### {itype.upper()}\n\n| Key | Value |\n|-----|-------|\n"
        md += "\n".join(rows[:15])
        md += "\n\n"

    md += f"""---

## 📋 Methodology

1. **Reconnaissance** — DNS, WHOIS, subdomain discovery, OSINT
2. **Scanning** — Port scan, service detection, web fingerprinting
3. **Web Testing** — XSS, SQLi, IDOR, SSRF, auth bypass, JS analysis
4. **Cloud & SSL** — S3 buckets, metadata API, TLS configuration
5. **Exploit Research** — CVE matching, vulnerability validation
6. **Reporting** — This document

---

## ⚠️ Legal Disclaimer

> This report was generated by **RAJAN** for authorized security testing only.
> All testing was performed within the defined scope with explicit permission.
> Unauthorized use of these findings is illegal and unethical.

---

*RAJAN v1.0.0 — AI Ethical Hacking Agent*
*github.com/DHRUVIL-5/RAJAN | Generated: {date}*
"""
    return md


def save_reports(session, findings, intel, counts, llm=None):
    """Save both HTML and MD reports, return filenames"""
    os.makedirs("reports", exist_ok=True)
    target = session.get("target", "target")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"reports/report_{target}_{timestamp}"

    # Markdown
    md_content = generate_markdown_report(session, findings, intel, counts, llm)
    md_file = f"{base}.md"
    with open(md_file, "w", encoding="utf-8") as f:
        f.write(md_content)

    # HTML
    html_content = generate_html_report(session, findings, intel, counts)
    html_file = f"{base}.html"
    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    return md_file, html_file
