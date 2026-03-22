"""
RAJAN Confidence & Scoring System
Every finding gets: confidence level, CVSS-style score, reliability rating.
Needed for real-world bug bounty — removes false positives.
"""


# CVSS-style base scores per vulnerability type
VULN_BASE_SCORES = {
    "rce":              10.0,
    "remote code":      10.0,
    "log4shell":        10.0,
    "eternalblue":      9.8,
    "sql injection":    9.0,
    "sqli":             9.0,
    "ssrf":             8.5,
    "cloud metadata":   9.5,
    "s3 bucket":        8.5,
    "xss stored":       8.0,
    "xss":              7.0,
    "reflected xss":    7.0,
    "idor":             7.5,
    "path traversal":   7.5,
    "lfi":              7.5,
    "ssti":             9.5,
    "command injection":9.5,
    "xxe":              8.0,
    "open redirect":    5.5,
    "csrf":             6.0,
    "default cred":     9.0,
    "default password": 9.0,
    "git exposed":      8.5,
    ".git":             8.5,
    "secret":           8.5,
    "api key":          8.5,
    "missing header":   3.0,
    "ssl":              5.0,
    "tls":              5.0,
    "weak cipher":      6.0,
    "subdomain":        4.0,
    "chain":            10.0,
}

# How confidence maps to a label
CONFIDENCE_LABELS = {
    (90, 100): ("CONFIRMED",  "✅", "Verified with proof-of-concept"),
    (70,  89): ("HIGH",       "🟢", "Strong evidence, likely real"),
    (50,  69): ("MEDIUM",     "🟡", "Indicative, needs manual verification"),
    (30,  49): ("LOW",        "🟠", "Possible false positive"),
    (0,   29): ("UNVERIFIED", "⚠️ ", "Needs manual investigation"),
}


def get_confidence_label(score):
    for (lo, hi), (label, icon, desc) in CONFIDENCE_LABELS.items():
        if lo <= score <= hi:
            return label, icon, desc
    return "UNVERIFIED", "⚠️ ", "Needs manual investigation"


def score_finding(title, description, proof="", has_poc=False):
    """
    Calculate confidence score (0-100) and CVSS-style base score for a finding.
    Returns dict with all scoring details.
    """
    title_lower = (title + " " + description).lower()

    # Base CVSS score from vulnerability type
    cvss = 5.0  # default medium
    for keyword, score in VULN_BASE_SCORES.items():
        if keyword in title_lower:
            cvss = score
            break

    # Confidence score starts at base
    confidence = 50

    # Boost confidence if we have proof
    if proof and len(proof) > 5:
        confidence += 25
    if has_poc:
        confidence += 15

    # Boost for strong evidence keywords
    strong_evidence = [
        "confirmed", "verified", "response contains", "reflected in",
        "triggered", "delay", "seconds", "listing files", "passwd",
        "error in your sql", "instance-id", "ami-id",
    ]
    for kw in strong_evidence:
        if kw in (proof + description).lower():
            confidence += 10
            break

    # Reduce for uncertain language
    uncertain = ["potential", "possible", "candidate", "may be", "could be"]
    for kw in uncertain:
        if kw in title_lower:
            confidence -= 15
            break

    # Cap between 0 and 100
    confidence = max(0, min(100, confidence))
    label, icon, desc = get_confidence_label(confidence)

    # Reliability rating (based on testing method)
    if has_poc:
        reliability = "HIGH"
    elif proof and len(proof) > 10:
        reliability = "MEDIUM"
    else:
        reliability = "LOW"

    # Map CVSS to severity
    if cvss >= 9.0:
        severity = "CRITICAL"
    elif cvss >= 7.0:
        severity = "HIGH"
    elif cvss >= 4.0:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "cvss_score":        round(cvss, 1),
        "confidence_score":  confidence,
        "confidence_label":  label,
        "confidence_icon":   icon,
        "confidence_desc":   desc,
        "reliability":       reliability,
        "severity":          severity,
    }


def format_score_badge(scoring):
    """Returns a one-line badge string for log output"""
    return (
        f"CVSS:{scoring['cvss_score']} | "
        f"Confidence:{scoring['confidence_score']}% [{scoring['confidence_label']}] | "
        f"Reliability:{scoring['reliability']}"
    )


class ScoringEngine:
    """Wrapper used by agents to score and enrich findings before saving"""

    def enrich_finding(self, title, severity, description, proof="", has_poc=False):
        """
        Returns enriched finding dict with confidence + scoring attached.
        Agents call this before add_finding().
        """
        scoring = score_finding(title, description, proof, has_poc)

        # Override severity from CVSS if higher
        sev_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        cvss_sev = scoring["severity"]
        if sev_rank.get(cvss_sev, 0) > sev_rank.get(severity, 0):
            final_severity = cvss_sev
        else:
            final_severity = severity

        enriched_proof = proof
        if proof:
            enriched_proof = (
                f"{proof}\n"
                f"[Score] CVSS:{scoring['cvss_score']} | "
                f"Confidence:{scoring['confidence_score']}% "
                f"({scoring['confidence_label']}) | "
                f"Reliability:{scoring['reliability']}"
            )

        return {
            "title":       title,
            "severity":    final_severity,
            "description": description,
            "proof":       enriched_proof,
            "scoring":     scoring,
        }
