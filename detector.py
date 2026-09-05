"""
Rule-Based Phishing Email Detection System
Emith Sudusinghe / E194040
"""

import re
from urllib.parse import urlparse


# ─────────────────────────────────────────────
# RULE DEFINITIONS
# Each rule has: name, category, weight, pattern/logic, tip
# ─────────────────────────────────────────────

URGENCY_KEYWORDS = [
    "immediate action", "act now", "account locked", "account suspended",
    "account will be suspended", "24 hours", "48 hours", "urgent",
    "immediately", "right away", "expires today", "limited time",
    "unauthorized access", "security alert", "unusual activity",
    "verify immediately", "action required", "permanently locked",
]

SENSITIVE_INFO_KEYWORDS = [
    "password", "credit card", "card number", "ssn", "social security",
    "bank account", "account number", "date of birth", "billing info",
    "confirm your details", "verify your identity", "personal information",
    "pin number", "cvv", "security code",
]

GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear account holder",
    "dear valued customer", "dear member", "hello customer",
    "dear sir", "dear madam", "to whom it may concern",
]

SUSPICIOUS_DOMAINS = [
    "secure-", "-secure", "verify-", "-verify", "update-", "-update",
    "login-", "-login", "account-", "-account", "banking-", "paypal-",
    "apple-", "amazon-", "microsoft-", "google-",
]

TRUSTED_BRANDS = [
    "paypal", "apple", "amazon", "microsoft", "google", "bank",
    "netflix", "facebook", "instagram", "ebay", "dhl", "fedex",
]


def extract_urls(text):
    """Extract all URLs from email text."""
    url_pattern = re.compile(
        r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
        re.IGNORECASE
    )
    return url_pattern.findall(text)


def extract_html_links(text):
    """Extract (display_text, href) pairs from anchor tags."""
    anchor_pattern = re.compile(
        r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
        re.IGNORECASE | re.DOTALL
    )
    return anchor_pattern.findall(text)


def check_link_discrepancy(text):
    """Check if displayed link text differs from actual href domain."""
    findings = []
    links = extract_html_links(text)

    for href, display in links:
        display_clean = re.sub(r'<[^>]+>', '', display).strip().lower()
        try:
            href_domain = urlparse(href).netloc.lower().replace("www.", "")
            display_domain = urlparse(display_clean if display_clean.startswith("http")
                                      else "http://" + display_clean).netloc.lower().replace("www.", "")

            if display_domain and href_domain and display_domain != href_domain:
                for brand in TRUSTED_BRANDS:
                    if brand in display_domain and brand not in href_domain:
                        findings.append({
                            "displayed": display_clean,
                            "actual": href,
                            "detail": f"Shows '{display_clean}' but links to '{href_domain}'"
                        })
                        break
        except Exception:
            pass

    # Also check plain-text URLs for suspicious domain patterns
    urls = extract_urls(text)
    for url in urls:
        domain = urlparse(url).netloc.lower()
        for pattern in SUSPICIOUS_DOMAINS:
            if pattern in domain:
                for brand in TRUSTED_BRANDS:
                    if brand in text.lower() and brand not in domain:
                        findings.append({
                            "displayed": brand,
                            "actual": url,
                            "detail": f"Suspicious domain pattern '{domain}' while referencing '{brand}'"
                        })
                        break

    return findings


def analyze_email(subject, body):
    """
    Main analysis function.
    Returns a detailed result dict with score, classification, and triggered rules.
    """
    full_text = (subject + " " + body).lower()
    triggered_rules = []
    total_score = 0

    # ── RULE 1: Urgency (weight: Low-Medium = 1-2 pts each) ──
    urgency_hits = []
    for kw in URGENCY_KEYWORDS:
        if kw in full_text:
            urgency_hits.append(kw)

    if urgency_hits:
        score = min(len(urgency_hits) * 1, 2)  # cap at 2
        total_score += score
        triggered_rules.append({
            "category": "Urgency Language",
            "weight": "Low–Medium",
            "score": score,
            "indicators": urgency_hits[:3],  # show top 3
            "tip": "Legitimate organisations rarely pressure you to act within hours. "
                   "If unsure, go directly to the company's official website — don't click links in the email."
        })

    # ── RULE 2: Sensitive Information Request (weight: High = 3 pts) ──
    sensitive_hits = []
    for kw in SENSITIVE_INFO_KEYWORDS:
        if kw in full_text:
            sensitive_hits.append(kw)

    if sensitive_hits:
        total_score += 3
        triggered_rules.append({
            "category": "Sensitive Information Request",
            "weight": "High",
            "score": 3,
            "indicators": sensitive_hits[:3],
            "tip": "No legitimate company will ask for your password, credit card number, "
                   "or SSN via email. Never provide this information through an email link."
        })

    # ── RULE 3: Link Discrepancy (weight: High = 3 pts) ──
    link_issues = check_link_discrepancy(body)
    if link_issues:
        total_score += 3
        triggered_rules.append({
            "category": "Link Discrepancy",
            "weight": "High",
            "score": 3,
            "indicators": [i["detail"] for i in link_issues[:2]],
            "tip": "The visible link text doesn't match where the link actually goes. "
                   "Always hover over links to see the real destination before clicking."
        })

    # ── RULE 4: Generic Greeting (weight: Low = 1 pt) ──
    greeting_hits = []
    for greet in GENERIC_GREETINGS:
        if greet in full_text:
            greeting_hits.append(greet)

    if greeting_hits:
        total_score += 1
        triggered_rules.append({
            "category": "Generic Greeting",
            "weight": "Low",
            "score": 1,
            "indicators": greeting_hits,
            "tip": "Legitimate companies that have your account usually address you by name. "
                   "Generic greetings are a common phishing tactic."
        })

    # ── CLASSIFICATION ──
    if total_score <= 2:
        classification = "Safe"
        color = "green"
        description = "This email appears clean. No significant phishing indicators detected."
    elif total_score <= 5:
        classification = "Suspicious"
        color = "orange"
        description = "This email shows some warning signs. Exercise caution before clicking links or replying."
    else:
        classification = "Phishing"
        color = "red"
        description = "This email shows strong phishing indicators. Do not click any links or provide any information."

    return {
        "score": total_score,
        "classification": classification,
        "color": color,
        "description": description,
        "triggered_rules": triggered_rules,
        "rules_checked": 4,
        "rules_triggered": len(triggered_rules),
    }


# ─────────────────────────────────────────────
# COMMAND LINE INTERFACE (for demo / testing)
# ─────────────────────────────────────────────

def cli_demo():
    print("\n" + "="*60)
    print("  PHISHING EMAIL DETECTOR — Emith Sudusinghe / E194040")
    print("="*60)
    print("\nPaste the email subject and body below.")
    print("Press Enter twice when done.\n")

    subject = input("Subject: ").strip()
    print("Body (press Enter twice when done):")

    lines = []
    while True:
        line = input()
        if line == "":
            if lines and lines[-1] == "":
                break
            lines.append(line)
        else:
            lines.append(line)

    body = "\n".join(lines).strip()
    result = analyze_email(subject, body)

    print("\n" + "="*60)
    print(f"  RESULT: {result['classification']}  (Score: {result['score']})")
    print("="*60)
    print(f"\n{result['description']}")

    if result["triggered_rules"]:
        print(f"\n⚠  {result['rules_triggered']} rule(s) triggered:\n")
        for rule in result["triggered_rules"]:
            print(f"  [{rule['category']}]  Weight: {rule['weight']}  +{rule['score']} pts")
            print(f"    Indicators: {', '.join(rule['indicators'])}")
            print(f"    Tip: {rule['tip']}\n")
    else:
        print("\n✓  No phishing indicators detected.")

    print("="*60 + "\n")


if __name__ == "__main__":
    cli_demo()
