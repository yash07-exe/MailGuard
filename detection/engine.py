
"""MailGuard Email Phishing Detection Engine"""

import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "urgent", "verify your account", "password",
    "suspended", "click here", "bank details",
    "confirm your identity", "limited time"
]


def analyze_email(sender="", subject="", body=""):
    text = f"{sender} {subject} {body}".lower()

    score = 0
    reasons = []

    # Check suspicious words
    for word in SUSPICIOUS_WORDS:
        if word in text:
            score += 10
            reasons.append(f"Suspicious phrase detected: {word}")

    # Extract URLs
    urls = re.findall(r'https?://[^\s<>"\']+', body)

    for url in urls:
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or ""

            if parsed.scheme != "https":
                score += 10
                reasons.append("URL does not use HTTPS")

            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
                score += 25
                reasons.append("URL uses an IP address")

            if len(domain) > 40:
                score += 10
                reasons.append("Unusually long domain")

        except ValueError:
            score += 10
            reasons.append("Malformed URL")

    score = min(score, 100)

    if score >= 70:
        risk = "Critical"
    elif score >= 40:
        risk = "High"
    elif score >= 20:
        risk = "Moderate"
    else:
        risk = "Low"

    risk_level = f"{risk} Risk"
    indicator_risk = {
        "Low": "low",
        "Moderate": "medium",
        "High": "high",
        "Critical": "high",
    }[risk]
    return {
        "sender": sender,
        "subject": subject,
        "score": score,
        "risk": risk,
        "risk_score": score,
        "risk_level": risk_level,
        "classification": risk_level,
        "indicators": [
            {"type": reason, "risk": indicator_risk}
            for reason in reasons
        ],
        "authentication": {},
        "analysis": {
            "link_analysis": [
                {"description": url}
                for url in urls
            ]
        },
        "reasons": reasons,
        "urls": urls,
        "is_phishing": score >= 40
    }
