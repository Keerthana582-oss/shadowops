import json
import random

# FREE MODE: this file returns realistic fake AI responses instead of
# calling the real Anthropic API. Swap back to real calls later by
# restoring the original llm_engine.py once you have API credits.

FAKE_SEVERITIES = ["low", "medium", "high", "critical"]
FAKE_CATEGORIES = [
    "brute force", "data exfiltration", "privilege escalation",
    "malware C2", "ransomware", "account compromise"
]


def triage(alert: dict) -> dict:
    rule_name = alert.get("rule_name", "Unknown Alert")
    host = alert.get("host", "unknown-host")

    severity = random.choice(FAKE_SEVERITIES)
    category = random.choice(FAKE_CATEGORIES)

    return {
        "summary": f"[MOCK] Detected '{rule_name}' on {host}. This looks like a {category} pattern based on the alert details.",
        "severity": severity,
        "attack_category": category,
        "confidence": "medium",
    }


def recommend_playbook(incident_summary: str, severity: str, attack_category: str) -> list:
    return [
        {
            "description": "Add IP to watchlist",
            "risk_tier": "low",
            "reversible": True,
            "rationale": "[MOCK] Low-risk monitoring step, safe to auto-execute."
        },
        {
            "description": "Tag host for monitoring",
            "risk_tier": "low",
            "reversible": True,
            "rationale": "[MOCK] Increases visibility without disrupting operations."
        },
        {
            "description": f"Isolate affected host due to {attack_category}",
            "risk_tier": "high",
            "reversible": False,
            "rationale": "[MOCK] High-impact action, requires human approval."
        },
        {
            "description": "Notify on-call channel",
            "risk_tier": "low",
            "reversible": True,
            "rationale": "[MOCK] Keeps the team informed without side effects."
        },
    ]