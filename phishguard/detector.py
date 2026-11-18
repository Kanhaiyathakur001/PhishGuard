"""Detector: explainable rule score + popularity allowlist.

    raw_score = sum of the points of every rule that fires (0-100, see rules.py)

Popularity allowlist: if the registered domain is one of the 20,000 most popular
domains (and not a user-content platform, see trust.py) and raw_score is below
50, the final score is capped at 20 (LOW). URL text alone cannot tell that
paypal.com/signin is the real PayPal; a reputation list can.

Risk bands: 0-24 LOW, 25-49 MEDIUM, 50+ HIGH.

No network request is ever made: the URL is analysed purely as text.
"""

from .rules import defang, parse, risk_from_score, run_rules
from .trust import is_trusted

ALLOWLIST_CAP = 20      # final score cap for trusted domains
ALLOWLIST_BYPASS = 50   # rules at/above this score override the allowlist


def analyze(raw_url: str) -> dict:
    """Analyse one URL. Never makes a network request."""
    raw_url = (raw_url or "").strip()
    base = {"url": raw_url, "url_defanged": defang(raw_url)}
    if not raw_url:
        return {**base, "valid": False, "risk": "INVALID", "score": 0,
                "error": "Empty URL", "findings": []}
    if len(raw_url) > 2048:
        return {**base, "valid": False, "risk": "INVALID", "score": 0,
                "error": "URL too long (max 2048 characters)", "findings": []}
    try:
        rules = run_rules(raw_url)
    except ValueError as exc:
        return {**base, "valid": False, "risk": "INVALID", "score": 0,
                "error": str(exc), "findings": []}

    score = rules["score"]
    trusted = is_trusted(parse(raw_url)[2])
    # allowlist_applied is True only when the allowlist actually lowered the score
    allowlist_applied = trusted and ALLOWLIST_CAP < score < ALLOWLIST_BYPASS
    if trusted and score < ALLOWLIST_BYPASS:
        score = min(score, ALLOWLIST_CAP)

    return {
        **base,
        "valid": True,
        "trusted_domain": trusted,
        "allowlist_applied": allowlist_applied,
        "score": int(min(score, 100)),
        "risk": risk_from_score(score),
        "rule_score": rules["score"],      # before the allowlist
        "findings": [f"(+{p}) {msg}" for p, msg in rules["findings"]],
    }
