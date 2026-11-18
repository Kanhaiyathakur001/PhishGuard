"""Hybrid detector: ML probability + explainable rule score.

combined_score = 0.7 * (ML probability * 100) + 0.3 * rule_score   (if a model exists)
combined_score = rule_score                                         (rules-only fallback)

Popularity allowlist: if the registered domain is one of the 20k most popular
domains (and not a user-content platform, see trust.py) and the rules score is
below 50, the combined score is capped at 20 (LOW). URL text alone cannot tell
that paypal.com/signin is the real PayPal; a reputation list can.

Risk bands: 0-24 LOW, 25-49 MEDIUM, 50+ HIGH.
"""

from . import model as ml
from .rules import defang, parse, risk_from_score, run_rules
from .trust import is_trusted

ML_WEIGHT = 0.7
RULE_WEIGHT = 0.3


def analyze(raw_url: str, model=None) -> dict:
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

    prob = ml.predict_proba(raw_url, model)
    if prob is None:
        score, mode = rules["score"], "rules-only"
    else:
        score = round(ML_WEIGHT * prob * 100 + RULE_WEIGHT * rules["score"])
        mode = "hybrid"

    trusted = is_trusted(parse(raw_url)[2])
    if trusted and rules["score"] < 50:
        score = min(score, 20)
        mode += "+allowlist"

    return {
        **base,
        "valid": True,
        "trusted_domain": trusted,
        "mode": mode,
        "score": int(min(score, 100)),
        "risk": risk_from_score(score),
        "ml_probability": None if prob is None else round(prob, 4),
        "rule_score": rules["score"],
        "rule_risk": rules["risk"],
        "findings": [f"(+{p}) {msg}" for p, msg in rules["findings"]],
        "signals": ml.top_signals(raw_url, model) if prob is not None else [],
    }
