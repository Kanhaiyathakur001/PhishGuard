from phishguard.detector import analyze
from phishguard.model import load_model

needs_model = load_model() is not None


def test_empty_and_invalid():
    assert analyze("")["risk"] == "INVALID"
    assert analyze("http://")["risk"] == "INVALID"
    assert analyze("a" * 3000)["risk"] == "INVALID"


def test_result_shape():
    r = analyze("https://www.google.com/")
    for k in ("url", "url_defanged", "valid", "risk", "score", "findings", "rule_score"):
        assert k in r
    assert 0 <= r["score"] <= 100


def test_defanged_output():
    r = analyze("http://evil.example.xyz/login")
    assert "hxxp://" in r["url_defanged"] and "[.]" in r["url_defanged"]


def test_falls_back_to_rules_without_model(monkeypatch):
    from phishguard import model as m
    monkeypatch.setattr(m, "predict_proba", lambda *a, **k: None)
    r = analyze("http://paypa1-login.secure.example.xyz/verify")
    assert r["mode"] == "rules-only" and r["ml_probability"] is None
    assert r["score"] == r["rule_score"] and r["risk"] == "HIGH"


def test_phishing_vs_legit_ordering():
    bad = analyze("http://paypa1-secure-login.verify-account.example.xyz/signin/confirm.php?id=8f3a9c2b7d1e4f60a5b8")
    good = analyze("https://www.wikipedia.org/")
    assert bad["score"] > good["score"]
    assert bad["risk"] in ("MEDIUM", "HIGH") and good["risk"] == "LOW"


def test_hybrid_mode_when_model_present():
    if not needs_model:
        return
    r = analyze("https://www.wikipedia.org/")
    assert r["mode"].startswith("hybrid") and 0 <= r["ml_probability"] <= 1
    assert len(r["signals"]) == 5


# ---- popularity allowlist ---------------------------------------------------
import pytest  # noqa: E402

from phishguard.trust import is_trusted  # noqa: E402

REAL_LEGIT = [
    "https://github.com/anthropics/claude-code/issues/1234",
    "https://www.paypal.com/signin",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://accounts.google.com/signin/v2/identifier?service=mail&continue=https%3A%2F%2Fmail.google.com",
    "https://www.amazon.in/dp/B0C1234567/ref=sr_1_1?keywords=laptop&qid=1699999999",
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc",
    "https://www.sbi.co.in/web/personal-banking",
    "https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster",
]
REAL_PHISH = [
    "http://secure-paypal-update.com/login.php",
    "http://amaz0n-account-verify.top/signin",
    "http://185.234.12.9/wp-includes/secure/office365/login.html",
    "https://netflix.com.billing-update.work/account",
    "http://appleid.apple.com.verify-id.icu/confirm",
    "https://sites.google.com/view/metamask-wallet-recover/home",
]


@pytest.mark.skipif(not needs_model, reason="model not trained")
@pytest.mark.parametrize("url", REAL_LEGIT)
def test_known_legit_sites_are_low(url):
    assert analyze(url)["risk"] == "LOW"


@pytest.mark.skipif(not needs_model, reason="model not trained")
@pytest.mark.parametrize("url", REAL_PHISH)
def test_known_phishing_patterns_are_high(url):
    assert analyze(url)["risk"] == "HIGH"


def test_allowlist_matches_registered_domain_only():
    assert is_trusted("www.paypal.com")
    assert not is_trusted("paypal.com.evil.xyz")      # registered domain is evil.xyz
    assert not is_trusted("paypal-login.example-phish.xyz")
    assert not is_trusted("192.168.1.1")


def test_user_content_platforms_never_trusted():
    for host in ("sites.google.com", "someone.github.io", "foo.blogspot.com",
                 "x.workers.dev", "bucket.s3.amazonaws.com"):
        assert not is_trusted(host), host


def test_trusted_flag_in_result():
    assert analyze("https://www.wikipedia.org/")["trusted_domain"] is True
    assert analyze("http://wikipedia.org.evil-site.xyz/")["trusted_domain"] is False
