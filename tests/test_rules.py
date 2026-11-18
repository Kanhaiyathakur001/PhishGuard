import pytest

from phishguard.rules import defang, refang, risk_from_score, run_rules, split_host


def pts(url):
    return {msg.split(":")[0].split(" (")[0]: p for p, msg in run_rules(url)["findings"]}


def msgs(url):
    return " ".join(m for _, m in run_rules(url)["findings"])


def test_clean_https_site_is_low():
    r = run_rules("https://www.wikipedia.org/")
    assert r["score"] == 0 and r["risk"] == "LOW"


def test_ip_host():
    assert "raw IP" in msgs("http://192.168.1.10/index.html")


def test_at_symbol():
    assert "'@'" in msgs("https://google.com@evil.example.net/")


def test_suspicious_tld():
    assert "Suspicious top-level domain: .xyz" in msgs("https://example.xyz")


def test_shortener():
    assert "shortener" in msgs("https://bit.ly/abc")


def test_excess_subdomains():
    assert "Excessive subdomains" in msgs("https://a.b.c.d.example.com")


def test_keywords_capped_at_20():
    r = run_rules("https://example.com/login/verify/secure/account")
    kw = [p for p, m in r["findings"] if "keywords" in m][0]
    assert kw == 20


def test_leet_lookalike():
    assert "paypal" in msgs("https://paypa1.com/") and "substitution" in msgs("https://paypa1.com/")


def test_brand_on_wrong_domain():
    assert "Brand 'paypal'" in msgs("https://paypal.evil-site.net/login")


def test_real_brand_domain_not_flagged():
    assert "Brand" not in msgs("https://www.paypal.com/signin")


def test_punycode_and_port_and_double_slash():
    m = msgs("http://xn--pple-43d.com:8080//a")
    assert "Punycode" in m and "Non-standard port: 8080" in m and "Double slash" in m


def test_http_penalty():
    assert "Does not use HTTPS" in msgs("http://example.com")


def test_classic_phish_is_high():
    r = run_rules("http://paypa1-login.secure.example.xyz/verify")
    assert r["risk"] == "HIGH" and r["score"] >= 50


def test_two_part_suffix():
    assert split_host("shop.example.co.uk") == (["shop"], "example", "co.uk")


@pytest.mark.parametrize("bad", ["", "http://", "http://host:notaport/"])
def test_unparsable_raises(bad):
    with pytest.raises(ValueError):
        run_rules(bad)


def test_defang_roundtrip():
    u = "http://example.com/a"
    assert defang(u) == "hxxp://example[.]com/a" and refang(defang(u)) == u


def test_thresholds():
    assert [risk_from_score(s) for s in (0, 24, 25, 49, 50, 100)] == \
        ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH"]
