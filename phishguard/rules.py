"""Rule-based heuristic engine (12 weighted rules, score 0-100).

This is the explainable half of PhishGuard: every rule that fires comes with a
plain-English reason. It is also reused by the feature extractor.
"""

import ipaddress
import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country",
    "work", "zip", "mov", "icu", "buzz", "rest", "support", "loan",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
}

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "update", "secure", "account",
    "banking", "confirm", "password", "suspend", "unlock", "wallet",
    "invoice", "payment", "billing", "recover", "authenticate",
]

BRANDS = [
    "paypal", "microsoft", "office365", "google", "apple", "amazon",
    "netflix", "facebook", "instagram", "linkedin", "dropbox",
    "docusign", "chase", "wellsfargo", "bankofamerica", "dhl", "fedex",
]

TWO_PART_SUFFIXES = {
    "co.uk", "com.au", "co.in", "com.np", "co.jp", "com.br", "org.uk",
    "com.cn", "co.za", "com.mx", "co.kr", "com.tr", "com.sg", "ac.in",
}

LEET_MAP = str.maketrans(
    {"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t", "$": "s"}
)

MAX_SUBDOMAINS = 3
MAX_URL_LENGTH = 75
MAX_HYPHENS = 3

LOW_THRESHOLD = 25
HIGH_THRESHOLD = 50


def normalize(url: str) -> str:
    """Add a scheme if missing so urlparse works correctly."""
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def split_host(host: str):
    """Return (subdomain labels, registered-domain label, tld)."""
    labels = host.lower().split(".")
    if len(labels) < 2:
        return [], host.lower(), ""
    last_two = ".".join(labels[-2:])
    if last_two in TWO_PART_SUFFIXES and len(labels) >= 3:
        return labels[:-3], labels[-3], last_two
    return labels[:-2], labels[-2], labels[-1]


def registered_domain(host: str) -> str:
    """Return e.g. 'example.com' or 'example.co.uk' for a hostname."""
    _, label, tld = split_host(host)
    return f"{label}.{tld}" if tld else label


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def defang(url: str) -> str:
    """Make a URL safe to paste into tickets: hxxp://example[.]com"""
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def refang(url: str) -> str:
    return url.replace("hxxp", "http", 1).replace("[.]", ".")


def risk_from_score(score: int) -> str:
    if score >= HIGH_THRESHOLD:
        return "HIGH"
    if score >= LOW_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def parse(raw_url: str):
    """Return (normalized_url, ParseResult, host) or raise ValueError."""
    url = normalize(raw_url)
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        _ = parsed.port  # raises ValueError on a bad port
    except ValueError as exc:
        raise ValueError("Could not parse URL") from exc
    if not host:
        raise ValueError("No hostname found")
    return url, parsed, host


def run_rules(raw_url: str) -> dict:
    """Run all 12 rules. Returns {'score', 'risk', 'findings': [(pts, msg)]}.

    Raises ValueError if the URL cannot be parsed.
    """
    url, parsed, host = parse(raw_url)
    findings = []

    path_query = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")

    host_is_ip = is_ip(host)
    if host_is_ip:
        findings.append((30, "Host is a raw IP address instead of a domain name"))

    subdomains, reg_label, tld = ([], host, "") if host_is_ip else split_host(host)

    if len(subdomains) > MAX_SUBDOMAINS:
        findings.append((15, f"Excessive subdomains ({len(subdomains)} levels): "
                             f"often used to bury the real domain"))

    if tld in SUSPICIOUS_TLDS:
        findings.append((15, f"Suspicious top-level domain: .{tld}"))

    if "@" in parsed.netloc:
        findings.append((25, "Contains '@' in the authority section, "
                             "which can hide the real destination"))

    if host in URL_SHORTENERS:
        findings.append((15, f"URL shortener ({host}) hides the final destination"))

    hits = [k for k in PHISHING_KEYWORDS if k in (host + path_query).lower()]
    if hits:
        findings.append((min(10 * len(hits), 20),
                         "Credential-harvesting keywords: " + ", ".join(hits)))

    if len(url) > MAX_URL_LENGTH:
        findings.append((10, f"Very long URL ({len(url)} characters)"))

    if host.count("-") >= MAX_HYPHENS:
        findings.append((10, f"Many hyphens in hostname ({host.count('-')})"))

    if "xn--" in host:
        findings.append((20, "Punycode domain (xn--): possible lookalike/homograph attack"))

    if not host_is_ip:
        for label in [reg_label] + subdomains:
            done = False
            for part in label.split("-"):
                swapped = part.translate(LEET_MAP)
                if swapped != part and swapped in BRANDS:
                    findings.append((20, f"Lookalike of brand '{swapped}' using "
                                         f"character substitution ('{part}')"))
                    done = True
                    break
            if done:
                break

    if parsed.scheme != "https":
        findings.append((10, f"Does not use HTTPS (scheme: {parsed.scheme})"))

    if not host_is_ip:
        for brand in BRANDS:
            present = brand in host or brand in path_query.lower()
            if present and brand not in reg_label:
                findings.append((25, f"Brand '{brand}' appears in the URL but the real "
                                     f"domain is '{reg_label}.{tld}'"))
                break

    if "//" in parsed.path:
        findings.append((10, "Double slash in path, possible redirect trick"))

    if parsed.port and parsed.port not in (80, 443):
        findings.append((10, f"Non-standard port: {parsed.port}"))

    score = min(sum(p for p, _ in findings), 100)
    return {"score": score, "risk": risk_from_score(score), "findings": findings}
