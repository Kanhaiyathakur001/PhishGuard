"""Lexical / host-based feature extraction for the ML model.

All features are computed from the URL string alone (no network access, no page
download), so analysing a URL is safe and fast.
"""

import math
import re
from collections import Counter

from .rules import (BRANDS, LEET_MAP, PHISHING_KEYWORDS, SUSPICIOUS_TLDS,
                    URL_SHORTENERS, is_ip, parse, split_host)

FEATURE_NAMES = [
    "url_length", "host_length", "path_length", "query_length",
    "dot_count", "hyphen_count", "underscore_count", "slash_count",
    "digit_count", "digit_ratio", "letter_ratio", "special_char_count",
    "at_symbol", "double_slash_in_path", "has_port", "nonstandard_port",
    "is_https", "is_ip_host", "subdomain_count", "tld_length",
    "suspicious_tld", "is_shortener", "keyword_count", "brand_in_url",
    "brand_not_registered_domain", "leet_brand", "has_punycode",
    "host_digit_count", "host_hyphen_count", "host_entropy", "path_entropy",
    "path_depth", "param_count", "longest_token_length", "has_long_hex_token",
    "has_file_extension", "reg_domain_length",
]

_TOKEN_SPLIT = re.compile(r"[^a-zA-Z0-9]+")
_HEX_TOKEN = re.compile(r"[0-9a-f]{16,}")
_FILE_EXT = re.compile(r"\.(php|html?|asp|aspx|jsp|cgi|exe|zip)$", re.I)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract_features(raw_url: str) -> dict:
    """Return an ordered dict {feature_name: float}. Raises ValueError if unparsable."""
    url, parsed, host = parse(raw_url)
    path = parsed.path or ""
    query = parsed.query or ""
    path_query = (path + ("?" + query if query else "")).lower()
    low = url.lower()

    host_is_ip = is_ip(host)
    subs, reg_label, tld = ([], host, "") if host_is_ip else split_host(host)

    letters = sum(ch.isalpha() for ch in url)
    digits = sum(ch.isdigit() for ch in url)
    n = max(len(url), 1)

    brand_anywhere = any(b in host or b in path_query for b in BRANDS)
    brand_off_domain = (not host_is_ip) and any(
        (b in host or b in path_query) and b not in reg_label for b in BRANDS)
    leet = False
    if not host_is_ip:
        for label in [reg_label] + subs:
            for part in label.split("-"):
                swapped = part.translate(LEET_MAP)
                if swapped != part and swapped in BRANDS:
                    leet = True

    tokens = [t for t in _TOKEN_SPLIT.split(low) if t]
    port = parsed.port

    feats = {
        "url_length": len(url),
        "host_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "underscore_count": url.count("_"),
        "slash_count": url.count("/"),
        "digit_count": digits,
        "digit_ratio": digits / n,
        "letter_ratio": letters / n,
        "special_char_count": sum(not ch.isalnum() for ch in url),
        "at_symbol": int("@" in parsed.netloc),
        "double_slash_in_path": int("//" in path),
        "has_port": int(port is not None),
        "nonstandard_port": int(port is not None and port not in (80, 443)),
        "is_https": int(parsed.scheme == "https"),
        "is_ip_host": int(host_is_ip),
        "subdomain_count": len(subs),
        "tld_length": len(tld),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "is_shortener": int(host in URL_SHORTENERS),
        "keyword_count": sum(k in (host + path_query) for k in PHISHING_KEYWORDS),
        "brand_in_url": int(brand_anywhere),
        "brand_not_registered_domain": int(brand_off_domain),
        "leet_brand": int(leet),
        "has_punycode": int("xn--" in host),
        "host_digit_count": sum(ch.isdigit() for ch in host),
        "host_hyphen_count": host.count("-"),
        "host_entropy": shannon_entropy(host),
        "path_entropy": shannon_entropy(path_query),
        "path_depth": len([p for p in path.split("/") if p]),
        "param_count": len([p for p in query.split("&") if p]),
        "longest_token_length": max((len(t) for t in tokens), default=0),
        "has_long_hex_token": int(bool(_HEX_TOKEN.search(low))),
        "has_file_extension": int(bool(_FILE_EXT.search(path))),
        "reg_domain_length": len(reg_label),
    }
    return {name: float(feats[name]) for name in FEATURE_NAMES}


def feature_vector(raw_url: str):
    f = extract_features(raw_url)
    return [f[n] for n in FEATURE_NAMES]
