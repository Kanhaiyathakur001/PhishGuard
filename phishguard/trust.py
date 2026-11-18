"""Popularity allowlist ("trusted domains").

Pure URL-text ML models cannot know that paypal.com/signin is the *real* PayPal.
Production systems therefore combine ML with a reputation list. PhishGuard uses
the top 20,000 most popular domains (data/top_domains.txt).

Safety rules:
* The match is on the *registered domain* only, so 'paypal.com.evil.xyz' (whose
  registered domain is evil.xyz) is NOT trusted.
* Platforms where anyone can publish a page (github.io, blogspot.com,
  sites.google.com, S3, workers.dev ...) are never trusted, even though they are
  popular, because attackers host phishing pages on them.
"""

from pathlib import Path

from .rules import is_ip, registered_domain

TOP_DOMAINS_PATH = Path(__file__).resolve().parent.parent / "data" / "top_domains.txt"

# Hosts where third parties can publish arbitrary content. Matched as host suffix.
USER_CONTENT_SUFFIXES = (
    "github.io", "githubusercontent.com", "blogspot.com", "blogger.com",
    "weebly.com", "wixsite.com", "wordpress.com", "tumblr.com", "medium.com",
    "sharepoint.com", "amazonaws.com", "cloudfront.net", "azurewebsites.net",
    "windows.net", "googleapis.com", "sites.google.com", "docs.google.com",
    "drive.google.com", "forms.gle", "googleusercontent.com", "notion.site",
    "typeform.com", "godaddysites.com", "myshopify.com", "webflow.io",
    "herokuapp.com", "netlify.app", "pages.dev", "workers.dev", "web.app",
    "firebaseapp.com", "glitch.me", "000webhostapp.com", "dweb.link", "ipfs.io",
    "canva.com", "mailchi.mp", "dropbox.com", "box.com", "bit.ly", "tinyurl.com",
    "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly", "weebly.com",
    "yolasite.com", "jimdofree.com", "square.site", "carrd.co", "000webhost.com",
)

_trusted = None


def _load():
    global _trusted
    if _trusted is None:
        try:
            _trusted = {l.strip() for l in open(TOP_DOMAINS_PATH, encoding="utf-8") if l.strip()}
        except OSError:
            _trusted = set()
    return _trusted


def is_trusted(host: str) -> bool:
    """True if host belongs to a popular domain that is not a user-content platform."""
    host = host.lower().rstrip(".")
    if not host or is_ip(host):
        return False
    if any(host == s or host.endswith("." + s) for s in USER_CONTENT_SUFFIXES):
        return False
    return registered_domain(host) in _load()
