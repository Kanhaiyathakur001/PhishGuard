# PhishGuard: Rule-Based Phishing URL Detector

![CI](https://github.com/Kanhaiyathakur001/PhishGuard/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

PhishGuard classifies a URL as **LOW / MEDIUM / HIGH** phishing risk using

1. an **explainable rule engine**: 12 weighted heuristics, each with a plain-English reason, and
2. a **popularity allowlist** (top 20,000 domains) so well-known sites are not flagged by mistake.

It ships as a command-line tool, a web app and a JSON API. There is **no machine learning**: every score can be traced to the exact rules that produced it. URLs are analysed **as text only; PhishGuard never visits them.**

## Features
- 12 weighted rules; every rule that fires explains itself
- Allowlist that cannot be abused (matches the registered domain only; user-content platforms such as `github.io` or `sites.google.com` are never trusted)
- Defanged output (`hxxp://example[.]com`) so results are safe to paste into tickets
- CLI (single URL, many URLs, bulk file, CSV export), Flask web UI, and REST API
- Evaluation script that measures the rules on 40,000 labelled URLs
- 50 automated tests and GitHub Actions CI

## Quick start
```bash
git clone https://github.com/Kanhaiyathakur001/PhishGuard.git
cd PhishGuard
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

**Command line**
```bash
python -m phishguard "http://paypa1-login.secure.example.xyz/verify"
python -m phishguard -f sample_urls.txt -o results.csv
```

**Web app**
```bash
python app/app.py          # open http://127.0.0.1:5000
```

**API**
```bash
curl -X POST http://127.0.0.1:5000/api/analyze \
     -H "Content-Type: application/json" \
     -d '{"url": "http://paypa1-login.secure.example.xyz/verify"}'
# batch (max 100):  {"urls": ["...", "..."]}
```

**Example output**
```
URL   : hxxp://paypa1-login[.]secure[.]example[.]xyz/verify
RISK  : HIGH  (score 65/100, raw rule score 65)
WHY   :
   - (+15) Suspicious top-level domain: .xyz
   - (+20) Credential-harvesting keywords: login, verify, secure
   - (+20) Lookalike of brand 'paypal' using character substitution ('paypa1')
   - (+10) Does not use HTTPS (scheme: http)
```

## How it works
```
 URL ──► parse ──► 12 rules ──► sum of points (max 100) ──► allowlist check ──► LOW / MEDIUM / HIGH
                                                              (top-20k domain and raw score < 50
                                                               → final score capped at 20)
```
Risk bands: **0–24 LOW, 25–49 MEDIUM, 50+ HIGH.**

### The 12 rules
| # | Rule | Points |
|---|------|--------|
| 1 | Raw IP address as host | 30 |
| 2 | More than 3 subdomains | 15 |
| 3 | Suspicious TLD (.xyz, .top, .tk, …) | 15 |
| 4 | `@` in the URL authority | 25 |
| 5 | URL shortener (bit.ly, tinyurl, …) | 15 |
| 6 | Phishing keywords (login, verify, …) | 10 each, max 20 |
| 7 | URL > 75 characters / 3+ hyphens in host | 10 each |
| 8 | Punycode / digit-substitution lookalike (`paypa1`) | 20 each |
| 9 | No HTTPS | 10 |
| 10 | Brand name present but not the real domain | 25 |
| 11 | Double slash in path | 10 |
| 12 | Non-standard port | 10 |

Weights reflect how specific each signal is: structural tricks that almost never appear on honest sites (`@` in authority, raw IP host, brand on the wrong domain) score highest; signals that also occur on legitimate sites (no HTTPS, long URL) score lowest. **The weights are expert-chosen heuristics, not values fitted to data.**

### The allowlist
URL text alone cannot tell that `paypal.com/signin` is the genuine PayPal (the word "signin" trips a keyword rule). If the registered domain is in the top 20,000 most popular domains, and the raw rule score is below 50, the final score is capped at 20 (LOW). Strong signals still win: `https://google.com@evil-site.top/login` is HIGH because the real host is `evil-site.top`, not a trusted domain.

## Evaluation
`python scripts/evaluate.py` runs the rules on `data/dataset.csv` (20,000 phishing + 20,000 legitimate URLs). No training is involved, so the whole file is a test set. Results are saved in `reports/rule_evaluation.json`.

| Setting | Accuracy | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|---|
| Rules + allowlist, MEDIUM or higher counts as phishing | 0.596 | 0.989 | 0.193 | 0.324 | 0.2% |
| Rules + allowlist, only HIGH counts | 0.514 | 1.000 | 0.028 | 0.055 | 0.0% |

**Reading this honestly:** the rules are extremely precise (when they flag a URL it is almost always phishing, 45 false alarms in 20,000 legitimate URLs) but they **miss about 80% of the phishing URLs** in this dataset, because most real phishing URLs do not use any of the 12 tricks. They are a transparent first-line filter, not a complete defence.

Which rules actually fire (share of URLs, from the same run):

| Rule | Phishing | Legitimate |
|---|---|---|
| Phishing keywords | 22.9% | 0.5% |
| Suspicious TLD | 11.7% | 0.1% |
| Brand on wrong domain | 7.5% | 0.1% |
| Many hyphens in host | 2.7% | 0.1% |
| Raw IP host | 1.7% | 0.0% |
| Excessive subdomains | 0.9% | 0.0% |
| Very long URL | 29.4% | 16.7% |
| No HTTPS | 26.2% | 26.8% |

"No HTTPS" fires equally on both classes (the dataset deliberately matches the HTTPS rate) and "Very long URL" is only weakly discriminating, which is why both carry low weights.

**Real-world spot check.** On 20 hand-picked well-known legitimate URLs (GitHub, PayPal, Google sign-in, Wikipedia, Amazon, SBI, …) all 20 are rated LOW. On 8 phishing-style URLs, 4 are HIGH, 2 are MEDIUM and 2 are LOW (a Google Sites page and an IPFS-hosted page, which look structurally normal). This set is tiny and written by the authors, so it is a sanity check, not a benchmark. Run it with `python scripts/real_world_check.py`.

## Dataset
| Class | Source |
|---|---|
| Phishing | [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) "ACTIVE" feed |
| Legitimate (75%) | "good" URLs from [faizann24/Using-machine-learning-to-detect-malicious-URLs](https://github.com/faizann24/Using-machine-learning-to-detect-malicious-URLs) |
| Legitimate (25%) | Homepages of top-ranked domains, [zer0h/top-1000000-domains](https://github.com/zer0h/top-1000000-domains) |

Stored defanged in `data/dataset.csv`. Details and caveats: [`data/README.md`](data/README.md).

## Tests
```bash
pytest -q        # 50 tests
```

## Project structure
```
phishguard/        rules.py  trust.py  detector.py  cli.py
app/               Flask app + HTML template
scripts/           evaluate.py  real_world_check.py  build_dataset.py
data/              dataset.csv  top_domains.txt  README.md
reports/           rule_evaluation.json
tests/             pytest tests
docs/              PROJECT_REPORT.md
.github/workflows/ ci.yml
```

## Limitations
- **Low recall.** The rules catch roughly 1 in 5 phishing URLs in the dataset. A phishing page on a clean-looking or compromised domain scores LOW.
- **Lexical only.** It never fetches the page or checks WHOIS/domain age, TLS certificates, page content or live blocklists.
- **Hand-set weights and lists.** The weights, the brand list, the TLD list and the keyword list were chosen by hand and will not cover every brand or every new trick.
- **Dataset bias.** Legitimate URLs come from an older crawl and a domain ranking, while phishing URLs are recent, so the figures are indicative, not a guarantee for real traffic. The allowlist cannot be fairly scored on this dataset because some legitimate homepages came from the same ranking.
- **Allowlist trade-off.** Popular domains are capped at LOW unless the rules reach HIGH, so a compromised popular site or an open redirect on one would be under-reported.
- A LOW result is **not** a guarantee of safety.

## Future work
- Domain age (WHOIS), certificate and DNS features
- VirusTotal / PhishTank / Google Safe Browsing lookups for MEDIUM+ results
- Tune the rule weights on labelled data, and add rules for more brands and tactics
- Page-content and visual-similarity checks
- Browser extension front-end

## Author
Kanhaiya Kumar

## Disclaimer
For educational and defensive use only. Do not use it as the sole basis for security decisions.

## License
MIT. See [LICENSE](LICENSE).
