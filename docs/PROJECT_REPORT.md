# PhishGuard: An Explainable Rule-Based Phishing URL Detector
*Major project report (skeleton with content filled from the implementation; add your name, roll no., guide, and college on the title page.)*

## 1. Abstract
Phishing attacks trick users into entering credentials on fake websites, and the malicious URL is often the first and cheapest thing to inspect. PhishGuard scores a URL's phishing risk using twelve explainable heuristic rules plus a popularity allowlist that reduces false alarms on well-known sites. It is delivered as a command-line tool, a Flask web application and a REST API, and it analyses URLs purely as text without ever visiting them. On a 40,000-URL labelled set the rules reach 98.9% precision with a 0.2% false-positive rate but only 19.3% recall, which shows both the value and the limits of purely lexical heuristics.

## 2. Introduction and problem statement
- Phishing is a leading initial-access technique for fraud and malware.
- Users cannot reliably judge URLs; look-alike domains (`paypa1.com`), `@` tricks, and long subdomain chains are common.
- **Goal:** given only the URL text, produce a risk level with a human-readable explanation, safely (never visiting the URL).

## 3. Objectives
1. Implement transparent heuristics for known URL-based phishing tricks.
2. Make every verdict explainable: list exactly which rules fired and why.
3. Reduce false alarms on popular legitimate sites without opening an easy bypass.
4. Measure the rules honestly on labelled real-world data.
5. Provide usable interfaces (CLI, web, API) with tests and CI.

## 4. Literature / background (to extend)
Suggested topics to cite: blacklist-based protection (Google Safe Browsing, PhishTank) and its latency problem; heuristic approaches (e.g. CANTINA, Zhang et al. 2007); lexical URL analysis (Ma et al., "Beyond Blacklists", KDD 2009); content/visual-similarity approaches; Tranco ranking (Le Pochat et al., NDSS 2019). Verify each reference before citing.

## 5. System design
### 5.1 Architecture
`parse URL → 12 rules → sum of points → allowlist check → risk band → output (CLI / web / API)`.
Modules: `rules.py` (rule engine and URL parsing helpers), `trust.py` (allowlist), `detector.py` (combines them), `cli.py`, `app/app.py`.

### 5.2 Rule engine
Twelve weighted rules (see README table). Score = sum of the points of every rule that fires, capped at 100. Bands: 0–24 LOW, 25–49 MEDIUM, 50+ HIGH.

| Rule | Why it matters |
|---|---|
| Raw IP host (30) | Legitimate services use domain names |
| `@` in authority (25) | `https://google.com@evil.top` actually goes to `evil.top` |
| Brand on wrong domain (25) | `paypal.evil.xyz` borrows trust from a brand |
| Lookalike / punycode (20) | `paypa1`, `xn--pple-43d` imitate real names |
| Keywords (10 each, max 20) | login, verify, update… are used to bait credentials |
| Suspicious TLD, shortener, many subdomains (15) | cheap or hiding techniques |
| No HTTPS, long URL, many hyphens, `//`, odd port (10) | weak signals also seen on honest sites |

Weights follow specificity: signals rare on legitimate sites get more points. They are expert-chosen, not fitted to data.

### 5.3 Allowlist
If the registered domain is in the top-20,000 popular list (excluding user-content platforms such as `github.io`, `sites.google.com`, `amazonaws.com`, URL shorteners) and the raw rule score is below 50, the final score is capped at 20. The match is on the registered domain only, so `paypal.com.evil.xyz` is not trusted. Rules scoring 50 or more override the allowlist.

### 5.4 Security design
The tool only parses text and never requests the URL (no SSRF, no exposure to malicious pages). The web UI escapes all output (Jinja autoescape; covered by a test), limits request size (256 KB) and batch size (100), and outputs defanged URLs.

## 6. Implementation
Python 3.11+, Flask, pytest, GitHub Actions. About 950 lines of Python including tests and scripts, and 50 tests. The only runtime dependency is Flask; the CLI uses the standard library alone.

## 7. Dataset
See `data/README.md`. 20,000 phishing URLs (Phishing.Database ACTIVE feed) and 20,000 legitimate URLs (75% real URLs with paths, 25% homepages of top domains), at most 3 URLs per domain. The dataset is used only for evaluation; nothing is trained on it.

## 8. Experimental setup
`scripts/evaluate.py` runs the rule engine on every URL in the dataset and compares the verdict with the label. Two decision thresholds are reported: MEDIUM or higher counts as phishing (score ≥ 25), and only HIGH counts (score ≥ 50). Results are written to `reports/rule_evaluation.json`.

## 9. Results
| Setting | Accuracy | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|
| Rules + allowlist, MEDIUM+ | 0.596 | 0.989 | 0.193 | 0.324 | 0.2% |
| Rules + allowlist, HIGH only | 0.514 | 1.000 | 0.028 | 0.055 | 0.0% |

Confusion matrix for MEDIUM+: 3,868 true positives, 45 false positives, 19,955 true negatives, 16,132 false negatives.

Rule firing rates (phishing / legitimate): keywords 22.9% / 0.5%; suspicious TLD 11.7% / 0.1%; brand on wrong domain 7.5% / 0.1%; many hyphens 2.7% / 0.1%; raw IP 1.7% / 0.0%; no HTTPS 26.2% / 26.8%; long URL 29.4% / 16.7%.

**Real-world spot check** (`scripts/real_world_check.py`): 20/20 well-known legitimate URLs rated LOW; of 8 phishing-style URLs, 4 HIGH, 2 MEDIUM, 2 LOW. This is a small, author-written sanity check, not a benchmark.

**Discussion.**
- The rules are **precise but narrow**: very few false alarms, but most real phishing URLs use none of the 12 tricks, so recall is low.
- The strongest signals (keywords, suspicious TLD, brand on the wrong domain, raw IP) fire far more often on phishing than on legitimate URLs (for example keywords 22.9% vs 0.5%). "No HTTPS" fires equally on both classes in this dataset, which supports giving it a low weight.
- The two missed spot-check URLs (a Google Sites page and an IPFS page) are structurally normal: lexical rules cannot see that the page content is a fake wallet recovery form.
- A shortener on its own scores 15 (LOW) because the rule only says the destination is hidden, not that it is malicious.

## 10. Lessons learned (useful for the viva)
1. **Precision versus recall is a design choice.** The rules were kept strict so that a flagged URL is almost always bad; the cost is missed phishing.
2. **Popularity matters.** Keyword rules alone flag `paypal.com/signin`. The allowlist fixed this, and the design (registered domain only, user-content platforms excluded, strong signals override) is what stops it from becoming a loophole.
3. **Evaluate on real data.** A rule engine checked only against hand-written examples looks better than it is; the 40,000-URL evaluation exposed the low recall.
4. **Weights are hypotheses.** They are expert judgement and can be tuned if labelled data is used.

## 11. Limitations
See README "Limitations": low recall; lexical features only; hand-set weights and lists; dataset-era bias; allowlist can under-report compromised popular sites and cannot be fairly evaluated on this data; phishing tactics evolve.

## 12. Conclusion and future work
PhishGuard shows that a small set of transparent URL heuristics can flag phishing with very few false alarms and clear explanations, but it also shows that URL text alone is not enough to catch most phishing. Future work: domain age and certificate checks, live reputation APIs (Safe Browsing, PhishTank, VirusTotal), data-driven tuning of the weights, content and visual-similarity analysis, and a browser extension.

## 13. How to demo
1. `python app/app.py` → analyse a classic phishing URL and a real site; show the "Why?" panel.
2. `python -m phishguard -f sample_urls.txt` for bulk mode.
3. `python scripts/evaluate.py` and `pytest -q`.
4. Be ready to explain the precision/recall result (§9) and why the weights were chosen (§5.2).

## 14. References
To be completed by the author (see §4 for starting points; verify each).
