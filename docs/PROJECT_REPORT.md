# PhishGuard: A Hybrid Rule-Based and Machine-Learning Phishing URL Detector
*Major project report (skeleton with content filled from the implementation; add your name, roll no., guide, and college on the title page.)*

## 1. Abstract
Phishing attacks trick users into entering credentials on fake websites, and the malicious URL is often the first and cheapest thing to inspect. This project builds PhishGuard, a system that scores a URL's phishing risk using (a) twelve explainable heuristic rules and (b) a Gradient Boosting classifier trained on 40,000 real URLs using 37 lexical features, plus (c) a popularity allowlist to reduce false alarms on well-known sites. It is delivered as a CLI, a Flask web application and a REST API. On domain-disjoint test data the classifier reaches 88.5% accuracy (F1 0.882, ROC-AUC 0.957); the rules alone reach 99% precision but only 19% recall.

## 2. Introduction and problem statement
- Phishing is a leading initial-access technique for fraud and malware.
- Users cannot reliably judge URLs; look-alike domains (`paypa1.com`), `@` tricks, and long subdomain chains are common.
- **Goal:** given only the URL text, produce a risk level with a human-readable explanation, safely (never visiting the URL).

## 3. Objectives
1. Implement transparent heuristics for known URL-based phishing tricks.
2. Train and compare ML classifiers on real data, with a leakage-free evaluation.
3. Combine both into one explainable score.
4. Provide usable interfaces (CLI, web, API) with tests and CI.

## 4. Literature / background (to extend)
Suggested topics to cite: blacklist-based protection (Google Safe Browsing, PhishTank) and its latency problem; heuristic approaches (e.g. CANTINA, Zhang et al. 2007); lexical URL classification (Ma et al., "Beyond Blacklists", KDD 2009); content/visual-similarity approaches; Tranco ranking (Le Pochat et al., NDSS 2019). Verify each reference before citing.

## 5. System design
### 5.1 Architecture
`parse URL → {rule engine, feature extractor → classifier, allowlist} → combine → risk band → output (CLI/web/API)`.
Modules: `rules.py`, `features.py`, `model.py`, `trust.py`, `detector.py`, `cli.py`, `app/app.py`.

### 5.2 Rule engine
Twelve weighted rules (see README table). Score = sum of fired rule points, capped at 100; bands 0–24 LOW, 25–49 MEDIUM, 50+ HIGH. Weights follow specificity: signals rare on legitimate sites get more points.

### 5.3 Features (37)
Length/size (URL, host, path, query), character statistics (dots, hyphens, digits, ratios, special characters), structural flags (`@`, `//` in path, port, https, IP host, punycode), host structure (subdomain count, TLD, shortener), semantic signals (keyword count, brand-on-wrong-domain, leet-speak brand), randomness (Shannon entropy of host and path, long hex tokens), path structure (depth, parameters, file extension).

### 5.4 Hybrid scoring
`score = 0.7 × P(phishing) × 100 + 0.3 × rule_score`. If the registered domain is in the top-20k list (excluding user-content platforms) and `rule_score < 50`, the score is capped at 20.

### 5.5 Security design
The tool only parses text and never requests the URL (no SSRF, no exposure to malicious pages). The web UI escapes all output (Jinja autoescape; covered by a test), limits request size (256 KB) and batch size (100), and outputs defanged URLs.

## 6. Implementation
Python 3.11+, scikit-learn, Flask, joblib, pytest, GitHub Actions. ~1,000 lines of code, 53 tests.

## 7. Dataset
See `data/README.md`. 20,000 phishing URLs (Phishing.Database ACTIVE feed) and 20,000 legitimate URLs (75% real URLs with paths, 25% homepages of top domains). Capped at 3 URLs per domain.

## 8. Experimental setup
80/20 split **grouped by registered domain** (`GroupShuffleSplit`, seed 42) so the same domain never appears in train and test. Threshold 0.5. Models: Logistic Regression (scaled), Decision Tree (depth 12), Random Forest (300 trees), Gradient Boosting (250 trees, depth 4). Model selection by ROC-AUC on the test split (Random Forest and Gradient Boosting were within 0.001 F1; Gradient Boosting was chosen on AUC and because its model file is ~125× smaller). *(A stricter protocol would use a separate validation split or cross-validation for selection; this is noted as a limitation.)*

## 9. Results
| Model | Acc | Prec | Recall | F1 | AUC |
|---|---|---|---|---|---|
| Logistic Regression | 0.826 | 0.889 | 0.749 | 0.813 | 0.907 |
| Decision Tree | 0.830 | 0.897 | 0.750 | 0.817 | 0.899 |
| Random Forest | 0.884 | 0.900 | 0.867 | 0.883 | 0.952 |
| **Gradient Boosting (selected)** | 0.885 | 0.911 | 0.854 | 0.882 | 0.957 |
| Rules only | 0.591 | 0.994 | 0.190 | 0.319 | 0.678 |
| Hybrid (MEDIUM+) | 0.874 | 0.845 | 0.918 | 0.880 | 0.956 |
| Hybrid (HIGH only) | 0.863 | 0.957 | 0.761 | 0.848 | 0.956 |

Figures: `reports/confusion_matrix.png`, `reports/roc_curve.png`, `reports/feature_importance.png`. The most important features were longest token length, phishing-keyword count, suspicious TLD and hyphens in the host.

**Discussion.** Rules are precise but narrow; ML generalises better; the hybrid trades about one point of accuracy for explanations, a rules-only fallback and a configurable precision/recall operating point. The hybrid scored on the test set does not include the allowlist (see limitations).

## 10. Lessons learned (important for the viva)
1. **First attempt: 97% accuracy: and it was wrong.** The initial dataset generated benign URLs from simple path templates. The model scored 97% on its test split but flagged 10 of 15 real, well-known sites (github.com, wikipedia.org, …) as MEDIUM/HIGH: it had learned the artefacts of the synthetic data. Replacing the synthetic URLs with real ones dropped the benchmark to ~88% but made the numbers honest.
2. **A spot check on real-world URLs is essential**, because a held-out split from the same data source cannot reveal dataset bias.
3. **Even then, lexical ML alone cannot know `paypal.com/signin` is genuine.** Adding the popularity allowlist fixed this (19/20 legitimate spot-check URLs LOW), at the cost of the trade-offs in §11.
4. **Group-aware splitting** (by domain) avoids optimistic leakage when many URLs share a domain.

## 11. Limitations
See README "Limitations": lexical features only; dataset-era bias; allowlist can under-report compromised popular sites and cannot be fairly evaluated on this data; phishing evolves; selection on the test split.

## 12. Conclusion and future work
PhishGuard demonstrates that combining explainable heuristics with a learned model gives better coverage than rules alone while keeping explanations. Future work: content and visual features, WHOIS/domain-age, certificate features, live reputation APIs, time-based evaluation on fresh data, and a browser extension.

## 13. How to demo
1. `python app/app.py` → analyse a classic phishing URL and a real site; show the explanation panel.
2. `python -m phishguard -f sample_urls.txt` for bulk mode.
3. Show `reports/` plots and `pytest -q`.
4. Be ready to explain §10 (the 97% → 88% story): it shows you validated your own results.

## 14. References
To be completed by the author (see §4 for starting points; verify each).
