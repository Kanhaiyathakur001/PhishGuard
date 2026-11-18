# Data

| File | Description |
|---|---|
| `dataset.csv` | Evaluation set, 40,000 rows: `url,label` (1 = phishing, 0 = legitimate). **URLs are defanged** (`hxxp://`, `[.]`); the loader calls `refang()`. Do not "un-defang" and click phishing rows. |
| `top_domains.txt` | Top 20,000 popular domains, used by the allowlist (`phishguard/trust.py`). |

## Sources
- Phishing: https://github.com/mitchellkrogza/Phishing.Database (`phishing-links-ACTIVE.txt`)
- Legitimate URLs with paths: https://github.com/faizann24/Using-machine-learning-to-detect-malicious-URLs (`data/data.csv`, rows labelled `good`)
- Legitimate homepages and the allowlist: https://github.com/zer0h/top-1000000-domains

Check each source's own licence/terms before redistributing the data outside a coursework context.

## Construction
- Max 3 URLs per registered domain in each class (prevents a single phishing kit or site dominating the evaluation).
- Benign sources have no scheme, so `http`/`https` is assigned at random with the same https rate as the phishing class (~74%) to stop the scheme being a label shortcut.
- Fixed random seed (42); `python scripts/build_dataset.py` reproduces the file from the raw sources.

## Known issues
- The "good" URLs are old (DMOZ era). The phishing URLs are current. See "Limitations" in the main README.
- Labels are taken from the sources and not manually verified; a few mislabelled rows are expected.
