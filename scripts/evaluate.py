"""Evaluate the rule engine on data/dataset.csv (40,000 labelled URLs).

No training is involved: the rules are fixed, so the whole file is a test set.
Prints and saves to reports/rule_evaluation.json:
  * accuracy / precision / recall / F1 / false-positive rate at two thresholds
    (MEDIUM+ = score >= 25, HIGH only = score >= 50), with and without the allowlist
  * how often each rule fires on phishing vs legitimate URLs

Usage:  python scripts/evaluate.py
"""

import csv
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from phishguard.detector import ALLOWLIST_BYPASS, ALLOWLIST_CAP  # noqa: E402
from phishguard.rules import parse, refang, run_rules  # noqa: E402
from phishguard.trust import is_trusted  # noqa: E402

RULE_NAMES = [  # (label, substring of the finding message)
    ("Raw IP host", "raw IP"),
    ("Excessive subdomains", "Excessive subdomains"),
    ("Suspicious TLD", "Suspicious top-level"),
    ("'@' in URL", "'@'"),
    ("URL shortener", "shortener"),
    ("Phishing keywords", "keywords"),
    ("Very long URL", "Very long URL"),
    ("Many hyphens in host", "Many hyphens"),
    ("Punycode", "Punycode"),
    ("Lookalike (leet)", "substitution"),
    ("No HTTPS", "Does not use HTTPS"),
    ("Brand on wrong domain", "Brand '"),
    ("Double slash in path", "Double slash"),
    ("Non-standard port", "Non-standard port"),
]


def metrics(y, pred):
    tp = sum(1 for a, b in zip(y, pred) if a and b)
    tn = sum(1 for a, b in zip(y, pred) if not a and not b)
    fp = sum(1 for a, b in zip(y, pred) if not a and b)
    fn = sum(1 for a, b in zip(y, pred) if a and not b)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"accuracy": round((tp + tn) / len(y), 4), "precision": round(prec, 4),
            "recall": round(rec, 4), "f1": round(f1, 4),
            "false_positive_rate": round(fp / (fp + tn), 4),
            "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn}}


def main():
    rows = []
    with open(ROOT / "data" / "dataset.csv", newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            url = refang(r["url"])
            try:
                res = run_rules(url)
                trusted = is_trusted(parse(url)[2])
            except ValueError:
                continue
            rows.append((int(r["label"]), res, trusted))

    y = [r[0] for r in rows]
    raw = [r[1]["score"] for r in rows]
    final = [min(s, ALLOWLIST_CAP) if (t and s < ALLOWLIST_BYPASS) else s
             for (_, _, t), s in zip(rows, raw)]

    out = {"rows": len(rows), "phishing": sum(y), "legitimate": len(y) - sum(y), "results": {}}
    for name, scores in (("rules only", raw), ("rules + allowlist", final)):
        for thr, label in ((25, "MEDIUM or higher"), (50, "HIGH only")):
            out["results"][f"{name} | {label}"] = metrics(y, [s >= thr for s in scores])

    fired = {0: Counter(), 1: Counter()}
    totals = Counter(y)
    for lab, res, _ in rows:
        for _, msg in res["findings"]:
            for name, key in RULE_NAMES:
                if key in msg:
                    fired[lab][name] += 1
    out["rule_firing_rate"] = {
        name: {"phishing": round(fired[1][name] / totals[1], 4),
               "legitimate": round(fired[0][name] / totals[0], 4)}
        for name, _ in RULE_NAMES}

    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports" / "rule_evaluation.json").write_text(json.dumps(out, indent=2))

    print(f"{out['rows']} URLs ({out['phishing']} phishing, {out['legitimate']} legitimate)\n")
    print(f"{'setting':42s} {'acc':>6s} {'prec':>6s} {'rec':>6s} {'F1':>6s} {'FPR':>6s}")
    for k, m in out["results"].items():
        print(f"{k:42s} {m['accuracy']:6.3f} {m['precision']:6.3f} {m['recall']:6.3f} "
              f"{m['f1']:6.3f} {m['false_positive_rate']:6.3f}")
    print(f"\n{'rule':26s} {'phishing':>9s} {'legit':>9s}")
    for name, v in out["rule_firing_rate"].items():
        print(f"{name:26s} {v['phishing']*100:8.1f}% {v['legitimate']*100:8.1f}%")


if __name__ == "__main__":
    main()
