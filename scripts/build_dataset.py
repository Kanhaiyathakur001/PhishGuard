"""Build data/dataset.csv from public sources.

Phishing (label=1): Phishing.Database "ACTIVE" feed (current, real phishing URLs)
    https://github.com/mitchellkrogza/Phishing.Database
Legitimate (label=0), two real sources, no synthetic URLs:
    * 75%: real benign URLs *with paths* from the "good" rows of
      https://github.com/faizann24/Using-machine-learning-to-detect-malicious-URLs
      (data/data.csv; older DMOZ-era URLs, stored without a scheme)
    * 25%: homepages of top-ranked domains from
      https://github.com/zer0h/top-1000000-domains

An earlier version generated benign paths from templates; the resulting model
flagged real sites such as github.com and wikipedia.org, so it was replaced by
real URLs (see docs/PROJECT_REPORT.md, "Lessons learned").

The benign sources have no scheme, so http/https is assigned at random with the
same https rate as the phishing class. That stops "https" being a label shortcut
(and reflects reality: many phishing sites use https today).

URLs are stored *defanged* (hxxp://..., [.]) so the CSV is safe to open.

Usage:
    python scripts/build_dataset.py --phish phish.txt --legit-urls good.csv --legit-domains top1m.txt
"""

import argparse
import csv
import random
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from phishguard.rules import defang, parse, registered_domain  # noqa: E402

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phish", required=True)
    ap.add_argument("--legit-urls", required=True,
                    help="faizann24 data.csv (url,label with 'good' rows)")
    ap.add_argument("--legit-domains", required=True, help="top-1M domain list, one per line")
    ap.add_argument("--homepage-share", type=float, default=0.25)
    ap.add_argument("--n", type=int, default=20000, help="rows per class")
    ap.add_argument("--max-per-domain", type=int, default=3)
    ap.add_argument("--legit-pool", type=int, default=150000,
                    help="use the top-K domains of the legit list")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="data/dataset.csv")
    args = ap.parse_args()
    random.seed(args.seed)

    # ---- phishing
    seen, per_domain, phish = set(), defaultdict(int), []
    lines = [l.strip() for l in open(args.phish, encoding="utf-8", errors="ignore")]
    random.shuffle(lines)
    for url in lines:
        if not url.startswith(("http://", "https://")) or len(url) > 400:
            continue
        if not url.isascii() or " " in url or url in seen:
            continue
        try:
            _, _, host = parse(url)
        except ValueError:
            continue
        dom = registered_domain(host)
        if per_domain[dom] >= args.max_per_domain:
            continue
        seen.add(url)
        per_domain[dom] += 1
        phish.append(url)
        if len(phish) >= args.n:
            break

    # ---- legitimate
    https_rate = sum(u.startswith("https://") for u in phish) / len(phish)
    n_home = int(args.n * args.homepage_share)
    n_path = args.n - n_home

    def with_scheme(u):
        return ("https://" if random.random() < https_rate else "http://") + u

    legit, per_domain = [], defaultdict(int)
    cand = []
    with open(args.legit_urls, encoding="utf-8", errors="ignore", newline="") as fh:
        for row in csv.reader(fh):
            if len(row) >= 2 and row[1] == "good":
                u = row[0].strip()
                if u.isascii() and " " not in u and "/" in u.rstrip("/") and len(u) <= 400:
                    cand.append(u)
    random.shuffle(cand)
    for u in cand:
        try:
            _, _, host = parse("http://" + u)
        except ValueError:
            continue
        dom = registered_domain(host)
        if per_domain[dom] >= args.max_per_domain:
            continue
        per_domain[dom] += 1
        legit.append(with_scheme(u))
        if len(legit) >= n_path:
            break

    domains = []
    for l in open(args.legit_domains, encoding="utf-8", errors="ignore"):
        d = l.strip().lower()
        if d and "." in d and d.isascii():
            domains.append(d)
        if len(domains) >= args.legit_pool:
            break
    random.shuffle(domains)
    for d in domains[:n_home]:
        legit.append(with_scheme(("www." if random.random() < 0.6 else "") + d))

    rows = [(defang(u), 1) for u in phish] + [(defang(u), 0) for u in legit]
    random.shuffle(rows)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "label"])
        w.writerows(rows)
    print(f"phishing={len(phish)} legitimate={len(legit)} -> {args.out}")


if __name__ == "__main__":
    main()
