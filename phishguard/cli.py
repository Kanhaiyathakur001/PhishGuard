"""Command-line interface.

    python -m phishguard "http://paypa1-login.secure.example.xyz/verify"
    python -m phishguard -f urls.txt -o results.csv
"""

import argparse
import csv
import sys
from datetime import datetime

from .detector import analyze


def print_result(r: dict) -> None:
    print("=" * 70)
    print(f"URL   : {r['url_defanged']}")
    if not r["valid"]:
        print(f"RISK  : INVALID ({r['error']})")
        return
    ml = "n/a" if r["ml_probability"] is None else f"{r['ml_probability'] * 100:.1f}%"
    print(f"RISK  : {r['risk']}  (score {r['score']}/100)")
    print(f"MODE  : {r['mode']} | ML phishing probability: {ml} | rule score: {r['rule_score']}")
    if r.get("trusted_domain"):
        print("NOTE  : domain is in the top-20k popular list (score capped unless rules are HIGH)")
    if r["findings"]:
        print("WHY   :")
        for f in r["findings"]:
            print(f"   - {f}")
    else:
        print("WHY   : No rule-based indicators triggered")


def write_csv(results: list, path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp", "url_defanged", "risk", "score",
                    "ml_probability", "rule_score", "findings"])
        now = datetime.now().isoformat(timespec="seconds")
        for r in results:
            w.writerow([now, r["url_defanged"], r["risk"], r["score"],
                        r.get("ml_probability", ""), r.get("rule_score", ""),
                        " | ".join(r["findings"]) or r.get("error", "")])
    print(f"\nResults saved to {path}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="phishguard",
                                description="PhishGuard: hybrid phishing URL detector")
    p.add_argument("url", nargs="*", help="One or more URLs to analyze")
    p.add_argument("-f", "--file", help="Text file with one URL per line ('#' = comment)")
    p.add_argument("-o", "--output", help="Save results to a CSV file")
    args = p.parse_args(argv)

    urls = list(args.url)
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                urls += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        except OSError as exc:
            print(f"Error reading {args.file}: {exc}", file=sys.stderr)
            return 1
    if not urls:
        p.print_help()
        return 1

    results = [analyze(u) for u in urls]
    for r in results:
        print_result(r)
    counts = {k: sum(r["risk"] == k for r in results) for k in ("HIGH", "MEDIUM", "LOW", "INVALID")}
    print("=" * 70)
    print(f"Summary: {len(results)} URLs | HIGH {counts['HIGH']} | MEDIUM {counts['MEDIUM']} "
          f"| LOW {counts['LOW']} | INVALID {counts['INVALID']}")
    if args.output:
        write_csv(results, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
