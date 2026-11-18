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
    print(f"RISK  : {r['risk']}  (score {r['score']}/100, raw rule score {r['rule_score']})")
    if r.get("allowlist_applied"):
        print("NOTE  : domain is in the top-20k popular list, so the score was capped at LOW")
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
                    "rule_score", "findings"])
        now = datetime.now().isoformat(timespec="seconds")
        for r in results:
            w.writerow([now, r["url_defanged"], r["risk"], r["score"],
                        r.get("rule_score", ""),
                        " | ".join(r["findings"]) or r.get("error", "")])
    print(f"\nResults saved to {path}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="phishguard",
                                description="PhishGuard: rule-based phishing URL detector")
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
