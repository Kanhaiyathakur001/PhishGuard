"""Small hand-picked real-world spot check (20 legitimate, 8 phishing-style URLs).

Not a benchmark: a sanity check that the system does not flag well-known sites and does flag obvious phishing-style URLs.
Usage: python scripts/real_world_check.py
"""
import sys; sys.path.insert(0, __import__('pathlib').Path(__file__).resolve().parent.parent.as_posix())
from phishguard.detector import analyze
legit = """https://github.com/anthropics/claude-code/issues/1234
https://www.paypal.com/signin
https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster
https://en.wikipedia.org/wiki/Phishing
https://accounts.google.com/signin/v2/identifier?service=mail&continue=https%3A%2F%2Fmail.google.com
https://www.amazon.in/dp/B0C1234567/ref=sr_1_1?keywords=laptop&qid=1699999999
https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc
https://www.irctc.co.in/nget/train-search
https://www.youtube.com/watch?v=dQw4w9WgXcQ
https://docs.python.org/3/library/urllib.parse.html
https://www.nytimes.com/2024/05/12/technology/ai-chatbots-future.html
https://www.linkedin.com/in/some-person-123abc/
https://www.sbi.co.in/web/personal-banking
https://mail.google.com/mail/u/0/#inbox
https://drive.google.com/file/d/1aBcDeFgHiJkLmNoPqRsTuVwXyZ012345/view?usp=sharing
https://www.bbc.com/news/world-asia-india-67890123
https://www.flipkart.com/apple-iphone-15/p/itm6ac6485515ae4
https://www.reddit.com/r/learnpython/comments/abc123/how_do_i_start/
https://www.geeksforgeeks.org/python-programming-language/
https://scholar.google.com/scholar?q=phishing+detection""".split()
phish = """http://secure-paypal-update.com/login.php
http://amaz0n-account-verify.top/signin
https://sbi-online-kyc-update.xyz/login
http://185.234.12.9/wp-includes/secure/office365/login.html
https://netflix.com.billing-update.work/account
http://appleid.apple.com.verify-id.icu/confirm
https://sites.google.com/view/metamask-wallet-recover/home
https://bafybeigdyrzt5.ipfs.dweb.link/login.html""".split()
for name,xs in (("LEGIT",legit),("PHISH",phish)):
    print(name)
    for u in xs:
        r=analyze(u); print(f"  {r['risk']:7s} final={r['score']:3d} raw={r['rule_score']:3d}  {u[:80]}")

ok_l = sum(analyze(u)["risk"] == "LOW" for u in legit)
ok_p = sum(analyze(u)["risk"] == "HIGH" for u in phish)
print(f"\nLegitimate rated LOW: {ok_l}/{len(legit)} | Phishing rated HIGH: {ok_p}/{len(phish)}")
