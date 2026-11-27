"""Write examples/sample-error.log: an invented log full of fake secrets, for trying share-safe.

The fake tokens are assembled here at runtime instead of being stored in the repository, so secret
scanners do not flag this project. Every value is random or a published test value.
"""
import random
import string
from pathlib import Path

rng = random.Random(7)


def fake(prefix: str, n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return prefix + "".join(rng.choice(alphabet) for _ in range(n))


log = f"""2026-11-22 18:01:02 INFO  connecting to postgres://shop:Winter2026!@db1.acme.internal:5432/orders
2026-11-22 18:01:02 DEBUG POST https://api.payments.example/v1/charges
2026-11-22 18:01:02 DEBUG Authorization: Bearer {fake("sk" + "_live_", 24)}
2026-11-22 18:01:02 DEBUG Cookie: session={fake("", 32)}; theme=dark
2026-11-22 18:01:03 ERROR charge failed for maria.schmidt@gmail.com (84.163.22.17), card 4111 1111 1111 1111
2026-11-22 18:01:03 ERROR refund account DE89 3704 0044 0532 0130 00, phone +49 151 23456789
Traceback (most recent call last):
  File "/Users/maria/projects/shop/payments.py", line 88, in charge
    raise PaymentError(response.json())
PaymentError: {{'code': 'card_declined', 'request_id': 'req_8f3a2c'}}
2026-11-22 18:01:04 WARN  retrying for maria.schmidt@gmail.com from 84.163.22.17
# .env loaded:
GITHUB_TOKEN={fake("gh" + "p_", 36)}
OPENAI_API_KEY={fake("sk" + "-proj-", 48)}
AWS_ACCESS_KEY_ID={fake("AK" + "IA", 16, string.ascii_uppercase + string.digits)}
"""
out = Path(__file__).with_name("sample-error.log")
out.write_text(log, encoding="utf-8")
print(f"wrote {out}")
