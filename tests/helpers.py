"""Fake credentials are assembled at runtime, so no token-shaped string appears in the source.
That keeps secret scanners (including GitHub push protection) quiet about this test suite."""
import random
import string

_rng = random.Random(42)
ALNUM = string.ascii_letters + string.digits


def fake(prefix: str, length: int, alphabet: str = ALNUM) -> str:
    return prefix + "".join(_rng.choice(alphabet) for _ in range(length))


GITHUB = fake("gh" + "p_", 36)
GITHUB_PAT = fake("github" + "_pat_", 82, ALNUM + "_")
AWS = fake("AK" + "IA", 16, string.ascii_uppercase + string.digits)
OPENAI = fake("sk" + "-proj-", 48, ALNUM + "-_")
ANTHROPIC = fake("sk" + "-ant-api03-", 60, ALNUM + "-_")
STRIPE = fake("sk" + "_live_", 24)
SLACK = fake("xo" + "xb-", 40, ALNUM + "-")
GOOGLE = fake("AI" + "za", 35, ALNUM + "-_")
NPM = fake("np" + "m_", 36)
HF = fake("h" + "f_", 34)
GITLAB = fake("gl" + "pat-", 20, ALNUM + "-_")
JWT = "eyJ" + fake("", 20, ALNUM) + ".eyJ" + fake("", 30, ALNUM) + "." + fake("", 43, ALNUM + "-_")
PEM = ("-----BEGIN " + "RSA PRIVATE KEY-----\n" + "\n".join(fake("", 64, ALNUM + "+/") for _ in range(4))
       + "\n-----END " + "RSA PRIVATE KEY-----")
