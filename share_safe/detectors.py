"""What counts as sensitive, and how to find it.

Three categories, checked in this order of priority:

* secret: credentials that give access to something (API keys, tokens, passwords, private keys).
  Leaking one means rotating it.
* pii: data about a person (email addresses, phone numbers, bank and card numbers).
* infra: details about your systems (IP and MAC addresses, the username in home-directory paths,
  and any domains or terms you name).

Every detector is a regular expression, optionally with a validator that rejects look-alikes
(an IBAN must pass its checksum, a card number the Luhn check, an IP must not be a version number).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

SECRET, PII, INFRA = "secret", "pii", "infra"
CATEGORIES = (SECRET, PII, INFRA)


@dataclass(frozen=True)
class Detector:
    kind: str  # identifier, e.g. "github_token"
    category: str
    label: str  # placeholder stem, e.g. GITHUB_TOKEN -> <GITHUB_TOKEN_1>
    pattern: re.Pattern
    group: int = 0  # the regex group that holds the sensitive part
    validate: Callable[[str, re.Match, str], bool] | None = None  # (value, match, whole text) -> keep?
    description: str = ""


def _luhn(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        n = int(ch)
        if i % 2 == parity:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def _card(value: str, m: re.Match, text: str) -> bool:
    """Luhn-valid, starts like a real card (3 Amex/Diners, 4 Visa, 5 Mastercard, 6 Discover/UnionPay) and
    has a card's length. This keeps out millisecond timestamps and long order numbers."""
    digits = re.sub(r"\D", "", value)
    return (digits[0] in "3456" and len(digits) in (14, 15, 16, 19) and len(set(digits)) >= 2 and _luhn(digits))


IBAN_LENGTH = {"DE": 22, "AT": 20, "CH": 21, "NL": 18, "BE": 16, "FR": 27, "ES": 24, "IT": 27, "PL": 28, "GB": 22,
               "IE": 22, "LU": 20, "DK": 18, "SE": 24, "NO": 15, "FI": 18, "PT": 25, "CZ": 24}


def _iban(value: str, m: re.Match, text: str) -> bool:
    s = value.replace(" ", "")
    if s[:2] in IBAN_LENGTH and len(s) != IBAN_LENGTH[s[:2]]:
        return False
    if not 15 <= len(s) <= 34:
        return False
    return int("".join(str(int(c, 36)) for c in s[4:] + s[:4])) % 97 == 1


EXAMPLE_DOMAINS = re.compile(r"(?:^|\.)(?:example\.(?:com|org|net)|example|test|invalid|localhost)$", re.I)


def _email(value: str, m: re.Match, text: str) -> bool:
    return not EXAMPLE_DOMAINS.search(value.rsplit("@", 1)[-1])


def _ipv4(value: str, m: re.Match, text: str) -> bool:
    if value.startswith("127.") or value in {"0.0.0.0", "255.255.255.255"}:
        return False
    before = text[max(0, m.start() - 12): m.start()].lower()
    after = text[m.end(): m.end() + 1]
    # version strings: "v1.2.3.4", "version 10.0.0.1", "Chrome/120.0.0.0", "1.2.3.4-beta"
    return not re.search(r"(?:\bv|version\s*|/)$", before) and after not in {"-", "."}


def _ipv6(value: str, m: re.Match, text: str) -> bool:
    return value not in {"::1", "::"} and value.count(":") >= 3 and bool(re.search(r"[0-9a-fA-F]{3,}", value))


NOT_A_SECRET = re.compile(r"^(?:<[^>]*>|\$\{?[\w.]+\}?|%\(?\w+\)?s?|\*+|x+|null|none|nil|true|false|undefined|"
                          r"changeme|password|secret|redacted|\[redacted\]|\.\.\.|your[_-]?\w*|\{\{.*\}\})$", re.I)


def _assigned_secret(value: str, m: re.Match, text: str) -> bool:
    """A value assigned to a key named like a secret, unless it is a placeholder, a plain number, a code
    expression such as re.compile(...), or a single lower-case word (prose like "secret: credentials")."""
    return not (NOT_A_SECRET.match(value) or value.isdigit() or value.startswith("<") or "(" in value
                or re.fullmatch(r"[a-z]+", value))


SKIP_USERS = {"Shared", "Public", "Default", "All Users", "Default User"}


def _home_user(value: str, m: re.Match, text: str) -> bool:
    return value not in SKIP_USERS and bool(re.fullmatch(r"[A-Za-z0-9._\-]+", value))


def _d(kind, category, label, regex, group=0, validate=None, flags=0, description=""):
    return Detector(kind, category, label, re.compile(regex, flags), group, validate, description)


SECRET_KEYS = (r"[A-Za-z0-9_.\-]*(?:password|passwd|passwort|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
               r"private[_-]?key|client[_-]?secret|auth[_-]?key|credentials?)[A-Za-z0-9_.\-]*")

DETECTORS: tuple[Detector, ...] = (
    # secrets, most specific first
    _d("private_key", SECRET, "PRIVATE_KEY",
       r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----",
       description="PEM, OpenSSH and PGP private key blocks"),
    _d("aws_access_key", SECRET, "AWS_ACCESS_KEY", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    _d("github_token", SECRET, "GITHUB_TOKEN", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
    _d("gitlab_token", SECRET, "GITLAB_TOKEN", r"\bglpat-[A-Za-z0-9_\-]{20,}"),
    _d("anthropic_key", SECRET, "ANTHROPIC_KEY", r"\bsk-ant-[A-Za-z0-9_\-]{20,}"),
    _d("openai_key", SECRET, "OPENAI_KEY", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}"),
    _d("stripe_key", SECRET, "STRIPE_KEY", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"),
    _d("slack_token", SECRET, "SLACK_TOKEN", r"\bxox[abposr]-[A-Za-z0-9\-]{10,}"),
    _d("slack_webhook", SECRET, "SLACK_WEBHOOK", r"https://hooks\.slack\.com/services/[A-Za-z0-9_/]+"),
    _d("discord_webhook", SECRET, "DISCORD_WEBHOOK", r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+"),
    _d("google_api_key", SECRET, "GOOGLE_API_KEY", r"\bAIza[0-9A-Za-z_\-]{35}"),
    _d("npm_token", SECRET, "NPM_TOKEN", r"\bnpm_[A-Za-z0-9]{36}\b"),
    _d("pypi_token", SECRET, "PYPI_TOKEN", r"\bpypi-[A-Za-z0-9_\-]{50,}"),
    _d("huggingface_token", SECRET, "HF_TOKEN", r"\bhf_[A-Za-z0-9]{30,}\b"),
    _d("sendgrid_key", SECRET, "SENDGRID_KEY", r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}"),
    _d("jwt", SECRET, "JWT", r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    _d("bearer_token", SECRET, "TOKEN", r"\b[Bb]earer\s+([A-Za-z0-9._~+/\-]{16,}=*)", group=1),
    _d("basic_auth", SECRET, "BASIC_AUTH", r"(?i)\bauthorization\s*:\s*basic\s+([A-Za-z0-9+/]{8,}=*)", group=1),
    _d("url_password", SECRET, "PASSWORD", r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@\"']+:([^\s@/\"']+)@", group=1,
       description="the password in user:password@host URLs and connection strings"),
    _d("cookie", SECRET, "COOKIE", r"(?i)(?<![\w-])(?:set-)?cookie\s*:\s*([^\r\n]+)", group=1,
       description="the value of Cookie and Set-Cookie headers, anywhere in a line"),
    _d("assigned_secret", SECRET, "SECRET",
       r"(?i)\b" + SECRET_KEYS + r"[\"']?\s*(?:=|:|=>)\s*[\"'`]?([^\s\"'`,;&<>]{6,})", group=1, validate=_assigned_secret,
       description="values assigned to keys like password, token, api_key, secret"),
    # personal data
    _d("email", PII, "EMAIL", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b", validate=_email,
       description="email addresses, except example.com and similar"),
    _d("iban", PII, "IBAN", r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b", validate=_iban),
    _d("card_number", PII, "CARD", r"\b(?:\d[ \-]?){12,18}\d\b", validate=_card, description="card numbers passing the Luhn check"),
    _d("phone", PII, "PHONE", r"(?<![\w+])\+\d{1,3}(?:[ \-/]?\(?\d{1,5}\)?){2,5}\b",
       validate=lambda v, m, t: 8 <= len(re.sub(r"\D", "", v)) <= 15, description="international numbers starting with +"),
    # infrastructure
    _d("ipv4", INFRA, "IP", r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b", validate=_ipv4,
       description="IPv4 addresses except loopback and version numbers"),
    _d("ipv6", INFRA, "IP", r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}(?![\w:])|(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){1,6}:(?:[0-9A-Fa-f]{1,4}:?){1,6}(?![\w:])",
       validate=_ipv6),
    _d("mac_address", INFRA, "MAC", r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b"),
    _d("home_user", INFRA, "USER", r"(?:/home/|/Users/|/var/home/|[A-Za-z]:\\\\?Users\\\\?)([^/\\\s:\"'<>]+)", group=1,
       validate=_home_user, description="the username in home-directory paths"),
)

BY_KIND = {d.kind: d for d in DETECTORS}
PRIORITY = {d.kind: i for i, d in enumerate(DETECTORS)}
