import pytest

from share_safe import find
from share_safe.redactor import Options

from . import helpers as h


def kinds(text, **opts):
    return [(x.kind, x.value) for x in find(text, Options(**opts))]


@pytest.mark.parametrize("token, kind", [
    (h.GITHUB, "github_token"), (h.GITHUB_PAT, "github_token"), (h.AWS, "aws_access_key"),
    (h.OPENAI, "openai_key"), (h.ANTHROPIC, "anthropic_key"), (h.STRIPE, "stripe_key"), (h.SLACK, "slack_token"),
    (h.GOOGLE, "google_api_key"), (h.NPM, "npm_token"), (h.HF, "huggingface_token"), (h.GITLAB, "gitlab_token"),
    (h.JWT, "jwt"),
])
def test_token_formats(token, kind):
    assert kinds(f"value: {token} end") == [(kind, token)]


def test_private_key_block_spans_lines():
    found = find(f"before\n{h.PEM}\nafter")
    assert [x.kind for x in found] == ["private_key"] and found[0].value == h.PEM


def test_password_in_connection_string_keeps_user_and_host():
    assert kinds("postgres://app:S3cr3t!@db.local:5432/x") == [("url_password", "S3cr3t!")]
    assert kinds("https://user:tok%40en@example.com/path") == [("url_password", "tok%40en")]


def test_bearer_basic_and_cookie_headers():
    assert kinds("Authorization: Bearer abcdefghijklmnop1234") == [("bearer_token", "abcdefghijklmnop1234")]
    assert kinds("authorization: Basic dXNlcjpwYXNzd29yZA==") == [("basic_auth", "dXNlcjpwYXNzd29yZA==")]
    assert kinds("> Cookie: session=abc123; theme=dark") == [("cookie", "session=abc123; theme=dark")]
    assert kinds("12:00 DEBUG Set-Cookie: sid=xyz; HttpOnly") == [("cookie", "sid=xyz; HttpOnly")]


@pytest.mark.parametrize("line, value", [
    ("password=hunter2!", "hunter2!"), ('"apiKey": "k_9f8e7d6c5b"', "k_9f8e7d6c5b"),
    ("DB_PASSWORD: s3cretvalue", "s3cretvalue"), ("client_secret => 'abcdef123'", "abcdef123"),
    ("https://api.x.com/v1?api_key=abc123def&q=1", "abc123def"),
])
def test_values_assigned_to_secret_keys(line, value):
    assert kinds(line) == [("assigned_secret", value)]


@pytest.mark.parametrize("line", [
    "password = <your-password>", "token: ${GITHUB_TOKEN}", "password: changeme", "secret: ********",
    "max_tokens: 4096000", "password: null", "api_key = %(key)s", "token_count = 12",
    "* secret: credentials that give access", "SECRET_RE = re.compile(r'x')", "use `token: ${GITHUB_TOKEN}` here",
])
def test_placeholders_and_numbers_are_not_secrets(line):
    assert kinds(line) == []


def test_emails_but_not_example_domains():
    assert kinds("from maria@gmail.com and a.b+c@mail.co.uk") == [("email", "maria@gmail.com"), ("email", "a.b+c@mail.co.uk")]
    assert kinds("see user@example.com or x@test") == []


def test_iban_needs_a_valid_checksum():
    assert kinds("IBAN DE89 3704 0044 0532 0130 00") == [("iban", "DE89 3704 0044 0532 0130 00")]
    assert kinds("IBAN DE89 3704 0044 0532 0130 01") == []


def test_cards_need_luhn_and_a_card_prefix():
    assert kinds("card 4111 1111 1111 1111") == [("card_number", "4111 1111 1111 1111")]
    assert kinds("card 5555-5555-5555-4444") == [("card_number", "5555-5555-5555-4444")]
    assert kinds("ts=1732291262000 order 4111111111111112") == []


def test_international_phone_numbers():
    assert kinds("call +49 151 23456789 or +1 (415) 555-0100") == [("phone", "+49 151 23456789"), ("phone", "+1 (415) 555-0100")]
    assert kinds("version +1.2 and +12") == []


def test_ip_addresses_but_not_loopback_or_versions():
    assert kinds("from 84.163.22.17 and 10.0.0.5") == [("ipv4", "84.163.22.17"), ("ipv4", "10.0.0.5")]
    assert kinds("127.0.0.1 0.0.0.0 Chrome/120.0.6099.109 v1.2.3.4 version 2.0.0.1") == []
    assert kinds("addr 2001:db8:85a3::8a2e:370:7334 and ::1") == [("ipv6", "2001:db8:85a3::8a2e:370:7334")]
    assert kinds("at 10:15:30 and 12:00") == []


def test_mac_address_and_home_directories():
    assert kinds("eth0 a4:83:e7:12:9b:0c") == [("mac_address", "a4:83:e7:12:9b:0c")]
    assert kinds('File "/Users/maria/app.py"') == [("home_user", "maria")]
    assert kinds("/home/dev/.cache and C:\\Users\\Tom\\AppData") == [("home_user", "dev"), ("home_user", "Tom")]
    assert kinds("/Users/Shared/data") == []
    assert kinds("/home/… and /Users/<USER_1>/x") == []


def test_secret_wins_over_overlapping_matches():
    found = kinds(f"export GITHUB_TOKEN={h.GITHUB}")
    assert found == [("github_token", h.GITHUB)]


def test_keep_by_kind_or_category():
    text = "maria@gmail.com from 84.163.22.17 api_key=abcdef123"
    assert [k for k, _ in kinds(text, keep=frozenset({"ipv4"}))] == ["email", "assigned_secret"]
    assert [k for k, _ in kinds(text, keep=frozenset({"pii", "infra"}))] == ["assigned_secret"]


def test_terms_and_domains():
    text = "Acme GmbH runs db1.acme.internal and api.acme.internal; acmes is different; maria@acme.internal"
    found = kinds(text, terms=("Acme GmbH",), domains=("acme.internal",))
    assert [k for k, _ in found] == ["term", "domain", "domain", "email"]  # the email is hidden whole
