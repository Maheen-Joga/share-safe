from share_safe import Options, redact, restore
from share_safe.redactor import mask, random_strings

from . import helpers as h


def test_same_value_same_placeholder_different_value_new_number():
    r = redact("a maria@gmail.com b tom@gmx.de c maria@gmail.com")
    assert r.text == "a <EMAIL_1> b <EMAIL_2> c <EMAIL_1>"
    assert r.mapping == {"<EMAIL_1>": "maria@gmail.com", "<EMAIL_2>": "tom@gmx.de"}
    assert r.counts["email"] == 3


def test_kinds_are_numbered_separately():
    r = redact(f"{h.GITHUB} 84.163.22.17 {h.AWS} 10.0.0.9")
    assert r.text == "<GITHUB_TOKEN_1> <IP_1> <AWS_ACCESS_KEY_1> <IP_2>"


def test_restore_is_exact():
    text = f"user maria@gmail.com\ntoken {h.GITHUB}\n{h.PEM}\npath /Users/maria/x"
    r = redact(text)
    assert h.GITHUB not in r.text and "maria" not in r.text and "PRIVATE KEY" not in r.text
    assert restore(r.text, r.mapping) == text


def test_restore_leaves_unknown_placeholders():
    assert restore("<EMAIL_9> and <EMAIL_1>", {"<EMAIL_1>": "a@b.de"}) == "<EMAIL_9> and a@b.de"


def test_existing_mapping_keeps_numbers_stable_across_files():
    first = redact("maria@gmail.com")
    second = redact("tom@gmx.de then maria@gmail.com", mapping=first.mapping)
    assert second.text == "<EMAIL_2> then <EMAIL_1>"


def test_already_redacted_text_is_unchanged():
    r = redact("password: <SECRET_1> and <EMAIL_3>")
    assert r.text == "password: <SECRET_1> and <EMAIL_3>" and r.mapping == {}


def test_random_strings_are_reported_not_redacted_by_default():
    blob = "Zq8Lm2Np4Rt6Vx9Bc1Df3Gh5Jk7Mn0Pq2Rs4"
    r = redact(f"x-signature: {blob}")
    assert blob in r.text and r.suspicious == [(1, "Zq8L…")]


def test_aggressive_redacts_random_strings():
    blob = "Zq8Lm2Np4Rt6Vx9Bc1Df3Gh5Jk7Mn0Pq2Rs4"
    r = redact(f"x-signature: {blob}", Options(aggressive=True))
    assert r.text == "x-signature: <SECRET_1>" and r.suspicious == []


def test_git_hashes_and_paths_are_not_random_strings():
    text = "commit 3f9c2a1b7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a /usr/local/lib/python3.12/site-packages/thing"
    assert random_strings(text) == []


def test_mask_shows_only_a_prefix():
    assert mask("maria@gmail.com") == "m…@…" and mask("abcdefghijk") == "abcd…" and mask("abc") == "…"


def test_a_realistic_log():
    log = (f"2026-11-22 INFO connect postgres://app:S3cr3tPw!@db.acme.internal:5432/orders\n"
           f"2026-11-22 DEBUG Authorization: Bearer {h.OPENAI}\n"
           f"2026-11-22 ERROR user maria.schmidt@gmail.com (84.163.22.17) card 4111 1111 1111 1111\n"
           f'  File "/Users/maria/shop/app.py", line 42\n'
           f"GITHUB_TOKEN={h.GITHUB}\n")
    r = redact(log, Options(domains=("acme.internal",)))
    for secret in ("S3cr3tPw", h.OPENAI, "maria", "84.163", "4111", h.GITHUB, "acme"):
        assert secret not in r.text, secret
    assert "postgres://app:<PASSWORD_1>@<HOST_1>:5432/orders" in r.text
    assert 'File "/Users/<USER_1>/shop/app.py", line 42' in r.text
    assert restore(r.text, r.mapping) == log
