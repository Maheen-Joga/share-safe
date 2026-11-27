---
name: share-safe
description: Make logs, stack traces, config files, terminal output, HTTP requests and error messages safe to share by replacing API keys, tokens, passwords, private keys, cookies, emails, phone numbers, IBANs, card numbers, IP addresses and home-directory usernames with consistent placeholders. Use whenever text is about to leave the user's machine - a GitHub issue or PR, a gist, Slack, Stack Overflow, a support ticket, an email to a vendor, a bug report, documentation, or a prompt for another AI - and when the user asks "is this safe to share", "redact this", "anonymise these logs" or "remove secrets". Also use before you yourself paste command output or logs into an issue, PR description, commit message or public file.
---

# share-safe

People paste logs into public places every day, and those logs carry API keys, session cookies,
customers' email addresses and internal hostnames. Your job is to make sure what leaves the machine is
safe, while keeping the log useful to whoever reads it.

## When to act without being asked

Run this skill on your own before you put command output, logs, stack traces, HTTP traffic or config
into anything outside the user's machine: a GitHub issue or PR description, a gist, a commit message,
documentation, or a message you draft for them. If the user only pastes something into this chat to
ask for help, there is nothing to redact; it stays here.

## 1. Redact with the bundled tool

It is pure Python 3.10+ with no dependencies, in this skill's directory:

```bash
PYTHONPATH="<this skill's directory>" python3 -m share_safe <file> --map /tmp/share-safe-map.json -o <file>.safe
cat <text> | PYTHONPATH="<this skill's directory>" python3 -m share_safe
```

Use the base directory shown when this skill loaded. It prints a summary on standard error. Options:

- `--term "Acme GmbH"` hides a name everywhere (company, customer, project, colleague); repeatable.
- `--domain acme.internal` hides a domain and all its subdomains; repeatable.
- `--keep ipv4` or `--keep infra` leaves a kind or category alone when the reader needs it, e.g. a
  network bug where the IP matters. `python3 -m share_safe kinds` lists them.
- `--aggressive` also hides long random-looking strings no detector recognised.
- `--map FILE` saves placeholder -> original in a file only the user can read, so
  `python3 -m share_safe restore reply.md --map FILE` can put real values back into an answer later.
  Never share the map.

The same value always becomes the same placeholder (`<EMAIL_1>` in every line), so the log still
tells its story.

## 2. Read the result yourself

A pattern scan cannot know what is sensitive in this particular context. Read the redacted text once
and look for:

- names of people, customers or employers, and internal project or host names; rerun with `--term`
  or `--domain` for each, rather than editing by hand, so the placeholders stay consistent;
- anything the summary flagged as a random-looking string: decide whether it is a secret (rerun with
  `--aggressive`) or harmless (a request id, a hash);
- business data in payloads: order contents, addresses, health or financial details.

Ask the user only about things you cannot judge, in one short question, for example whether a hostname
is public.

## 3. Hand it over

Give the user the redacted text, ready to paste, and a short summary: what was replaced (by kind and
count) and anything you added with `--term` or `--domain`.

If the original contained a real credential (`secret` category) and there is any chance it was already
shared (pasted, committed, sent), say so plainly: the key must be revoked and replaced at its provider,
because redacting the copy does not un-leak it. Name the provider (GitHub, AWS, OpenAI, Stripe and so
on) from the placeholder.

## Rules

- Never repeat a secret or personal value in your own reply; refer to it by placeholder or by line.
- Do not weaken redaction to make a log "more useful" unless the user asks for a specific kind to be kept.
- `check` (`python3 -m share_safe check FILE`) exits 1 if anything sensitive is present; use it to verify
  a file before committing it, or suggest it as a pre-commit hook.
