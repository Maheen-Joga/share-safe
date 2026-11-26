"""Command line.

  share-safe error.log                 redact and print (or read standard input)
  share-safe check config.yml          exit 1 if anything sensitive is found
  share-safe restore reply.md --map m.json
  share-safe kinds                     list what is detected
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .detectors import CATEGORIES, DETECTORS
from .redactor import Options, describe, find, line_of, mask, redact, restore

EXIT_OK, EXIT_FOUND, EXIT_INPUT = 0, 1, 2
COMMANDS = {"redact", "check", "restore", "kinds"}


def _read(paths: list[str]) -> list[tuple[str, str]]:
    if not paths or paths == ["-"]:
        return [("<stdin>", sys.stdin.read())]
    out = []
    for p in paths:
        out.append((p, Path(p).read_text(encoding="utf-8", errors="replace")))
    return out


def _options(args: argparse.Namespace) -> Options:
    keep = frozenset(k.strip() for item in args.keep for k in item.split(",") if k.strip())
    known = {d.kind for d in DETECTORS} | set(CATEGORIES)
    unknown = sorted(keep - known)
    if unknown:
        raise ValueError(f"unknown kind or category in --keep: {', '.join(unknown)} (see `share-safe kinds`)")
    return Options(keep=keep, terms=tuple(args.term), domains=tuple(args.domain), aggressive=args.aggressive)


def _write_map(path: str, mapping: dict[str, str]) -> None:
    """The map holds the original secrets, so it is created readable by you only."""
    existing = json.loads(Path(path).read_text(encoding="utf-8")) if Path(path).exists() else {}
    existing.update(mapping)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(existing, fh, indent=2, ensure_ascii=False)


def cmd_redact(args: argparse.Namespace) -> int:
    opts = _options(args)
    mapping = json.loads(Path(args.map).read_text(encoding="utf-8")) if args.map and Path(args.map).exists() else {}
    outputs, total, suspicious = [], {}, []
    for name, text in _read(args.files):
        res = redact(text, opts, mapping)
        mapping = res.mapping
        outputs.append((name, res.text))
        for k, v in res.counts.items():
            total[k] = total.get(k, 0) + v
        suspicious += [(name, line, m) for line, m in res.suspicious]
    body = outputs[0][1] if len(outputs) == 1 else "".join(f"===== {n} =====\n{t}" for n, t in outputs)
    if args.output:
        Path(args.output).write_text(body, encoding="utf-8")
    else:
        sys.stdout.write(body)
    if args.map:
        _write_map(args.map, mapping)
    if not args.quiet:
        n = sum(total.values())
        print(f"share-safe: replaced {n} value{'s' if n != 1 else ''}"
              + (": " + ", ".join(f"{v} {k}" for k, v in sorted(total.items(), key=lambda kv: -kv[1])) if n else ""),
              file=sys.stderr)
        for name, line, m in suspicious:
            print(f"share-safe: check {name}:{line}, random-looking string {m} was left in (use --aggressive to hide it)",
                  file=sys.stderr)
        if args.map:
            print(f"share-safe: map written to {args.map}; it contains the originals, never share it", file=sys.stderr)
        print("share-safe: read it once before sharing; names, customers and internal details can still be in there",
              file=sys.stderr)
    return EXIT_OK


def cmd_check(args: argparse.Namespace) -> int:
    opts = _options(args)
    found = 0
    for name, text in _read(args.files):
        for h in find(text, opts):
            found += 1
            print(f"{name}:{line_of(text, h.start)}: {h.category} {h.kind} {mask(h.value)}")
    if found:
        print(f"{found} sensitive value{'s' if found != 1 else ''} found; run `share-safe {' '.join(args.files)}` to redact",
              file=sys.stderr)
        return EXIT_FOUND
    print("nothing sensitive found", file=sys.stderr)
    return EXIT_OK


def cmd_restore(args: argparse.Namespace) -> int:
    mapping = json.loads(Path(args.map).read_text(encoding="utf-8"))
    for _, text in _read(args.files):
        sys.stdout.write(restore(text, mapping))
    return EXIT_OK


def cmd_kinds(_: argparse.Namespace) -> int:
    for cat in CATEGORIES:
        print(f"{cat}:")
        for d in DETECTORS:
            if d.category == cat:
                print(f"  {d.kind:<18} <{d.label}_n>  {describe(d.kind)}")
    return EXIT_OK


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("files", nargs="*", help="files to read (default: standard input)")
    p.add_argument("--keep", action="append", default=[], metavar="KINDS",
                   help="comma-separated kinds or categories to leave alone, e.g. --keep ipv4,infra")
    p.add_argument("--term", action="append", default=[], metavar="WORD",
                   help="also hide this word everywhere, e.g. a company or customer name (repeatable)")
    p.add_argument("--domain", action="append", default=[], metavar="DOMAIN",
                   help="also hide this domain and its subdomains, e.g. acme.internal (repeatable)")
    p.add_argument("--aggressive", action="store_true", help="also hide long random-looking strings")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="share-safe", description="Make logs, configs and error messages safe to share: "
                                "API keys, tokens, passwords, emails, IPs and more are replaced by consistent placeholders.")
    p.add_argument("--version", action="version", version=f"share-safe {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("redact", help="replace sensitive values with placeholders (the default)")
    _common(r)
    r.add_argument("-o", "--output", metavar="FILE", help="write the result here instead of standard output")
    r.add_argument("--map", metavar="FILE", help="save placeholder -> original to this private file, for `restore`")
    r.add_argument("-q", "--quiet", action="store_true", help="no summary on standard error")
    r.set_defaults(func=cmd_redact)
    c = sub.add_parser("check", help="exit 1 if anything sensitive is found (for scripts and git hooks)")
    _common(c)
    c.set_defaults(func=cmd_check)
    s = sub.add_parser("restore", help="put the original values back using a saved map")
    s.add_argument("files", nargs="*")
    s.add_argument("--map", required=True, metavar="FILE")
    s.set_defaults(func=cmd_restore)
    sub.add_parser("kinds", help="list what is detected").set_defaults(func=cmd_kinds)
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0] not in COMMANDS and argv[0] not in {"-h", "--help", "--version"}):
        argv.insert(0, "redact")
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except OSError as e:
        print(f"error: {e.filename}: {e.strerror}", file=sys.stderr)
        return EXIT_INPUT
    except (ValueError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_INPUT
