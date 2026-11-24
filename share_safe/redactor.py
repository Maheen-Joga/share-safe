"""Find sensitive values and replace them with consistent placeholders.

The same value always gets the same placeholder, so a log stays readable: if one email address
appears in twenty lines, all twenty say <EMAIL_1>, and a different address says <EMAIL_2>. The
mapping can be saved to restore the original values in a reply later; it never leaves your machine.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

from .detectors import BY_KIND, CATEGORIES, DETECTORS, PRIORITY, SECRET, Detector

PLACEHOLDER = re.compile(r"<([A-Z][A-Z0-9_]*)_(\d+)>")


@dataclass(frozen=True)
class Hit:
    kind: str
    category: str
    label: str
    start: int
    end: int
    value: str


@dataclass
class Options:
    keep: frozenset[str] = frozenset()  # kinds or categories not to redact, e.g. {"ipv4", "infra"}
    terms: tuple[str, ...] = ()  # extra words to hide: company, project or customer names
    domains: tuple[str, ...] = ()  # hide these domains and every subdomain, e.g. "acme.internal"
    aggressive: bool = False  # also redact long random-looking strings that no detector recognised


@dataclass
class Result:
    text: str
    mapping: dict[str, str]  # placeholder -> original value
    counts: Counter = field(default_factory=Counter)  # kind -> number of replaced occurrences
    suspicious: list[tuple[int, str]] = field(default_factory=list)  # (line, masked string) left in the text


def _active(options: Options) -> list[Detector]:
    return [d for d in DETECTORS if d.kind not in options.keep and d.category not in options.keep]


def _extra_detectors(options: Options) -> list[Detector]:
    out = []
    for term in (t for t in options.terms if t.strip()):
        out.append(Detector("term", "infra", "TERM", re.compile(r"(?<!\w)" + re.escape(term.strip()) + r"(?!\w)", re.I)))
    for domain in (d for d in options.domains if d.strip()):
        dom = re.escape(domain.strip().lstrip(".").lower())
        out.append(Detector("domain", "infra", "HOST",
                            re.compile(r"(?<![\w.\-])(?:[A-Za-z0-9\-]+\.)*" + dom + r"(?![\w\-])", re.I)))
    return out


def find(text: str, options: Options | None = None) -> list[Hit]:
    """All sensitive spans, without overlaps. Secrets win over personal data, which wins over infra;
    within a category your own terms and domains come first, then the more specific detector (earlier
    in the list), then the longer match. A term inside an email address therefore never splits it."""
    options = options or Options()
    detectors = _extra_detectors(options) + _active(options)
    custom = {"term", "domain"}
    rank = {d.kind: (0 if d.kind in custom else 1, PRIORITY.get(d.kind, -1)) for d in detectors}
    candidates: list[Hit] = []
    for det in detectors:
        for m in det.pattern.finditer(text):
            value = m.group(det.group)
            if not value or PLACEHOLDER.fullmatch(value):
                continue
            if det.validate and not det.validate(value, m, text):
                continue
            s, e = m.span(det.group)
            candidates.append(Hit(det.kind, det.category, det.label, s, e, value))
    order = {c: i for i, c in enumerate(CATEGORIES)}
    candidates.sort(key=lambda h: (order.get(h.category, 9),
                                   rank[h.kind], -(h.end - h.start), h.start))
    taken: list[Hit] = []
    for h in candidates:
        if all(h.end <= t.start or h.start >= t.end for t in taken):
            taken.append(h)
    return sorted(taken, key=lambda h: h.start)


def _entropy(s: str) -> float:
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


RANDOM_LOOKING = re.compile(r"(?<![A-Za-z0-9_\-+/])[A-Za-z0-9_\-+/]{32,}={0,2}(?![A-Za-z0-9_\-+/])")


def random_strings(text: str) -> list[re.Match]:
    """Long strings with mixed case, digits and high entropy: possibly a secret no detector knows.
    Hex-only strings (git hashes, checksums) and placeholders are ignored."""
    out = []
    for m in RANDOM_LOOKING.finditer(text):
        s = m.group(0)
        if re.fullmatch(r"[0-9a-fA-F]+", s) or "/" in s.strip("/") and s.count("/") > 2:
            continue
        if re.search(r"[a-z]", s) and re.search(r"[A-Z]", s) and re.search(r"\d", s) and _entropy(s) > 4.0:
            out.append(m)
    return out


def mask(value: str) -> str:
    """Show just enough of a value to recognise it: 'ghp_…' or 'a…@…'."""
    if "@" in value:
        return value[0] + "…@…"
    return value[:4] + "…" if len(value) > 6 else "…"


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def redact(text: str, options: Options | None = None, mapping: dict[str, str] | None = None) -> Result:
    """Replace every sensitive value with a placeholder. Pass the mapping from a previous call to
    keep placeholders stable across several files."""
    options = options or Options()
    mapping = dict(mapping or {})
    reverse = {(PLACEHOLDER.fullmatch(p).group(1), v): p for p, v in mapping.items() if PLACEHOLDER.fullmatch(p)}
    next_n = Counter()
    for p in mapping:
        m = PLACEHOLDER.fullmatch(p)
        if m:
            next_n[m.group(1)] = max(next_n[m.group(1)], int(m.group(2)))
    hits = find(text, options)
    if options.aggressive:
        covered = [(h.start, h.end) for h in hits]
        for m in random_strings(text):
            if all(m.end() <= s or m.start() >= e for s, e in covered):
                hits.append(Hit("random_string", SECRET, "SECRET", m.start(), m.end(), m.group(0)))
        hits.sort(key=lambda h: h.start)
    counts: Counter = Counter()
    pieces, cursor = [], 0
    for h in hits:
        key = (h.label, h.value)
        if key not in reverse:
            next_n[h.label] += 1
            placeholder = f"<{h.label}_{next_n[h.label]}>"
            reverse[key] = placeholder
            mapping[placeholder] = h.value
        pieces += [text[cursor:h.start], reverse[key]]
        cursor = h.end
        counts[h.kind] += 1
    out = "".join(pieces) + text[cursor:]
    suspicious = [(line_of(out, m.start()), mask(m.group(0))) for m in random_strings(out)]
    return Result(out, mapping, counts, suspicious)


def restore(text: str, mapping: dict[str, str]) -> str:
    """Put the original values back, e.g. into a reply that quotes the redacted log."""
    return PLACEHOLDER.sub(lambda m: mapping.get(m.group(0), m.group(0)), text)


def describe(kind: str) -> str:
    d = BY_KIND.get(kind)
    return (d.description or d.label.replace("_", " ").lower()) if d else kind.replace("_", " ")
