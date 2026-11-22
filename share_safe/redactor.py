"""Find sensitive values in text: every detector runs, overlaps are resolved so that secrets win
over personal data and personal data over infrastructure details."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .detectors import CATEGORIES, DETECTORS, PRIORITY, Detector

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
