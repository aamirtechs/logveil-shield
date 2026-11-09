"""Redaction engine for logveil-shield.

Scans text with the detectors, resolves overlaps by detector priority,
and replaces each sensitive value according to the selected mode:

- redact:    [REDACTED:TYPE]
- tokenize:  [TYPE_1], [TYPE_2], ... consistent per unique value, so logs
             stay correlatable after scrubbing
- hash:      [HASH:TYPE:abcdef123456] (first 12 hex chars of sha256)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .detectors import DETECTORS, Detector

MODES = ("redact", "tokenize", "hash")


@dataclass
class _Hit:
    start: int
    end: int
    detector: Detector
    value_start: int  # span of just the secret value (== match span for most detectors)
    value_end: int
    priority: int = 0  # lower = higher priority, set from detector order


class Redactor:
    """Stateful redactor. Reuse one instance per run so tokenize maps stay consistent."""

    def __init__(self, mode: str = "redact", extra_detectors: list[Detector] | None = None):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}, got {mode!r}")
        self.mode = mode
        self.detectors: list[Detector] = list(extra_detectors or []) + DETECTORS
        self.counts: dict[str, int] = {}
        self._tokens: dict[tuple[str, str], str] = {}
        self._token_counters: dict[str, int] = {}

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def _collect_hits(self, text: str) -> list[_Hit]:
        hits: list[_Hit] = []
        for priority, detector in enumerate(self.detectors):
            for match in detector.pattern.finditer(text):
                if detector.validator is not None and not detector.validator(match):
                    continue
                if detector.value_group:
                    value = match.groupdict().get(detector.value_group)
                    if not value:
                        continue
                    vstart, vend = match.span(detector.value_group)
                else:
                    value = match.group(0)
                    vstart, vend = match.span(0)
                hits.append(_Hit(match.start(), match.end(), detector, vstart, vend, priority))
        hits.sort(key=lambda h: (h.start, h.priority))
        return hits

    def _replacement(self, detector: Detector, value: str) -> str:
        label = detector.name
        if self.mode == "redact":
            return f"[REDACTED:{label}]"
        if self.mode == "hash":
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
            return f"[HASH:{label}:{digest}]"
        # tokenize
        key = (label, value)
        token = self._tokens.get(key)
        if token is None:
            n = self._token_counters.get(label, 0) + 1
            self._token_counters[label] = n
            token = f"[{label}_{n}]"
            self._tokens[key] = token
        return token

    def scrub(self, text: str) -> str:
        """Return text with every detected sensitive value replaced."""
        hits = self._collect_hits(text)
        out: list[str] = []
        cursor = 0
        for hit in hits:
            if hit.start < cursor:
                continue  # overlapped by a higher-priority detector
            out.append(text[cursor:hit.value_start])
            value = text[hit.value_start:hit.value_end]
            out.append(self._replacement(hit.detector, value))
            out.append(text[hit.value_end:hit.end])  # trailing quote, @, etc.
            self.counts[hit.detector.name] = self.counts.get(hit.detector.name, 0) + 1
            cursor = hit.end
        out.append(text[cursor:])
        return "".join(out)

    def found_any(self, text: str) -> bool:
        """True if any detector matches text (used by --check, does not mutate counts)."""
        for detector in self.detectors:
            for match in detector.pattern.finditer(text):
                if detector.validator is None or detector.validator(match):
                    if detector.value_group and not match.group(detector.value_group):
                        continue
                    return True
        return False
