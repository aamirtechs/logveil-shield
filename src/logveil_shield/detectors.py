"""Detector definitions for logveil-shield.

Each detector is a named regular expression (optionally with a validator)
that finds one class of secret or sensitive value in free-form text.
Detectors are ordered by priority: earlier detectors win when two
patterns overlap the same span of text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional


def luhn_ok(digits: str) -> bool:
    """Return True if the digit string passes the Luhn checksum."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _valid_ipv4(match: re.Match) -> bool:
    try:
        return all(0 <= int(part) <= 255 for part in match.group(0).split("."))
    except ValueError:
        return False


def _valid_card(match: re.Match) -> bool:
    digits = re.sub(r"\D", "", match.group(0))
    return 13 <= len(digits) <= 19 and luhn_ok(digits)


_PLACEHOLDERS = {
    "none", "null", "nil", "changeme", "change-me", "xxx", "xxxx",
    "redacted", "[redacted]", "***", "your-key-here", "todo", "...",
    "undefined", "example",
}


def _not_placeholder(match: re.Match) -> bool:
    value = match.group("value") if "value" in match.groupdict() else match.group(0)
    return value.strip().lower() not in _PLACEHOLDERS


@dataclass
class Detector:
    """One sensitive-data pattern.

    name: short label used in reports and [REDACTED:NAME] markers.
    pattern: compiled regex.
    description: one line for humans, shown by --list-detectors.
    validator: optional extra check on the match (return False to skip).
    value_group: name of the regex group holding just the secret value,
        when the match also captures a key name to keep (e.g. env vars).
    """

    name: str
    pattern: re.Pattern
    description: str
    validator: Optional[Callable[[re.Match], bool]] = None
    value_group: Optional[str] = None


def _d(name, pattern, description, flags=0, **kwargs):
    return Detector(name=name, pattern=re.compile(pattern, flags), description=description, **kwargs)


DETECTORS: list[Detector] = [
    _d(
        "PEM_PRIVATE_KEY",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ED25519 )?PRIVATE KEY-----"
        r".*?"
        r"-----END (?:RSA |EC |DSA |OPENSSH |ED25519 )?PRIVATE KEY-----",
        "PEM private key blocks (RSA, EC, DSA, OpenSSH, Ed25519).",
        flags=re.DOTALL,
    ),
    _d(
        "DB_CONNECTION_STRING",
        r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?)://[^\s'\"]+",
        "Database connection strings (postgres, mysql, mongodb, redis).",
    ),
    _d(
        "URL_CREDENTIALS",
        r"https?://[^:/\s@]+:(?P<value>[^@\s/]+)@",
        "Passwords embedded in URLs (https://user:pass@host).",
        value_group="value",
    ),
    _d(
        "AWS_ACCESS_KEY",
        r"\bAKIA[0-9A-Z]{16}\b",
        "AWS access key IDs (AKIA...).",
    ),
    _d(
        "AWS_SECRET_KEY",
        r"(?i)(?P<key>aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*(?P<q>['\"]?)(?P<value>[A-Za-z0-9/+=]{30,})(?P=q)",
        "AWS secret access keys in assignments.",
        value_group="value",
        validator=_not_placeholder,
    ),
    _d(
        "GITHUB_TOKEN",
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b",
        "GitHub personal access and app tokens.",
    ),
    _d(
        "OPENAI_API_KEY",
        r"\bsk-[A-Za-z0-9]{20,}\b",
        "OpenAI API keys (sk-...).",
    ),
    _d(
        "STRIPE_KEY",
        r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b",
        "Stripe secret, publishable, and restricted keys.",
    ),
    _d(
        "SLACK_TOKEN",
        r"\bxox[abpras]-[A-Za-z0-9-]{10,}\b",
        "Slack bot, user, and app tokens.",
    ),
    _d(
        "JWT",
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        "JSON Web Tokens (header.payload.signature).",
    ),
    _d(
        "BEARER_TOKEN",
        r"(?P<key>[Bb]earer)\s+(?P<value>[A-Za-z0-9\-._~+/=]{10,})",
        "Bearer tokens in Authorization headers.",
        value_group="value",
        validator=_not_placeholder,
    ),
    _d(
        "API_SECRET",
        r"(?i)(?P<key>(?:[A-Za-z_][A-Za-z0-9_]*)?(?:api[_-]?key|api[_-]?secret|secret|password|passwd|pwd|token|client[_-]?secret)[A-Za-z0-9_]*)\s*[:=]\s*(?P<q>['\"]?)(?P<value>[^\s\"'#;,]{4,})(?P=q)",
        "Generic api_key / secret / password assignments.",
        value_group="value",
        validator=_not_placeholder,
    ),
    _d(
        "CREDIT_CARD",
        r"(?<!\d)\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}(?:[ -]?\d{1,3})?(?!\d)",
        "Credit card numbers (Luhn validated).",
        validator=_valid_card,
    ),
    _d(
        "EMAIL",
        r"(?<![\w:./-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "Email addresses.",
    ),
    _d(
        "IPV4",
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "IPv4 addresses (octets validated 0-255).",
        validator=_valid_ipv4,
    ),
    _d(
        "PHONE",
        r"(?<!\d)(?:\+\d{1,4}(?:[ .-]?\d){6,12}|\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4})(?!\d)",
        "Phone numbers (international and US style).",
    ),
]


def build_custom_detector(name: str, pattern: str) -> Detector:
    """Build a detector from a user-supplied NAME=PATTERN string."""
    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"invalid regex for --pattern {name!r}: {exc}") from exc
    return Detector(
        name=name.upper(),
        pattern=compiled,
        description=f"Custom pattern supplied with --pattern {name}.",
    )
