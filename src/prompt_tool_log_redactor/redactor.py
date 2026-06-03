"""Secret and PII redaction for text and JSONL logs."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from re import Pattern
from typing import Any


@dataclass(frozen=True)
class RedactionRule:
    name: str
    pattern: Pattern[str]
    replacement: str


SENSITIVE_KEYS = {"password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "authorization"}


def _compile(pattern: str, flags: int = 0) -> Pattern[str]:
    return re.compile(pattern, flags)


DEFAULT_RULES: tuple[RedactionRule, ...] = (
    RedactionRule("EMAIL", _compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED:EMAIL]"),
    RedactionRule("OPENAI_KEY", _compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"), "[REDACTED:SECRET]"),
    RedactionRule("BEARER", _compile(r"(?i)\bBearer\s+(?:Bearer\s+)?[A-Za-z0-9._~+/=-]+"), "Bearer [REDACTED:BEARER]"),
    RedactionRule(
        "PASSWORD",
        _compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*([^\s,;]+)"),
        r"\1=[REDACTED:PASSWORD]",
    ),
    RedactionRule(
        "SECRET_ASSIGNMENT",
        _compile(r"(?i)\b(api[_-]?key|token|secret)\s*[:=]\s*([^\s,;]+)"),
        r"\1=[REDACTED:SECRET]",
    ),
    RedactionRule("SSN", _compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED:SSN]"),
    RedactionRule("CREDIT_CARD", _compile(r"\b(?:\d[ -]*?){13,16}\b"), "[REDACTED:CARD]"),
)


def _flags_from_names(names: Iterable[str]) -> int:
    flags = 0
    for name in names:
        normalized = name.upper()
        if normalized == "IGNORECASE":
            flags |= re.IGNORECASE
        elif normalized == "MULTILINE":
            flags |= re.MULTILINE
        elif normalized == "DOTALL":
            flags |= re.DOTALL
        else:
            raise ValueError(f"unsupported regex flag: {name}")
    return flags


def load_rules(path: str | None) -> list[RedactionRule]:
    """Load additional redaction rules from a JSON file."""
    if not path:
        return []
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, list):
        raise ValueError("rules file must contain a JSON list")

    rules: list[RedactionRule] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"rule {index} must be an object")
        name = str(item.get("name") or f"custom_{index}")
        pattern = item.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            raise ValueError(f"rule {index} requires a non-empty pattern")
        replacement = str(item.get("replacement", f"[REDACTED:{name.upper()}]"))
        flags = _flags_from_names(item.get("flags", []))
        rules.append(RedactionRule(name, re.compile(pattern, flags), replacement))
    return rules


def redact_text(text: str, rules: Iterable[RedactionRule] | None = None) -> str:
    """Redact common secrets and PII from a string."""
    redacted = text
    for rule in (*DEFAULT_RULES, *(rules or [])):
        redacted = rule.pattern.sub(rule.replacement, redacted)
    return redacted


def _redact_json_value(value: Any, rules: Iterable[RedactionRule], key: str | None = None) -> Any:
    if isinstance(value, dict):
        return {k: _redact_json_value(v, rules, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_json_value(item, rules, key) for item in value]
    if isinstance(value, str):
        if key and key.lower() in SENSITIVE_KEYS:
            label = "PASSWORD" if key.lower() in {"password", "passwd", "pwd"} else "SECRET"
            return f"[REDACTED:{label}]"
        return redact_text(value, rules)
    return value


def redact_jsonl(text: str, rules: Iterable[RedactionRule] | None = None) -> str:
    """Redact strings inside newline-delimited JSON logs."""
    active_rules = list(rules or [])
    output: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            output.append(line)
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            output.append(redact_text(line, active_rules))
            continue
        output.append(json.dumps(_redact_json_value(value, active_rules), ensure_ascii=False, separators=(",", ":")))
    return "\n".join(output) + ("\n" if text.endswith("\n") else "")
