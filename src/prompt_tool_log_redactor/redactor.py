"""Secret and PII redaction for text and JSONL logs."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from re import Pattern
from typing import Any

MAX_RULES_FILE_BYTES = 256 * 1024
MAX_RULE_COUNT = 128
MAX_RULE_PATTERN_LENGTH = 4096
MAX_RULE_REPLACEMENT_LENGTH = 4096
DEFAULT_MAX_INPUT_BYTES = 10 * 1024 * 1024


@dataclass(frozen=True)
class RedactionRule:
    name: str
    pattern: Pattern[str]
    replacement: str


SENSITIVE_KEYS = {
    "access_key",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "credentials",
    "password",
    "passwd",
    "private_key",
    "pwd",
    "secret",
    "token",
}


def _compile(pattern: str, flags: int = 0) -> Pattern[str]:
    return re.compile(pattern, flags)


DEFAULT_RULES: tuple[RedactionRule, ...] = (
    RedactionRule("EMAIL", _compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED:EMAIL]"),
    RedactionRule("OPENAI_KEY", _compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"), "[REDACTED:SECRET]"),
    RedactionRule("GITHUB_TOKEN", _compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}_[A-Za-z0-9_]{20,})\b"), "[REDACTED:GITHUB_TOKEN]"),
    RedactionRule("AWS_ACCESS_KEY", _compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "[REDACTED:AWS_ACCESS_KEY]"),
    RedactionRule("SLACK_TOKEN", _compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED:SLACK_TOKEN]"),
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
        if not isinstance(name, str):
            raise ValueError("regex flags must be strings")
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


def _read_limited_bytes(handle: Any, max_bytes: int, description: str) -> bytes:
    if max_bytes < 0:
        raise ValueError(f"{description} limit must be non-negative")

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = handle.read(min(64 * 1024, max_bytes - total + 1))
        if chunk in (b"", ""):
            break
        if isinstance(chunk, str):
            try:
                chunk = chunk.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError(f"{description} must be valid UTF-8") from exc
        if not isinstance(chunk, (bytes, bytearray)):
            raise ValueError(f"unable to read {description}")
        chunk_bytes = bytes(chunk)
        total += len(chunk_bytes)
        if total > max_bytes:
            raise ValueError(f"{description} exceeds maximum size of {max_bytes} bytes")
        chunks.append(chunk_bytes)
    return b"".join(chunks)


def load_rules(path: str | None, max_rules_file_bytes: int = MAX_RULES_FILE_BYTES) -> list[RedactionRule]:
    """Load additional redaction rules from a JSON file."""
    if not path:
        return []
    with open(path, "rb") as handle:
        encoded = _read_limited_bytes(handle, max_rules_file_bytes, "rules file")
    try:
        raw = json.loads(encoded.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError("rules file must be valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"rules file is not valid JSON: {exc.msg}") from exc
    except RecursionError as exc:
        raise ValueError("rules file is too deeply nested") from exc
    if not isinstance(raw, list):
        raise ValueError("rules file must contain a JSON list")
    if len(raw) > MAX_RULE_COUNT:
        raise ValueError(f"rules file contains too many rules; maximum is {MAX_RULE_COUNT}")

    rules: list[RedactionRule] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"rule {index} must be an object")
        name = item.get("name", f"custom_{index}")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"rule {index} requires a non-empty string name")
        pattern = item.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            raise ValueError(f"rule {index} requires a non-empty pattern")
        if len(pattern) > MAX_RULE_PATTERN_LENGTH:
            raise ValueError(
                f"rule {index} pattern exceeds maximum length of {MAX_RULE_PATTERN_LENGTH} characters"
            )
        replacement = item.get("replacement", f"[REDACTED:{name.upper()}]")
        if not isinstance(replacement, str):
            raise ValueError(f"rule {index} replacement must be a string")
        if len(replacement) > MAX_RULE_REPLACEMENT_LENGTH:
            raise ValueError(
                f"rule {index} replacement exceeds maximum length of {MAX_RULE_REPLACEMENT_LENGTH} characters"
            )
        flags_names = item.get("flags", [])
        if not isinstance(flags_names, list):
            raise ValueError(f"rule {index} flags must be a list")
        flags = _flags_from_names(flags_names)
        try:
            compiled = re.compile(pattern, flags)
            compiled.sub(replacement, "")
        except (IndexError, OverflowError, re.error) as exc:
            raise ValueError(f"rule {index} contains an invalid regex or replacement: {exc}") from exc
        rules.append(RedactionRule(name, compiled, replacement))
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
