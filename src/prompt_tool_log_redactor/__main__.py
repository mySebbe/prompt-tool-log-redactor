"""CLI entry point for prompt-tool-log-redactor."""

from __future__ import annotations

import argparse
import re
import sys

from ._version import __version__
from .redactor import DEFAULT_MAX_INPUT_BYTES, load_rules, redact_jsonl, redact_text


def _non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a non-negative integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return parsed


def _read_limited(stream: object, max_bytes: int) -> str:
    if max_bytes < 0:
        raise ValueError("input limit must be non-negative")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = stream.read(min(64 * 1024, max_bytes - total + 1))  # type: ignore[attr-defined]
        if chunk in (b"", ""):
            break
        if isinstance(chunk, str):
            try:
                chunk = chunk.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError("input must be valid UTF-8") from exc
        if not isinstance(chunk, (bytes, bytearray)):
            raise ValueError("unable to read input")
        chunk_bytes = bytes(chunk)
        total += len(chunk_bytes)
        if total > max_bytes:
            raise ValueError(f"input exceeds maximum size of {max_bytes} bytes")
        chunks.append(chunk_bytes)
    try:
        return b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("input must be valid UTF-8") from exc


def _read(path: str | None, max_bytes: int = DEFAULT_MAX_INPUT_BYTES) -> str:
    if max_bytes < 0:
        raise ValueError("input limit must be non-negative")
    if not path or path == "-":
        return _read_limited(getattr(sys.stdin, "buffer", sys.stdin), max_bytes)
    with open(path, "rb") as handle:
        return _read_limited(handle, max_bytes)


def _write(path: str | None, text: str) -> None:
    if not path or path == "-":
        sys.stdout.write(text)
        return
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Redact common secrets and PII from text or JSONL logs.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("path", nargs="?", help="Input file. Reads stdin when omitted or '-'.")
    parser.add_argument("--jsonl", action="store_true", help="Treat input as newline-delimited JSON.")
    parser.add_argument("--rules", help="JSON file with custom regex redaction rules.")
    parser.add_argument("--output", "-o", help="Output file. Writes stdout when omitted.")
    parser.add_argument(
        "--max-bytes",
        type=_non_negative_int,
        default=DEFAULT_MAX_INPUT_BYTES,
        metavar="BYTES",
        help=f"Maximum UTF-8 input size (default: {DEFAULT_MAX_INPUT_BYTES} bytes).",
    )
    parser.add_argument("--check", action="store_true", help="Exit 1 if input contains redactable content without writing output.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        rules = load_rules(args.rules)
        text = _read(args.path, args.max_bytes)
        redacted = redact_jsonl(text, rules) if args.jsonl else redact_text(text, rules)
        if args.check:
            if redacted != text:
                print("prompt-tool-log-redactor: redactions needed", file=sys.stderr)
                return 1
            return 0
        _write(args.output, redacted)
    except (OSError, ValueError, re.error) as exc:
        print(f"prompt-tool-log-redactor: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
