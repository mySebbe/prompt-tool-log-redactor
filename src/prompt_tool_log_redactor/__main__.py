"""CLI entry point for prompt-tool-log-redactor."""

from __future__ import annotations

import argparse
import sys

from ._version import __version__
from .redactor import load_rules, redact_jsonl, redact_text


def _read(path: str | None) -> str:
    if not path or path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as handle:
        return handle.read()


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
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        rules = load_rules(args.rules)
        text = _read(args.path)
        redacted = redact_jsonl(text, rules) if args.jsonl else redact_text(text, rules)
        _write(args.output, redacted)
    except (OSError, ValueError) as exc:
        print(f"prompt-tool-log-redactor: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
