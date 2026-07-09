# Security Review 2026-07

## Executive summary

This review covers custom JSON rule ingestion and command-line processing of large text or JSONL logs. The implementation now bounds the bytes read before parsing, bounds the number and size of custom rules, validates regex patterns and replacement templates, and preserves the documented `--check` exit-code contract.

No unresolved high-confidence finding was identified in the reviewed scope. The residual risk is that Python regular expressions do not provide a built-in execution timeout, so custom rules should come from trusted sources.

## Findings

### SR-01: Unbounded custom rule ingestion

**Severity:** Medium, resolved

Before this change, a rules file could be read and expanded without limits. The loader now rejects files over 256 KiB, lists over 128 rules, patterns over 4,096 characters, and replacements over 4,096 characters before creating the active rule set. Invalid JSON, rule shapes, flags, regexes, and replacement templates are rejected as user errors.

Relevant implementation: `src/prompt_tool_log_redactor/redactor.py:85-158`, including `load_rules`.

### SR-02: Unbounded input ingestion

**Severity:** Medium, resolved

Before this change, the CLI read the complete input stream into memory. The CLI now reads UTF-8 input with a byte limit of 10 MiB by default. `--max-bytes` allows an operator to select a different non-negative limit while retaining bounded reads. Oversized input is rejected before redaction and returns exit code `2`.

Relevant implementation: `src/prompt_tool_log_redactor/__main__.py:23-54` and `:83-99`, covering `_read_limited`, `_read`, and CLI handling.

### SR-03: Regular-expression CPU complexity

**Severity:** Medium, accepted residual risk

The project uses Python's `re` engine for custom patterns. Length limits reduce parser and memory exposure but do not guarantee protection from catastrophic backtracking. Rule files should therefore be treated as configuration from a trusted source. A future hardening option is to use a regex engine with execution timeouts or to validate patterns with a safe-regex analysis before loading them.

## Exit-code contract

- `0`: input is clean, or normal redaction completed successfully.
- `1`: `--check` found content that would be changed.
- `2`: invalid arguments, invalid rules, invalid UTF-8, or an input/rules file over its configured limit.

The `--check` path performs no output write, including when an output path is supplied.

## Verification

Verified on 2026-07-09 with:

```text
python -m unittest discover -s tests
ruff check .
bandit -r src
python -m pip_audit
python -m build --sdist --wheel
```

Results: 15 tests passed; Ruff passed; Bandit reported no issues; pip-audit reported no known vulnerabilities and skipped only the local `smolagents` `1.27.0.dev0` dependency because it is not available on PyPI; and both sdist and wheel builds succeeded.
