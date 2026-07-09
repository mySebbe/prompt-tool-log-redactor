# prompt-tool-log-redactor

`prompt-tool-log-redactor` redacts common secrets and PII from plain text or JSONL logs. It is stdlib-only and supports custom regex rules in a JSON file.

## 0.1.2 Highlights

- `--check` mode now detects redactable content without writing redacted output.
- CI workflows can fail fast when logs still contain secrets or personal data.

## Install

```bash
python -m pip install .
```

## CLI

```bash
prompt-tool-log-redactor logs.txt
prompt-tool-log-redactor --jsonl trace.jsonl
prompt-tool-log-redactor --rules rules.json < logs.txt
prompt-tool-log-redactor --check logs.txt
prompt-tool-log-redactor --max-bytes 5242880 logs.txt
python -m prompt_tool_log_redactor --output redacted.txt logs.txt
```

Custom rules file:

```json
[
  {"name": "tenant", "pattern": "TENANT-[0-9]+", "replacement": "[TENANT]"}
]
```

Built-in redactions include email addresses, OpenAI-style `sk-` keys, bearer tokens, password assignments, secret assignments, SSNs, and likely card numbers.

## Safety limits

Custom rule files are limited to 256 KiB and 128 rules. Each rule pattern and replacement is limited to 4,096 characters. Invalid or oversized rules are rejected before processing and the CLI exits with code `2`.

Input is read as UTF-8 and limited to 10 MiB by default. Use `--max-bytes BYTES` to choose a different non-negative byte limit. An input that exceeds the limit also exits with code `2`, including in `--check` mode.

`--check` never writes output: it exits with code `0` for unchanged input, `1` when redactions are needed, and `2` for invalid arguments, rules, or oversized input. Custom patterns use Python regular expressions; only load rules from trusted sources because pattern complexity can still affect processing time.

## Development

```bash
python -m unittest discover -s tests
```
