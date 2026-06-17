# prompt-tool-log-redactor

`prompt-tool-log-redactor` redacts common secrets and PII from plain text or JSONL logs. It is stdlib-only and supports custom regex rules in a JSON file.

## 0.1.1 Highlights

- Default redaction now covers GitHub tokens, AWS access keys, and Slack tokens.
- JSONL redaction treats more nested key names as sensitive, including credentials and private keys.

## Install

```bash
python -m pip install .
```

## CLI

```bash
prompt-tool-log-redactor logs.txt
prompt-tool-log-redactor --jsonl trace.jsonl
prompt-tool-log-redactor --rules rules.json < logs.txt
python -m prompt_tool_log_redactor --output redacted.txt logs.txt
```

Custom rules file:

```json
[
  {"name": "tenant", "pattern": "TENANT-[0-9]+", "replacement": "[TENANT]"}
]
```

Built-in redactions include email addresses, OpenAI-style `sk-` keys, bearer tokens, password assignments, secret assignments, SSNs, and likely card numbers.

## Development

```bash
python -m unittest discover -s tests
```
