# Contributing

## Local Setup

```bash
python -m pip install -e .
python -m unittest discover -s tests
```

## Guidelines

- Keep rules conservative enough to avoid excessive false positives.
- Add tests for new redaction categories.
- Do not add network calls to tests.
- Prefer stdlib APIs over dependencies.

Release instructions live in [PUBLISHING.md](PUBLISHING.md).
