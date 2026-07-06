# Changelog

All notable changes to `prompt-tool-log-redactor` will be documented in this file.

The format is based on Keep a Changelog, and this project uses semantic versioning.

## [Unreleased]

- No unreleased changes yet.

## [0.1.2] - 2026-07-06

- Updated GitHub Actions workflow dependencies to current major versions.
- Modernized package license metadata to avoid current Setuptools deprecation warnings.
- Added `--check` mode to detect redactable input without writing output.
- Returned exit code `1` when check mode finds secrets or personal data.

## [0.1.1] - 2026-06-17

- Added default rules for GitHub tokens, AWS access keys, and Slack tokens.
- Expanded sensitive JSON key detection for credentials, access keys, and private keys.
- Fixed GitHub Actions workflow pins to supported action versions.

## [0.1.0] - 2026-06-03

- Initial open-source release with CLI, examples, tests, GitHub workflows, security policy, and contributor docs.
