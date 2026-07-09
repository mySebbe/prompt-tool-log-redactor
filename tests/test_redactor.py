import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from prompt_tool_log_redactor.redactor import (
    MAX_RULE_COUNT,
    MAX_RULE_PATTERN_LENGTH,
    MAX_RULE_REPLACEMENT_LENGTH,
    MAX_RULES_FILE_BYTES,
    load_rules,
    redact_jsonl,
    redact_text,
)


class RedactorTests(unittest.TestCase):
    def _run_cli(self, *arguments, input_text=""):
        env = os.environ.copy()
        env["PYTHONPATH"] = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
        return subprocess.run(
            [sys.executable, "-m", "prompt_tool_log_redactor", *arguments],
            input=input_text,
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )

    def _write_rules(self, rules, mode="w"):
        with tempfile.NamedTemporaryFile(mode, suffix=".json", delete=False) as handle:
            if "b" in mode:
                handle.write(rules)
            else:
                json.dump(rules, handle)
            path = handle.name
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return path

    def test_redact_text_masks_common_secrets_and_pii(self):
        text = (
            "email alice@example.invalid password=not-a-real-example-password "
            "api_key=not-a-real-example-key bearer Bearer not-a-real-example-token"
        )

        redacted = redact_text(text)

        self.assertNotIn("alice@example.invalid", redacted)
        self.assertNotIn("not-a-real-example-password", redacted)
        self.assertNotIn("not-a-real-example-key", redacted)
        self.assertNotIn("not-a-real-example-token", redacted)
        self.assertIn("[REDACTED:EMAIL]", redacted)

    def test_custom_json_rules_are_applied(self):
        path = self._write_rules([{"name": "tenant", "pattern": "TENANT-[0-9]+", "replacement": "[TENANT]"}])

        rules = load_rules(path)

        self.assertEqual(redact_text("id TENANT-1234", rules), "id [TENANT]")

    def test_custom_rules_reject_oversized_file(self):
        path = self._write_rules(b"[]" + b" " * MAX_RULES_FILE_BYTES, mode="wb")

        with self.assertRaisesRegex(ValueError, "rules file exceeds maximum size"):
            load_rules(path)

    def test_custom_rules_reject_too_many_rules(self):
        rules = [{"pattern": "x"} for _ in range(MAX_RULE_COUNT + 1)]
        path = self._write_rules(rules)

        with self.assertRaisesRegex(ValueError, "too many rules"):
            load_rules(path)

    def test_custom_rules_reject_oversized_pattern_and_replacement(self):
        oversized_rules = (
            {"pattern": "x" * (MAX_RULE_PATTERN_LENGTH + 1)},
            {"pattern": "x", "replacement": "x" * (MAX_RULE_REPLACEMENT_LENGTH + 1)},
        )
        for rule in oversized_rules:
            with self.subTest(rule=rule):
                path = self._write_rules([rule])
                with self.assertRaisesRegex(ValueError, "maximum length"):
                    load_rules(path)

    def test_custom_rules_reject_invalid_regex_and_replacement(self):
        invalid_rules = (
            {"pattern": "["},
            {"pattern": "token", "replacement": r"\g<missing>"},
            {"pattern": "token", "flags": "IGNORECASE"},
        )
        for rule in invalid_rules:
            with self.subTest(rule=rule):
                path = self._write_rules([rule])
                with self.assertRaises(ValueError):
                    load_rules(path)

    def test_redact_text_masks_common_platform_tokens(self):
        github_token = "ghp_" + "abcdefghijklmnopqrstuvwxyz1234567890"
        github_pat = "github_pat_" + "abcdefghijklmnopqrstuvwxyz" + "_" + "1234567890abcdefghijkl"
        aws_key = "AKIA" + "ABCDEFGHIJKLMNOP"
        slack_token = "xoxb-" + "1234567890-abcdefghijkl"
        text = f"github {github_token} fine {github_pat} aws {aws_key} slack {slack_token}"

        redacted = redact_text(text)

        self.assertNotIn(github_token, redacted)
        self.assertNotIn(github_pat, redacted)
        self.assertNotIn(aws_key, redacted)
        self.assertNotIn(slack_token, redacted)
        self.assertIn("[REDACTED:GITHUB_TOKEN]", redacted)
        self.assertIn("[REDACTED:AWS_ACCESS_KEY]", redacted)
        self.assertIn("[REDACTED:SLACK_TOKEN]", redacted)

    def test_redact_jsonl_redacts_nested_strings_and_preserves_invalid_lines(self):
        raw = '{"user":"bob@example.invalid","nested":{"password":"not-a-real-example-password","private_key":"abc"}}\nnot json\n'  # pragma: allowlist secret

        redacted = redact_jsonl(raw)
        first, second = redacted.splitlines()
        payload = json.loads(first)

        self.assertEqual(payload["user"], "[REDACTED:EMAIL]")
        self.assertEqual(payload["nested"]["password"], "[REDACTED:PASSWORD]")
        self.assertEqual(payload["nested"]["private_key"], "[REDACTED:SECRET]")
        self.assertEqual(second, "not json")

    def test_cli_redacts_stdin_text(self):
        completed = self._run_cli(input_text="call me at admin@example.invalid")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("admin@example.invalid", completed.stdout)

    def test_cli_check_mode_returns_nonzero_without_output_when_redactions_needed(self):
        completed = self._run_cli("--check", input_text="token=not-a-real-example-token")

        self.assertEqual(completed.returncode, 1)
        self.assertEqual("", completed.stdout)
        self.assertIn("redactions needed", completed.stderr)

    def test_cli_check_mode_returns_zero_for_clean_input(self):
        completed = self._run_cli("--check", input_text="ordinary build log")

        self.assertEqual(completed.returncode, 0)
        self.assertEqual("", completed.stdout)

    def test_cli_rejects_oversized_input_with_exit_code_two(self):
        completed = self._run_cli("--check", "--max-bytes", "8", input_text="ordinary log")

        self.assertEqual(completed.returncode, 2)
        self.assertEqual("", completed.stdout)
        self.assertIn("input exceeds maximum size", completed.stderr)

    def test_cli_rejects_invalid_rules_with_exit_code_two(self):
        path = self._write_rules([{"pattern": "["}])

        completed = self._run_cli("--check", "--rules", path, input_text="ordinary log")

        self.assertEqual(completed.returncode, 2)
        self.assertEqual("", completed.stdout)
        self.assertIn("invalid regex or replacement", completed.stderr)

    def test_cli_rejects_oversized_rules_file_with_exit_code_two(self):
        path = self._write_rules(b"[]" + b" " * MAX_RULES_FILE_BYTES, mode="wb")

        completed = self._run_cli("--check", "--rules", path, input_text="ordinary log")

        self.assertEqual(completed.returncode, 2)
        self.assertEqual("", completed.stdout)
        self.assertIn("rules file exceeds maximum size", completed.stderr)

    def test_cli_check_mode_does_not_write_output(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as handle:
            output_path = handle.name
        os.unlink(output_path)
        self.addCleanup(lambda: os.path.exists(output_path) and os.unlink(output_path))

        completed = self._run_cli("--check", "--output", output_path, input_text="token=not-a-real-example-token")

        self.assertEqual(completed.returncode, 1)
        self.assertFalse(os.path.exists(output_path))


if __name__ == "__main__":
    unittest.main()
