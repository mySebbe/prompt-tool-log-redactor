import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from prompt_tool_log_redactor.redactor import load_rules, redact_jsonl, redact_text


class RedactorTests(unittest.TestCase):
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
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump([{"name": "tenant", "pattern": "TENANT-[0-9]+", "replacement": "[TENANT]"}], handle)
            path = handle.name
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))

        rules = load_rules(path)

        self.assertEqual(redact_text("id TENANT-1234", rules), "id [TENANT]")

    def test_redact_text_masks_common_platform_tokens(self):
        text = (
            "github ghp_abcdefghijklmnopqrstuvwxyz1234567890 "
            "fine github_pat_abcdefghijklmnopqrstuvwxyz_1234567890abcdefghijkl "
            "aws AKIAABCDEFGHIJKLMNOP "
            "slack xoxb-1234567890-abcdefghijkl"
        )

        redacted = redact_text(text)

        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz1234567890", redacted)
        self.assertNotIn("github_pat_abcdefghijklmnopqrstuvwxyz_1234567890abcdefghijkl", redacted)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", redacted)
        self.assertNotIn("xoxb-1234567890-abcdefghijkl", redacted)
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
        env = os.environ.copy()
        env["PYTHONPATH"] = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))

        completed = subprocess.run(
            [sys.executable, "-m", "prompt_tool_log_redactor"],
            input="call me at admin@example.invalid",
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("admin@example.invalid", completed.stdout)


if __name__ == "__main__":
    unittest.main()
