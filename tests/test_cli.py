"""End-to-end tests for the logveil-shield CLI."""

import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
FIXTURES = os.path.join(ROOT, "fixtures")

ENV = dict(os.environ, PYTHONPATH=SRC + os.pathsep + os.environ.get("PYTHONPATH", ""))


def run_cli(args, input_text=None):
    return subprocess.run(
        [sys.executable, "-m", "logveil_shield.cli"] + args,
        input=input_text,
        capture_output=True,
        text=True,
        env=ENV,
    )


class CliTest(unittest.TestCase):
    def test_version(self):
        proc = run_cli(["--version"])
        self.assertEqual(proc.returncode, 0)
        self.assertIn("1.0.0", proc.stdout)

    def test_stdin_redact(self):
        proc = run_cli([], input_text="key AKIAIOSFODNN7EXAMPLE ok\n")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "key [REDACTED:AWS_ACCESS_KEY] ok\n")

    def test_list_detectors(self):
        proc = run_cli(["--list-detectors"])
        self.assertEqual(proc.returncode, 0)
        self.assertIn("AWS_ACCESS_KEY", proc.stdout)
        self.assertIn("CREDIT_CARD", proc.stdout)

    def test_tokenize_mode_stdin(self):
        proc = run_cli(["--mode", "tokenize"], input_text="a@x.com and a@x.com\n")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "[EMAIL_1] and [EMAIL_1]\n")

    def test_check_found(self):
        proc = run_cli(["--check"], input_text="sk-9f8e7d6c5b4a394827161514131210\n")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("sensitive data found", proc.stderr)

    def test_check_clean(self):
        proc = run_cli(["--check"], input_text="nothing secret here\n")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("no sensitive data found", proc.stderr)

    def test_check_no_output_on_stdout(self):
        proc = run_cli(["--check"], input_text="sk-9f8e7d6c5b4a394827161514131210\n")
        self.assertEqual(proc.stdout, "")

    def test_report(self):
        proc = run_cli(
            ["--report"],
            input_text="a@x.com\nb@y.org\nfrom 10.0.0.1\n",
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("EMAIL", proc.stderr)
        self.assertIn("IPV4", proc.stderr)
        self.assertIn("TOTAL", proc.stderr)

    def test_custom_pattern(self):
        proc = run_cli(
            ["--pattern", "SESSION_ID=sess_[a-z0-9]{16}"],
            input_text="sess_abcdef1234567890\n",
        )
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "[REDACTED:SESSION_ID]\n")

    def test_bad_pattern_errors(self):
        proc = run_cli(["--pattern", "NOEQUALS"], input_text="x\n")
        self.assertEqual(proc.returncode, 2)

    def test_missing_file_errors(self):
        proc = run_cli(["/does/not/exist.log"])
        self.assertEqual(proc.returncode, 2)

    def test_dir_without_recursive_errors(self):
        proc = run_cli([FIXTURES])
        self.assertEqual(proc.returncode, 2)

    def test_in_place(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "app.log")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("contact jane@example.com\n")
            proc = run_cli(["--in-place", path])
            self.assertEqual(proc.returncode, 0)
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "contact [REDACTED:EMAIL]\n")

    def test_recursive_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            sub = os.path.join(tmp, "sub")
            os.mkdir(sub)
            path = os.path.join(sub, "a.log")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("from 10.0.0.1\n")
            proc = run_cli(["--recursive", tmp])
            self.assertEqual(proc.returncode, 0)
            self.assertIn("[REDACTED:IPV4]", proc.stdout)

    def test_output_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "out.log")
            proc = run_cli(
                ["--output", dest],
                input_text="card 4111 1111 1111 1111\n",
            )
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(proc.stdout, "")
            with open(dest, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "card [REDACTED:CREDIT_CARD]\n")

    def test_fixture_sample_log(self):
        sample = os.path.join(FIXTURES, "sample.log")
        proc = run_cli([sample])
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn("4111 1111 1111 1111", proc.stdout)
        self.assertNotIn("jane.doe@example.com", proc.stdout)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", proc.stdout)
        self.assertNotIn("BEGIN RSA PRIVATE KEY", proc.stdout)
        self.assertNotIn("s3cret!dbpass", proc.stdout)
        self.assertIn("[REDACTED:CREDIT_CARD]", proc.stdout)
        self.assertIn("[REDACTED:EMAIL]", proc.stdout)

    def test_fixture_sample_env(self):
        sample = os.path.join(FIXTURES, "sample.env")
        proc = run_cli([sample])
        self.assertEqual(proc.returncode, 0)
        self.assertIn("OPENAI_API_KEY=[REDACTED:API_SECRET]", proc.stdout)
        self.assertIn("API_KEY=changeme", proc.stdout)
        self.assertIn("PASSWORD=xxx", proc.stdout)


if __name__ == "__main__":
    unittest.main()
