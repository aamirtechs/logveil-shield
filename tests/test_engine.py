"""Tests for the redaction engine."""

import unittest

from logveil_shield.engine import Redactor


class RedactModeTest(unittest.TestCase):
    def test_basic_redact(self):
        r = Redactor(mode="redact")
        out = r.scrub("email jane@example.com from 10.0.0.1")
        self.assertEqual(out, "email [REDACTED:EMAIL] from [REDACTED:IPV4]")
        self.assertEqual(r.counts, {"EMAIL": 1, "IPV4": 1})

    def test_key_value_keeps_key(self):
        r = Redactor(mode="redact")
        out = r.scrub("OPENAI_API_KEY=sk-9f8e7d6c5b4a394827161514131210")
        self.assertEqual(out, "OPENAI_API_KEY=[REDACTED:API_SECRET]")
        self.assertEqual(r.counts, {"API_SECRET": 1})

    def test_bearer_keeps_scheme(self):
        r = Redactor(mode="redact")
        out = r.scrub("Authorization: Bearer abcdef1234567890")
        self.assertEqual(out, "Authorization: Bearer [REDACTED:BEARER_TOKEN]")

    def test_db_string_beats_url_credentials(self):
        r = Redactor(mode="redact")
        text = "postgres://deploy:s3cret@db.internal:5432/myapp"
        out = r.scrub(text)
        self.assertEqual(out, "[REDACTED:DB_CONNECTION_STRING]")
        self.assertEqual(r.counts, {"DB_CONNECTION_STRING": 1})

    def test_url_credentials_beats_email(self):
        r = Redactor(mode="redact")
        out = r.scrub("see https://user:s3cret@host.example/x")
        self.assertEqual(out, "see https://user:[REDACTED:URL_CREDENTIALS]@host.example/x")

    def test_card_beats_phone(self):
        r = Redactor(mode="redact")
        out = r.scrub("card 4111 1111 1111 1111")
        self.assertEqual(out, "card [REDACTED:CREDIT_CARD]")

    def test_placeholders_survive(self):
        r = Redactor(mode="redact")
        text = "API_KEY=changeme\nPASSWORD=xxx\n"
        self.assertEqual(r.scrub(text), text)
        self.assertEqual(r.total, 0)

    def test_clean_text_untouched(self):
        r = Redactor(mode="redact")
        text = "2026-10-21 INFO request served in 42ms, version 1.2.3\n"
        self.assertEqual(r.scrub(text), text)
        self.assertEqual(r.total, 0)


class TokenizeModeTest(unittest.TestCase):
    def test_consistent_tokens(self):
        r = Redactor(mode="tokenize")
        text = "a@example.com wrote to a@example.com and b@example.com"
        out = r.scrub(text)
        self.assertEqual(out, "[EMAIL_1] wrote to [EMAIL_1] and [EMAIL_2]")

    def test_tokens_stable_across_calls(self):
        r = Redactor(mode="tokenize")
        first = r.scrub("from 10.0.0.1")
        second = r.scrub("from 10.0.0.1 again")
        self.assertIn("[IPV4_1]", first)
        self.assertIn("[IPV4_1]", second)

    def test_key_value_tokenize(self):
        r = Redactor(mode="tokenize")
        out = r.scrub("api_key=hunter2secret")
        self.assertEqual(out, "api_key=[API_SECRET_1]")


class HashModeTest(unittest.TestCase):
    def test_deterministic(self):
        r1 = Redactor(mode="hash")
        r2 = Redactor(mode="hash")
        text = "token ghp_abcdefghijklmnopqrstuvwxyZ01234567"
        self.assertEqual(r1.scrub(text), r2.scrub(text))

    def test_hash_format(self):
        r = Redactor(mode="hash")
        out = r.scrub("from 10.0.0.1")
        self.assertRegex(out, r"from \[HASH:IPV4:[0-9a-f]{12}\]")

    def test_same_value_same_hash(self):
        r = Redactor(mode="hash")
        out = r.scrub("10.0.0.1 and 10.0.0.1")
        first, second = out.split(" and ")
        self.assertEqual(first, second)


class CustomPatternTest(unittest.TestCase):
    def test_custom_pattern(self):
        from logveil_shield.detectors import build_custom_detector
        custom = build_custom_detector("SESSION_ID", r"sess_[a-z0-9]{16}")
        r = Redactor(mode="redact", extra_detectors=[custom])
        out = r.scrub("session sess_abcdef1234567890 ended")
        self.assertEqual(out, "session [REDACTED:SESSION_ID] ended")

    def test_bad_regex_rejected(self):
        from logveil_shield.detectors import build_custom_detector
        with self.assertRaises(ValueError):
            build_custom_detector("BROKEN", r"(unclosed")


if __name__ == "__main__":
    unittest.main()
