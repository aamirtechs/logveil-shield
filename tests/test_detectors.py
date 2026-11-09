"""Tests for the detector patterns."""

import re
import json
import unittest

from logveil_shield.detectors import DETECTORS, luhn_ok
from logveil_shield.engine import Redactor


def _detector(name):
    for detector in DETECTORS:
        if detector.name == name:
            return detector
    raise AssertionError(f"no detector named {name}")


def _matches(name, text):
    detector = _detector(name)
    return [
        m for m in detector.pattern.finditer(text)
        if detector.validator is None or detector.validator(m)
    ]


class LuhnTest(unittest.TestCase):
    def test_valid_cards(self):
        self.assertTrue(luhn_ok("4111111111111111"))
        self.assertTrue(luhn_ok("5500005555555559"))
        self.assertTrue(luhn_ok("378282246310005"))

    def test_invalid_cards(self):
        self.assertFalse(luhn_ok("4111111111111112"))
        self.assertFalse(luhn_ok("1234567890123456"))


class DetectorTest(unittest.TestCase):
    def test_azure_storage_account_key(self):
        fake_key = "A" * 84 + "=="  # Synthetic, never a real credential.
        source = f"DefaultEndpointsProtocol=https;AccountKey={fake_key};EndpointSuffix=core.windows.net"
        matches = _matches("AZURE_STORAGE_KEY", source)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].group("value"), fake_key)
        self.assertEqual(_matches("AZURE_STORAGE_KEY", "AccountKey=not-base64"), [])
        self.assertEqual(_matches("AZURE_STORAGE_KEY", "AccountKey=" + "A" * 16), [])
        self.assertIn("AccountKey=[REDACTED:AZURE_STORAGE_KEY]", Redactor().scrub(source))

    def test_gcp_service_account_precedes_pem_detector(self):
        fake_pem = ("-----BEGIN PRIVATE KEY-----\n" + "A" * 48
                    + "\n-----END PRIVATE KEY-----\n")
        source = json.dumps({"type": "service_account", "project_id": "test-project",
                             "private_key": fake_pem,
                             "client_email": "fake@sample-project.iam.gserviceaccount.com"})
        self.assertEqual(len(_matches("GCP_SERVICE_ACCOUNT", source)), 1)
        self.assertEqual(_matches("GCP_SERVICE_ACCOUNT", source.replace("service_account", "user")), [])
        self.assertEqual(_matches("GCP_SERVICE_ACCOUNT", source.replace("client_email", "email")), [])
        self.assertEqual(Redactor().scrub(source), "[REDACTED:GCP_SERVICE_ACCOUNT]")

    def test_aws_access_key(self):
        self.assertEqual(len(_matches("AWS_ACCESS_KEY", "key AKIAIOSFODNN7EXAMPLE here")), 1)
        self.assertEqual(len(_matches("AWS_ACCESS_KEY", "key AKIA too short")), 0)

    def test_github_token(self):
        self.assertEqual(len(_matches("GITHUB_TOKEN", "token ghp_abcdefghij0123456789abcdefghij012345 x")), 1)
        self.assertEqual(len(_matches("GITHUB_TOKEN", "token ghp_short x")), 0)

    def test_openai_key(self):
        self.assertEqual(len(_matches("OPENAI_API_KEY", "sk-9f8e7d6c5b4a394827161514131210")), 1)
        self.assertEqual(len(_matches("OPENAI_API_KEY", "sk-short")), 0)

    def test_stripe_key(self):
        self.assertEqual(len(_matches("STRIPE_KEY", "sk_live_" + "4eC39HqL" + "yjWDarjtT1zdp7dc")), 1)
        self.assertEqual(len(_matches("STRIPE_KEY", "pk_test_4eC39HqLyjWDarjtT1zdp7dc")), 1)
        self.assertEqual(len(_matches("STRIPE_KEY", "sk_9f8e7d6c5b4a394827161514131210")), 0)

    def test_slack_token(self):
        self.assertEqual(len(_matches("SLACK_TOKEN", "xoxb-" + "123456789012" + "-" + "FAKEEXAMPLETOKEN1")), 1)

    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        self.assertEqual(len(_matches("JWT", f"token {jwt} end")), 1)
        self.assertEqual(len(_matches("JWT", "eyJhbGciOiJIUzI1NiJ9.onlytwo")), 0)

    def test_bearer_token(self):
        matches = _matches("BEARER_TOKEN", "Authorization: Bearer abcdef1234567890")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].group("value"), "abcdef1234567890")

    def test_generic_assignment(self):
        matches = _matches("API_SECRET", "api_key = hunter2secret")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].group("key"), "api_key")
        self.assertEqual(matches[0].group("value"), "hunter2secret")

    def test_generic_assignment_ignores_placeholders(self):
        self.assertEqual(len(_matches("API_SECRET", "api_key=changeme")), 0)
        self.assertEqual(len(_matches("API_SECRET", 'password="xxx"')), 0)

    def test_pem_block(self):
        block = ("-----BEGIN RSA PRIVATE KEY-----\n"
                 "MIIEpAIBAAKCAQEA7bqsmk6f8qWmXh5JvE9J2vYd0\n"
                 "-----END RSA PRIVATE KEY-----")
        matches = _matches("PEM_PRIVATE_KEY", "before\n" + block + "\nafter")
        self.assertEqual(len(matches), 1)
        self.assertIn("BEGIN RSA PRIVATE KEY", matches[0].group(0))

    def test_url_credentials(self):
        matches = _matches("URL_CREDENTIALS", "see https://user:s3cret@host.example/x")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].group("value"), "s3cret")

    def test_db_connection_string(self):
        text = "db postgres://deploy:s3cret!dbpass@db.internal:5432/myapp ok"
        matches = _matches("DB_CONNECTION_STRING", text)
        self.assertEqual(len(matches), 1)
        self.assertIn("postgres://deploy", matches[0].group(0))

    def test_email(self):
        self.assertEqual(len(_matches("EMAIL", "write to jane.doe@example.com please")), 1)
        self.assertEqual(len(_matches("EMAIL", "no email here")), 0)

    def test_ipv4(self):
        self.assertEqual(len(_matches("IPV4", "from 203.0.113.45 accepted")), 1)
        self.assertEqual(len(_matches("IPV4", "from 999.999.999.999 rejected")), 0)

    def test_credit_card_luhn(self):
        self.assertEqual(len(_matches("CREDIT_CARD", "card 4111 1111 1111 1111 charged")), 1)
        self.assertEqual(len(_matches("CREDIT_CARD", "card 4111 1111 1111 1112 charged")), 0)

    def test_phone(self):
        self.assertEqual(len(_matches("PHONE", "call +1-555-014-8890 now")), 1)

    def test_phone_uk_style(self):
        self.assertEqual(len(_matches("PHONE", "call +44 20 7946 0018 now")), 1)


if __name__ == "__main__":
    unittest.main()
