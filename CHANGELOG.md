# Changelog

All notable changes to logveil-shield are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-10-22

Initial release.

### Added
- `logveil-shield` console script (Python 3.9+, standard library only, zero dependencies).
- 16 built-in detectors: PEM private key blocks, database connection strings,
  URL-embedded credentials, AWS access keys, AWS secret access keys, GitHub
  tokens (ghp/gho/ghu/ghs/ghr/github_pat), OpenAI API keys, Stripe keys,
  Slack tokens, JWTs, Bearer tokens, generic api_key/secret/password
  assignments, credit card numbers (Luhn validated), email addresses, IPv4
  addresses (octet validated), phone numbers.
- Three scrub modes: `--redact` ([REDACTED:TYPE]), `--tokenize` (consistent
  [TYPE_N] pseudonyms per unique value), `--hash` ([HASH:TYPE:digest]).
- Input handling: stdin, one or more files, `--recursive` directory walks.
- Output control: stdout (default), `--output FILE`, `--in-place`.
- `--report`: redaction summary table by type, printed to stderr.
- `--check`: exit 1 when sensitive data is found, for CI and pre-commit hooks.
- `--pattern NAME=PATTERN`: repeatable custom regex detectors.
- `--list-detectors`: print the built-in detector list.
- Placeholder-aware: values like `changeme`, `xxx`, or `null` are never redacted.
- Overlap resolution by detector priority (connection string beats URL
  credentials beats email; card beats phone).
