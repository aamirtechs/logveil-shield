# logveil-shield
**Live tool:** https://aamirtechs.github.io/logveil-shield/ (runs in your browser, no install)

Scrub secrets and sensitive data from logs and config files before you share them. Zero dependencies, standard library only.

Paste a log into a support ticket, a bug report, or ChatGPT without leaking API keys, tokens, connection strings, emails, or phone numbers.

## Install

```bash
pip install logveil-shield
# or from source
git clone https://github.com/aamirtechs/logveil-shield
cd logveil-shield
pip install .
```

Requires Python 3.9+.

## Quick start

Redact a config file (placeholders like `changeme` and `xxx` are left alone):

```bash
$ logveil-shield fixtures/sample.env --report
# Sample config for logveil-shield fixtures. All values are fake.
OPENAI_API_KEY=[REDACTED:API_SECRET]
AWS_ACCESS_KEY_ID=[REDACTED:AWS_ACCESS_KEY]
AWS_SECRET_ACCESS_KEY=[REDACTED:AWS_SECRET_KEY]
STRIPE_SECRET_KEY=[REDACTED:API_SECRET]
DATABASE_URL=[REDACTED:DB_CONNECTION_STRING]
SLACK_BOT_TOKEN=[REDACTED:API_SECRET]
GITHUB_TOKEN=[REDACTED:API_SECRET]
SUPPORT_EMAIL=[REDACTED:EMAIL]
ADMIN_PHONE=[REDACTED:PHONE]
# These placeholders must NOT be redacted:
API_KEY=changeme
PASSWORD=xxx

TYPE                     COUNT
---------------------- -------
API_SECRET                   4
AWS_ACCESS_KEY               1
AWS_SECRET_KEY               1
DB_CONNECTION_STRING         1
EMAIL                        1
PHONE                        1
---------------------- -------
TOTAL                        9
```

Tokenize a log so redacted values stay correlatable (same value, same token):

```bash
$ logveil-shield --mode tokenize fixtures/sample.log
2026-10-21 09:14:02 INFO  app starting, config loaded from /etc/myapp/prod.env
2026-10-21 09:14:03 DEBUG connecting to [DB_CONNECTION_STRING_1]
2026-10-21 09:14:04 INFO  stripe publishable key in use: [STRIPE_KEY_1]
2026-10-21 09:14:05 ERROR payment failed for card [CREDIT_CARD_1], customer [EMAIL_1]
2026-10-21 09:14:06 WARN  retrying webhook https://hooks:[URL_CREDENTIALS_1]@hooks.internal/v1/events
2026-10-21 09:14:07 INFO  user signed in from [IPV4_1], phone [PHONE_1]
2026-10-21 09:14:08 DEBUG openai client key [OPENAI_API_KEY_1]
2026-10-21 09:14:09 DEBUG aws credentials [AWS_ACCESS_KEY_1] loaded from env
2026-10-21 09:14:10 INFO  slack alert token [SLACK_TOKEN_1]
...
```

Use it as a CI or pre-commit gate:

```bash
$ logveil-shield --check fixtures/sample.env
logveil-shield: sensitive data found in 1 input(s)
$ echo $?
1
$ echo "just a normal log line" | logveil-shield --check
logveil-shield: no sensitive data found
$ echo $?
0
```

Hash mode for stable anonymized identifiers, and custom patterns for your own formats:

```bash
$ echo "contact ops@example.org" | logveil-shield --mode hash
contact [HASH:EMAIL:19ab8d683389]
$ echo "shipped ORD-482910 to ops@example.org" | logveil-shield --pattern "ORDER_ID=ORD-[0-9]{6}"
shipped [REDACTED:ORDER_ID] to [REDACTED:EMAIL]
```

## Modes

| Mode | Flag | Replacement | Best for |
|------|------|-------------|----------|
| redact | (default) | `[REDACTED:EMAIL]` | Sharing publicly, support tickets |
| tokenize | `--mode tokenize` | `[EMAIL_1]`, `[EMAIL_2]` | Debugging, keeps values correlatable |
| hash | `--mode hash` | `[HASH:EMAIL:9f2c...]` | Stable anonymized identifiers |

## Detectors

```text
PEM_PRIVATE_KEY      PEM private key blocks (RSA, EC, DSA, OpenSSH, Ed25519).
DB_CONNECTION_STRING Database connection strings (postgres, mysql, mongodb, redis).
URL_CREDENTIALS      Passwords embedded in URLs (https://user:pass@host).
AWS_ACCESS_KEY       AWS access key IDs (AKIA...).
AWS_SECRET_KEY       AWS secret access keys in assignments.
GITHUB_TOKEN         GitHub personal access and app tokens.
OPENAI_API_KEY       OpenAI API keys (sk-...).
STRIPE_KEY           Stripe secret, publishable, and restricted keys.
SLACK_TOKEN          Slack bot, user, and app tokens.
JWT                  JSON Web Tokens (header.payload.signature).
BEARER_TOKEN         Bearer tokens in Authorization headers.
API_SECRET           Generic api_key / secret / password assignments.
CREDIT_CARD          Credit card numbers (Luhn validated).
EMAIL                Email addresses.
IPV4                 IPv4 addresses (octets validated 0-255).
PHONE                Phone numbers (international and US style).
```

Notes:

- Values that are obviously placeholders (`changeme`, `xxx`, `null`, `...`) are never redacted.
- Credit cards are only redacted when they pass the Luhn checksum, so order numbers and timestamps are left alone.
- IPv4 octets are validated (999.999.999.999 is not an address).
- Overlapping matches resolve by detector priority: a database connection string wins over URL credentials, which wins over email; a credit card wins over a phone number.

## CLI reference

```text
usage: logveil-shield [-h] [--mode {redact,tokenize,hash}] [--report]
                      [--check] [--in-place] [-o FILE] [-r] [-p NAME=PATTERN]
                      [--list-detectors] [--version]
                      [PATH ...]

Scrub secrets and sensitive data from logs and config files before sharing
them. Reads files, directories, or stdin.

positional arguments:
  PATH                  Files to scrub. Directories need --recursive. Reads
                        stdin when omitted.

options:
  -h, --help            show this help message and exit
  --mode {redact,tokenize,hash}
                        redact: [REDACTED:TYPE] (default). tokenize:
                        consistent [TYPE_N] pseudonyms per unique value. hash:
                        [HASH:TYPE:abcdef123456].
  --report              Print a summary table of redactions by type to stderr.
  --check               Exit 1 if any sensitive data is found (for CI or pre-
                        commit hooks). Prints no scrubbed output.
  --in-place            Rewrite each input file with its scrubbed content.
  -o FILE, --output FILE
                        Write scrubbed output to FILE instead of stdout.
  -r, --recursive       Descend into directories given as inputs.
  -p NAME=PATTERN, --pattern NAME=PATTERN
                        Add a custom redaction regex. Repeatable. Example: -p
                        SESSION_ID='sess_[a-z0-9]{16}'.
  --list-detectors      List the built-in detectors and exit.
  --version             show program's version number and exit
```

## Recipes

```bash
# Scrub a whole directory in place before zipping it for support
logveil-shield --recursive --in-place ./logs/

# Pipe a live log through stdin
tail -f /var/log/app.log | logveil-shield --mode tokenize

# Pre-commit hook (.pre-commit-config.yaml)
- repo: local
  hooks:
    - id: logveil-shield
      name: no secrets in staged files
      entry: logveil-shield --check
      language: system
      files: \.(log|env|yaml|json)$
```

## Development

```bash
python -m unittest discover -s tests   # 52 tests, stdlib unittest
```

See [GOOD_FIRST_ISSUES.md](GOOD_FIRST_ISSUES.md) for starter contributions and [CHANGELOG.md](CHANGELOG.md) for release notes.

## License

MIT, Copyright 2026 Amir Hussain. See [LICENSE](LICENSE).
