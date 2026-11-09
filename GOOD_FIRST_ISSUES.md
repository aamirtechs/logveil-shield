# Good First Issues

New to the project? These are small, well-scoped starting points. Each one
can be done in a single pull request. Comment on the issue first if you plan
to work on it.

## 1. Add Azure and Google Cloud key detectors

**Description:** logveil-shield detects AWS, GitHub, OpenAI, Stripe, and Slack
secrets, but has no detectors for Microsoft Azure (`AccountKey=` connection
strings) or Google Cloud service-account JSON (`"private_key": "-----BEGIN
PRIVATE KEY-----"` plus `"client_email"`). Add both to `detectors.py` with the
same priority rules the existing detectors use.

**Acceptance criteria:**
- New `AZURE_STORAGE_KEY` detector matches `AccountKey=<base64>` inside Azure
  storage connection strings.
- New `GCP_SERVICE_ACCOUNT` detector matches service-account JSON blobs.
- Unit tests in `tests/test_detectors.py` cover a positive match, a
  near-miss, and an overlap case against the PEM detector.
- `README.md` detector table and `--list-detectors` output updated.
- All existing tests still pass.

## 2. `--exclude` flag for skipping paths during recursive scans

**Description:** Recursive scans (`--recursive`) currently walk everything,
including `.git`, `node_modules`, and vendored directories. Add an `--exclude`
flag (repeatable, glob patterns) that skips matching paths.

**Acceptance criteria:**
- `--exclude '.git/*' --exclude 'node_modules/*'` skips those directories in
  recursive mode.
- Works with comma-separated single use too: `--exclude '.git/*,node_modules/*'`.
- A test in `tests/test_cli.py` builds a temp tree with an excluded directory
  and asserts its files are not scanned.
- Documented in `README.md` usage section.

## 3. JSON report output (`--report json`)

**Description:** `--report` currently prints a human-readable table. CI
pipelines and dashboards would benefit from a machine-readable variant.
Add `--report json` (keeping the default table) that prints
`{"files_scanned": N, "redactions": {"EMAIL": 2, ...}, "total": T}` to stderr.

**Acceptance criteria:**
- `--report json` emits valid JSON parseable by `json.loads`.
- The default `--report` table output is unchanged.
- Counts include custom `--pattern` detectors under their uppercased names.
- A test asserts the JSON shape for a small known input.

## 4. IPv6 address detector

**Description:** Only IPv4 is redacted today. Real logs contain IPv6
addresses too (e.g. `2001:db8::1`, `fe80::a6db:30ff:fe98:1a2b`). Add an
`IPV6` detector.

**Acceptance criteria:**
- Matches full, compressed (`::`), and mixed IPv6 forms.
- Validates with Python's `ipaddress` module instead of a hand-rolled regex
  where feasible.
- Does not match timestamps like `12:34:56` or MAC addresses.
- Tests for positive matches, compressed forms, and the timestamp/MAC
  negative cases.
- README detector table updated.
