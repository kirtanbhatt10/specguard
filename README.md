# specguard

**A security linter for OpenAPI specifications.** specguard reads an API
description (OpenAPI 3.x, YAML or JSON) and points out design flaws before
any code ships: endpoints with no authentication, cleartext HTTP, API keys
that travel in URLs, weak auth schemes, request bodies that quietly accept
fields nobody meant to expose, login endpoints with no rate limiting, and
error responses that leak stack traces.

Most API security problems are decided on paper, long before a line of
server code is written. A missing `security` block or a `token` query
parameter looks harmless in a design doc, and it is exactly what attackers
and log scrapers look for. specguard checks the contract itself, so the
problem is caught during review and in CI, not after an incident.

It is a single Python file with one dependency (PyYAML). It never sends
network traffic. It only reads the file you give it.

## What it checks

| Rule | Severity | What it catches |
|------|----------|-----------------|
| SG001 | high / medium | An operation can be called without authentication, including `security: [{}]` (optional auth). Write methods are high, read methods are medium. |
| SG002 | high | A server URL uses `http://` for a non-local host. |
| SG003 | high | A credential-like parameter (`api_key`, `token`, `secret`, `password`, `session_id`) is passed in the query string. |
| SG004 | medium | A security scheme is weak by design: an API key sent in the query string, or HTTP Basic authentication. |
| SG005 | medium | A request body object does not close its fields with `additionalProperties: false`, which enables mass assignment (OWASP API Top 10, API3). |
| SG006 | medium | A login, token, or password-reset endpoint does not document a `429` response, so brute-force protection is not described. |
| SG007 | medium | An error response (4xx, 5xx, or `default`) has a schema field such as `stack` or `sql`, or an example containing a stack trace. |

Each finding includes the operation or location, the reason, and a concrete
fix.

## Example

Running specguard against the intentionally flawed sample in this repository
(`vulnerable_api.yaml`):

```text
$ python3 specguard.py vulnerable_api.yaml
[HIGH  ] SG001  DELETE /orders/{id}
    Operation does not require authentication.
    Fix: Add a security requirement to the operation or to the document. If the endpoint is meant to be public, make that explicit and keep it read-only.

[HIGH  ] SG002  servers[0]
    Server URL uses plain HTTP: http://api.example.com/v1
    Fix: Serve the API over https:// so tokens and personal data are not sent in cleartext.

[HIGH  ] SG003  GET /orders
    Credential-like query parameter 'api_key'. Query strings are written to proxy and server logs and to browser history.
    Fix: Move the credential into the Authorization header, or into a request body for non-GET operations.

...

[MEDIUM] SG006  POST /auth/login
    Authentication endpoint does not document rate limiting (no 429 response).
    Fix: Enforce per-client rate limits on this endpoint and document a 429 response with a Retry-After header.

[MEDIUM] SG007  GET /orders responses.500
    Error response exposes internal details: stack.
    Fix: Return a generic error body with a correlation ID. Log stack traces and SQL text on the server only.

11 finding(s): 4 high, 7 medium
$ echo $?
1
```

Findings are sorted by severity, so the most urgent problems come first.

`secure_api.yaml` is the same API with every finding fixed, with a comment
next to each fix naming the rule it resolves. specguard reports no findings
for it:

```text
$ python3 specguard.py secure_api.yaml
specguard: no findings.
```

CI uploads the scan of `secure_api.yaml`, not the vulnerable sample, to
GitHub code scanning, so the Security tab stays clean.

## Installation

Python 3.9 or newer is required.

```bash
git clone https://github.com/kirtanbhatt10/specguard.git
cd specguard
pip install .          # installs the `specguard` command
# or, without installing:
pip install -r requirements.txt
python3 specguard.py openapi.yaml
```

## Usage

```bash
# Human-readable report; exits 1 if anything is high severity (the default).
specguard openapi.yaml

# Machine-readable output for scripts and dashboards.
specguard openapi.json --format json

# SARIF 2.1.0 for GitHub code scanning.
specguard openapi.yaml --format sarif > specguard.sarif

# Fail the build on medium or worse.
specguard openapi.yaml --fail-on medium

# Report only, never fail.
specguard openapi.yaml --fail-on never
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No finding reached the `--fail-on` threshold. |
| 1 | At least one finding reached the threshold. |
| 2 | The file could not be read, is larger than 20 MB, or is not an OpenAPI document. |

### Use it in CI

This is the workflow the repository runs on itself. Copy it into your own
repository to lint your API contract and show results in the Security tab:

```yaml
name: API security lint

on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  specguard:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"
      - run: pip install git+https://github.com/kirtanbhatt10/specguard.git
      - name: Lint the API contract
        run: specguard api/openapi.yaml --format sarif --fail-on never > specguard.sarif
      - name: Upload SARIF
        if: github.event_name == 'push'
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: specguard.sarif
      - name: Fail the build on high severity findings
        run: specguard api/openapi.yaml --fail-on high
```

## How it works

specguard loads the document with PyYAML's safe loader, so a hostile
specification cannot run code on the machine that lints it. Documents larger
than 20 MB are refused before parsing. It then walks every operation under
`paths`, resolving the effective security requirement the way OpenAPI
defines it: an operation-level `security` overrides the document-level one,
and an explicit empty list, or one containing an empty requirement object,
means "no authentication".

Local `$ref` pointers (`#/components/...`) are followed for parameters,
request bodies, schemas, and responses. Each rule is a plain function that
takes the parsed document and returns findings, so new rules are short to
write and easy to test. Rules are listed in the `CHECKS` tuple in
`specguard.py`.

When a reference cannot be resolved, for example because it points to an
external file or a missing target, the rule skips that node rather than
guessing. That keeps false positives low.

## Development

The test suite uses only the standard library, so there is nothing extra to
install.

```bash
python3 -m unittest -v
```

The suite covers each rule with positive and negative cases, reference
resolution and cycles, the loader's error handling, the CLI exit codes, and
the JSON and SARIF output formats. The sample specification is also checked
to make sure it still triggers every rule.

## Limitations

- specguard checks the specification, not the running service. A correct
  spec does not prove the server enforces it.
- `$ref` targets in other files are not loaded. Only references that start
  with `#/` are followed.
- Authorization logic (for example, whether user A can read user B's order)
  cannot be determined from a spec alone. That needs testing against the
  live API.
- SG006 and SG007 are heuristics over the contract. SG006 matches on path
  words such as `login` or `token`, and SG007 matches on common field names.
  Both can miss a leak or flag a harmless endpoint, so review their findings.

## Roadmap

- Load `$ref` targets from external files, inside the project directory only.
- Configurable rule suppression with a reason, for accepted risks.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE).
