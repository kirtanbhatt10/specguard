# specguard

**A security linter for OpenAPI specifications.** specguard reads an API
description (OpenAPI 3.x, YAML or JSON) and points out design flaws before
any code ships: endpoints with no authentication, cleartext HTTP, API keys
that travel in URLs, weak auth schemes, and request bodies that quietly
accept fields nobody meant to expose.

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
| SG001 | high / medium | An operation can be called without authentication. Write methods are high, read methods are medium. |
| SG002 | high | A server URL uses `http://` for a non-local host. |
| SG003 | high | A credential-like parameter (`api_key`, `token`, `secret`, `password`, `session_id`) is passed in the query string. |
| SG004 | medium | A security scheme is weak by design: an API key sent in the query string, or HTTP Basic authentication. |
| SG005 | medium | A request body object does not set `additionalProperties: false`, which enables mass assignment (OWASP API Top 10, API3). |

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

[MEDIUM] SG001  GET /health
    Operation does not require authentication.
    Fix: Add a security requirement to the operation or to the document. If the endpoint is meant to be public, make that explicit and keep it read-only.

[MEDIUM] SG004  components.securitySchemes.basicAuth
    HTTP Basic authentication sends reusable credentials on every request.
    Fix: Prefer bearer tokens issued by OAuth 2.0 or OpenID Connect where you can.

[MEDIUM] SG004  components.securitySchemes.legacyKey
    API key is accepted in the query string.
    Fix: Accept the key in a header such as X-API-Key or in the Authorization header instead.

[MEDIUM] SG005  POST /orders
    Request body object accepts undeclared fields.
    Fix: Set additionalProperties: false on the request schema and list every field the server should accept.

7 finding(s): 3 high, 4 medium
$ echo $?
1
```

Findings are sorted by severity, so the most urgent problems come first.

## Installation

Python 3.9 or newer is required.

```bash
git clone https://github.com/kirtanbhatt10/specguard.git
cd specguard
pip install -r requirements.txt
```

## Usage

```bash
# Human-readable report; exits 1 if anything is high severity (the default).
python3 specguard.py openapi.yaml

# Machine-readable output for scripts and dashboards.
python3 specguard.py openapi.json --format json

# Fail the build on medium or worse.
python3 specguard.py openapi.yaml --fail-on medium

# Report only, never fail.
python3 specguard.py openapi.yaml --fail-on never
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No finding reached the `--fail-on` threshold. |
| 1 | At least one finding reached the threshold. |
| 2 | The file could not be read or is not an OpenAPI document. |

### Use it in CI

```yaml
- name: Lint API contract
  run: python3 specguard.py api/openapi.yaml --fail-on high
```

## How it works

specguard loads the document with PyYAML's safe loader, so a hostile
specification cannot run code on the machine that lints it. It then walks
every operation under `paths`, resolving the effective security requirement
the way OpenAPI defines it: an operation-level `security` overrides the
document-level one, and an explicit empty list means "no authentication".
Each rule is a plain function that takes the parsed document and returns
findings, so new rules are short to write and easy to test. Rules are listed
in the `CHECKS` tuple in `specguard.py`.

Rules skip `$ref` schemas that they cannot resolve, rather than guessing. That
keeps false positives low, and the README and tests document the limit.

## Development

The test suite uses only the standard library, so there is nothing extra to
install.

```bash
python3 -m unittest -v
```

The suite covers each rule with both a positive and a negative case, the
loader's error handling, the CLI exit codes, and JSON output. The sample
specification is also checked to make sure it still triggers every rule.

## Limitations

- specguard checks the specification, not the running service. A correct
  spec does not prove the server enforces it.
- `$ref` schemas are not followed, so mass-assignment checks skip referenced
  request bodies.
- Authorization logic (for example, whether user A can read user B's order)
  cannot be determined from a spec alone. That needs testing against the
  live API.

## Roadmap

- Resolve local `$ref` schemas for SG005.
- SARIF output so findings show up in GitHub code scanning.
- Rules for rate limiting and for verbose error responses that leak stack
  traces.

## License

MIT. See [LICENSE](LICENSE).
