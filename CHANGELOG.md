# Changelog

## Unreleased

### Added
- `secure_api.yaml`: the sample API with every finding fixed, and tests that it stays clean and covers the same operations.

### Changed
- CI uploads the scan of `secure_api.yaml` to code scanning instead of the intentionally vulnerable sample, which closes the 11 demo alerts. CI still checks that the vulnerable sample produces findings.

## 0.2.0

### Added
- SARIF 2.1.0 output (`--format sarif`) for GitHub code scanning.
- SG006: authentication endpoints (login, token, password reset) that do not document a 429 response.
- SG007: error responses whose schema or example exposes stack traces or internal fields.
- Local `$ref` resolution for parameters, request bodies, schemas and responses. External references are still skipped.
- `pyproject.toml` packaging with a `specguard` console command.
- GitHub Actions workflow: unit tests on Python 3.9, 3.11, 3.12 and 3.13, an install check of the `specguard` command, and a SARIF upload to code scanning.

### Fixed
- `security: [{}]` (optional authentication) is now reported by SG001. It was previously treated as protected.
- SG002 compares the parsed host exactly. `http://localhost.attacker.example` is no longer treated as local.
- SG005 flags `additionalProperties` set to a schema, not only to `true`, and treats an absent keyword as open, per the OpenAPI default.
- Reference cycles and malformed specs (for example `content: 1.5` or `parameters: "x"`) no longer crash the rules. A regression test swaps every node of the sample spec for wrong-typed values.
- Specification files larger than 20 MB are refused before parsing.

## 0.1.0

- Initial release with SG001 to SG005.
