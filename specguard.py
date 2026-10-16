#!/usr/bin/env python3
"""specguard: a security linter for OpenAPI 3.x specifications.

specguard reads an OpenAPI document (YAML or JSON) and reports design-level
security problems that are easy to introduce and easy to miss in review:
operations without authentication, cleartext transport, credentials that end
up in URLs, weak authentication schemes, and request bodies that accept
arbitrary extra fields (mass assignment).

It never sends traffic anywhere. It only reads the specification.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Iterator

import yaml

__version__ = "0.1.0"

HTTP_METHODS = ("get", "put", "post", "delete", "patch", "options", "head", "trace")
WRITE_METHODS = frozenset({"post", "put", "patch", "delete"})
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]", "0.0.0.0")
CREDENTIAL_PARAM = re.compile(
    r"(api[_-]?key|access[_-]?token|token|secret|passw(or)?d|session[_-]?id)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Finding:
    """A single problem found in a specification."""

    rule_id: str
    severity: str
    location: str
    message: str
    remediation: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def load_spec(path: str | Path) -> dict[str, Any]:
    """Parse an OpenAPI document from a YAML or JSON file.

    YAML is a superset of JSON, so one loader handles both. Only the safe
    loader is used, so untrusted documents cannot execute code.
    """
    text = Path(path).read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"could not parse {path}: {exc}") from exc
    if not isinstance(data, dict) or "openapi" not in data:
        raise ValueError(f"{path} does not look like an OpenAPI 3.x document")
    return data


def _operations(spec: dict[str, Any]) -> Iterator[tuple[str, str, dict, dict]]:
    """Yield (path, method, operation, path_item) for every operation."""
    for path, path_item in (spec.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() in HTTP_METHODS and isinstance(operation, dict):
                yield path, method.lower(), operation, path_item


def _label(method: str, path: str) -> str:
    return f"{method.upper()} {path}"


def check_missing_auth(spec: dict[str, Any]) -> list[Finding]:
    """SG001: an operation is reachable without any authentication."""
    findings = []
    global_security = spec.get("security")
    for path, method, operation, _ in _operations(spec):
        # An operation-level `security` key overrides the global one, and an
        # explicit empty list means "no authentication required".
        security = operation.get("security", global_security)
        if not security:
            severity = "high" if method in WRITE_METHODS else "medium"
            findings.append(
                Finding(
                    "SG001",
                    severity,
                    _label(method, path),
                    "Operation does not require authentication.",
                    "Add a security requirement to the operation or to the "
                    "document. If the endpoint is meant to be public, make "
                    "that explicit and keep it read-only.",
                )
            )
    return findings


def check_plain_http(spec: dict[str, Any]) -> list[Finding]:
    """SG002: a server URL uses cleartext HTTP to a non-local host."""
    findings = []
    for index, server in enumerate(spec.get("servers") or []):
        url = str(server.get("url", "")) if isinstance(server, dict) else ""
        if url.startswith("http://") and not any(host in url for host in LOCAL_HOSTS):
            findings.append(
                Finding(
                    "SG002",
                    "high",
                    f"servers[{index}]",
                    f"Server URL uses plain HTTP: {url}",
                    "Serve the API over https:// so tokens and personal data "
                    "are not sent in cleartext.",
                )
            )
    return findings


def check_credentials_in_query(spec: dict[str, Any]) -> list[Finding]:
    """SG003: a credential-like parameter is passed in the query string."""
    findings = []
    for path, method, operation, path_item in _operations(spec):
        parameters = list(path_item.get("parameters") or []) + list(
            operation.get("parameters") or []
        )
        for parameter in parameters:
            if not isinstance(parameter, dict):
                continue
            name = str(parameter.get("name", ""))
            if parameter.get("in") == "query" and CREDENTIAL_PARAM.search(name):
                findings.append(
                    Finding(
                        "SG003",
                        "high",
                        _label(method, path),
                        f"Credential-like query parameter '{name}'. Query "
                        "strings are written to proxy and server logs and to "
                        "browser history.",
                        "Move the credential into the Authorization header, or "
                        "into a request body for non-GET operations.",
                    )
                )
    return findings


def check_insecure_schemes(spec: dict[str, Any]) -> list[Finding]:
    """SG004: a declared security scheme is weak by design."""
    findings = []
    schemes = (spec.get("components") or {}).get("securitySchemes") or {}
    for name, scheme in schemes.items():
        if not isinstance(scheme, dict):
            continue
        if scheme.get("type") == "apiKey" and scheme.get("in") == "query":
            findings.append(
                Finding(
                    "SG004",
                    "medium",
                    f"components.securitySchemes.{name}",
                    "API key is accepted in the query string.",
                    "Accept the key in a header such as X-API-Key or in the "
                    "Authorization header instead.",
                )
            )
        if scheme.get("type") == "http" and str(scheme.get("scheme", "")).lower() == "basic":
            findings.append(
                Finding(
                    "SG004",
                    "medium",
                    f"components.securitySchemes.{name}",
                    "HTTP Basic authentication sends reusable credentials on "
                    "every request.",
                    "Prefer bearer tokens issued by OAuth 2.0 or OpenID Connect "
                    "where you can.",
                )
            )
    return findings


def check_mass_assignment(spec: dict[str, Any]) -> list[Finding]:
    """SG005: a request body object accepts fields it does not declare.

    Clients that can set undeclared fields can often reach server-side
    attributes such as roles, prices or ownership (OWASP API Top 10, API3).
    """
    findings = []
    for path, method, operation, _ in _operations(spec):
        body = operation.get("requestBody")
        if not isinstance(body, dict):
            continue
        for media in (body.get("content") or {}).values():
            schema = media.get("schema") if isinstance(media, dict) else None
            if not isinstance(schema, dict) or "$ref" in schema:
                continue
            is_object = schema.get("type") == "object" or "properties" in schema
            allows_extra = "additionalProperties" not in schema or schema["additionalProperties"] is True
            if is_object and allows_extra:
                findings.append(
                    Finding(
                        "SG005",
                        "medium",
                        _label(method, path),
                        "Request body object accepts undeclared fields.",
                        "Set additionalProperties: false on the request schema "
                        "and list every field the server should accept.",
                    )
                )
    return findings


CHECKS: tuple[Callable[[dict[str, Any]], list[Finding]], ...] = (
    check_missing_auth,
    check_plain_http,
    check_credentials_in_query,
    check_insecure_schemes,
    check_mass_assignment,
)


def audit(spec: dict[str, Any]) -> list[Finding]:
    """Run every rule and return findings, most severe first."""
    findings: list[Finding] = []
    for check in CHECKS:
        findings.extend(check(spec))
    return sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER[f.severity], f.rule_id, f.location),
    )


def format_text(findings: list[Finding]) -> str:
    if not findings:
        return "specguard: no findings."
    blocks = []
    for finding in findings:
        blocks.append(
            f"[{finding.severity.upper():<6}] {finding.rule_id}  {finding.location}\n"
            f"    {finding.message}\n"
            f"    Fix: {finding.remediation}"
        )
    counts = Counter(f.severity for f in findings)
    summary = ", ".join(f"{counts[sev]} {sev}" for sev in ("high", "medium", "low", "info") if counts[sev])
    blocks.append(f"{len(findings)} finding(s): {summary}")
    return "\n\n".join(blocks)


def format_json(findings: list[Finding]) -> str:
    return json.dumps([finding.to_dict() for finding in findings], indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="specguard",
        description="Security linter for OpenAPI 3.x specifications.",
    )
    parser.add_argument("spec", help="path to an OpenAPI document (YAML or JSON)")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument(
        "--fail-on",
        choices=["high", "medium", "low", "never"],
        default="high",
        help="exit with status 1 when a finding reaches this severity (default: high)",
    )
    parser.add_argument("--version", action="version", version=f"specguard {__version__}")
    args = parser.parse_args(argv)

    try:
        spec = load_spec(args.spec)
    except (OSError, ValueError) as exc:
        print(f"specguard: {exc}", file=sys.stderr)
        return 2

    findings = audit(spec)
    print(format_json(findings) if args.format == "json" else format_text(findings))

    if args.fail_on != "never":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
