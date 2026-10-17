#!/usr/bin/env python3
"""specguard: a security linter for OpenAPI 3.x specifications.

specguard reads an OpenAPI document (YAML or JSON) and reports design-level
security problems that are easy to introduce and easy to miss in review:
operations without authentication, cleartext transport, credentials that end
up in URLs, weak authentication schemes, request bodies that accept arbitrary
extra fields (mass assignment), authentication endpoints without rate limits,
and error responses that expose internal details.

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
from urllib.parse import urlparse

import yaml

__version__ = "0.2.0"

HTTP_METHODS = ("get", "put", "post", "delete", "patch", "options", "head", "trace")
WRITE_METHODS = frozenset({"post", "put", "patch", "delete"})
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
SARIF_SECURITY_SEVERITY = {"high": "8.0", "medium": "5.0", "low": "2.0", "info": "0.0"}
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})
MAX_SPEC_BYTES = 20 * 1024 * 1024
MAX_DEPTH = 12
CREDENTIAL_PARAM = re.compile(
    r"(api[_-]?key|access[_-]?token|token|secret|passw(or)?d|session[_-]?id)",
    re.IGNORECASE,
)
# Path segments that name an authentication endpoint. Matching is on whole
# segment words, so "/authors" and "/tokens" are not treated as auth endpoints.
AUTH_PATH = re.compile(
    r"(?<![a-z])(login|log-in|signin|sign-in|oauth|auth|token|password|passwd|otp|mfa|2fa|reset)(?![a-z])",
    re.IGNORECASE,
)
LEAK_FIELDS = frozenset(
    {
        "stack",
        "stacktrace",
        "stack_trace",
        "traceback",
        "exception",
        "exception_type",
        "sql",
        "sql_query",
        "debug_info",
    }
)
TRACE_MARKER = re.compile(
    r"Traceback \(most recent call last\)|\bat [\w$.<>]+\([^)]*\.(java|js|ts|py|kt|cs):\d+",
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


RULES: dict[str, str] = {
    "SG001": "Operation does not require authentication",
    "SG002": "Server URL uses cleartext HTTP to a non-local host",
    "SG003": "Credential-like parameter is passed in the query string",
    "SG004": "Security scheme is weak by design",
    "SG005": "Request body accepts undeclared fields (mass assignment)",
    "SG006": "Authentication endpoint does not document rate limiting",
    "SG007": "Error response exposes internal details",
}


def load_spec(path: str | Path) -> dict[str, Any]:
    """Parse an OpenAPI document from a YAML or JSON file.

    YAML is a superset of JSON, so one loader handles both. Only the safe
    loader is used, so untrusted documents cannot execute code. Files above
    MAX_SPEC_BYTES are refused to bound parser memory on hostile input.
    """
    path = Path(path)
    if path.stat().st_size > MAX_SPEC_BYTES:
        raise ValueError(f"{path} is larger than {MAX_SPEC_BYTES // (1024 * 1024)} MB")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"could not parse {path}: {exc}") from exc
    if not isinstance(data, dict) or "openapi" not in data:
        raise ValueError(f"{path} does not look like an OpenAPI 3.x document")
    return data


def _resolve(spec: dict[str, Any], node: Any) -> dict[str, Any] | None:
    """Follow local `#/...` $ref pointers and return the target object.

    Returns None when the node is not an object or the reference cannot be
    resolved (external files, missing targets, or reference cycles). Rules
    treat None as "unknown" and skip the node rather than guessing.
    """
    for _ in range(20):
        if not isinstance(node, dict):
            return None
        if "$ref" not in node:
            return node
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return None
        target: Any = spec
        for part in ref[2:].split("/"):
            key = part.replace("~1", "/").replace("~0", "~")
            if isinstance(target, dict) and key in target:
                target = target[key]
            else:
                return None
        node = target
    return None


def _as_dict(value: Any) -> dict:
    """Return value if it is a mapping, else an empty dict (malformed input)."""
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list:
    """Return value if it is a list, else an empty list (malformed input)."""
    return value if isinstance(value, list) else []


def _operations(spec: dict[str, Any]) -> Iterator[tuple[str, str, dict, dict]]:
    """Yield (path, method, operation, path_item) for every operation."""
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if str(method).lower() in HTTP_METHODS and isinstance(operation, dict):
                yield str(path), str(method).lower(), operation, path_item


def _label(method: str, path: str) -> str:
    return f"{method.upper()} {path}"


def _allows_anonymous(security: Any) -> bool:
    """True when the effective security requirement permits no credentials.

    An absent or empty list means no authentication. A list that contains an
    empty requirement object, such as `[{}]` or `[{}, {"bearerAuth": []}]`,
    means authentication is optional, so anonymous calls are allowed.
    """
    if not security:
        return True
    if not isinstance(security, list):
        return False
    return any(isinstance(item, dict) and not item for item in security)


def check_missing_auth(spec: dict[str, Any]) -> list[Finding]:
    """SG001: an operation is reachable without any authentication."""
    findings = []
    global_security = spec.get("security")
    for path, method, operation, _ in _operations(spec):
        # An operation-level `security` key overrides the global one.
        security = operation["security"] if "security" in operation else global_security
        if _allows_anonymous(security):
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
    servers = spec.get("servers")
    for index, server in enumerate(servers if isinstance(servers, list) else []):
        url = str(server.get("url", "")) if isinstance(server, dict) else ""
        if not url.lower().startswith("http://"):
            continue
        # Compare the parsed host exactly. A substring test would treat
        # "http://localhost.attacker.example" as local.
        host = (urlparse(url).hostname or "").lower()
        if host not in LOCAL_HOSTS:
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
        raw = _as_list(path_item.get("parameters")) + _as_list(operation.get("parameters"))
        for raw_parameter in raw:
            parameter = _resolve(spec, raw_parameter)
            if parameter is None:
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
    components = spec.get("components")
    schemes = components.get("securitySchemes") if isinstance(components, dict) else None
    for name, scheme in _as_dict(schemes).items():
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
    Local $ref request bodies and schemas are resolved; external references
    are skipped.
    """
    findings = []
    for path, method, operation, _ in _operations(spec):
        body = _resolve(spec, operation.get("requestBody"))
        if body is None:
            continue
        for media in _as_dict(body.get("content")).values():
            schema = _resolve(spec, media.get("schema")) if isinstance(media, dict) else None
            if schema is None:
                continue
            is_object = schema.get("type") == "object" or "properties" in schema
            # Absent additionalProperties defaults to true in OpenAPI, and a
            # schema value means undeclared fields are accepted with a type.
            if "additionalProperties" in schema:
                extra = schema["additionalProperties"]
                allows_extra = extra is True or isinstance(extra, dict)
            else:
                allows_extra = True
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


def check_rate_limiting(spec: dict[str, Any]) -> list[Finding]:
    """SG006: an authentication endpoint does not document a 429 response.

    Login, token, and password-reset endpoints are brute-force targets. A
    spec that does not describe a 429 (Too Many Requests) response usually
    means the throttling was never designed.
    """
    findings = []
    for path, method, operation, _ in _operations(spec):
        if not AUTH_PATH.search(path):
            continue
        responses = _as_dict(operation.get("responses"))
        if "429" in {str(code) for code in responses}:
            continue
        findings.append(
            Finding(
                "SG006",
                "medium",
                _label(method, path),
                "Authentication endpoint does not document rate limiting "
                "(no 429 response).",
                "Enforce per-client rate limits on this endpoint and document "
                "a 429 response with a Retry-After header.",
            )
        )
    return findings


def _scan_leaks(spec: dict[str, Any], node: Any, depth: int = 0) -> set[str]:
    """Collect field names and trace markers that reveal internals in a schema."""
    if depth > MAX_DEPTH:
        return set()
    if isinstance(node, list):
        hits: set[str] = set()
        for item in node:
            hits |= _scan_leaks(spec, item, depth + 1)
        return hits
    node = _resolve(spec, node)
    if node is None:
        return set()

    hits = set()
    for key, value in node.items():
        if key == "properties" and isinstance(value, dict):
            for name, sub_schema in value.items():
                if str(name).lower() in LEAK_FIELDS:
                    hits.add(str(name))
                hits |= _scan_leaks(spec, sub_schema, depth + 1)
        elif key in ("example", "examples", "default"):
            if TRACE_MARKER.search(json.dumps(value, default=str)):
                hits.add("stack trace in example")
        elif key in ("schema", "items", "additionalProperties", "allOf", "oneOf", "anyOf", "not"):
            hits |= _scan_leaks(spec, value, depth + 1)
    return hits


def check_verbose_errors(spec: dict[str, Any]) -> list[Finding]:
    """SG007: an error response schema or example exposes internal details."""
    findings = []
    for path, method, operation, _ in _operations(spec):
        responses = operation.get("responses") or {}
        if not isinstance(responses, dict):
            continue
        for code, raw_response in responses.items():
            code = str(code)
            if code != "default" and code[:1] not in ("4", "5"):
                continue
            response = _resolve(spec, raw_response)
            if response is None:
                continue
            hits: set[str] = set()
            for media in _as_dict(response.get("content")).values():
                if isinstance(media, dict):
                    hits |= _scan_leaks(spec, media)
            if hits:
                findings.append(
                    Finding(
                        "SG007",
                        "medium",
                        f"{_label(method, path)} responses.{code}",
                        "Error response exposes internal details: "
                        f"{', '.join(sorted(hits))}.",
                        "Return a generic error body with a correlation ID. "
                        "Log stack traces and SQL text on the server only.",
                    )
                )
    return findings


CHECKS: tuple[Callable[[dict[str, Any]], list[Finding]], ...] = (
    check_missing_auth,
    check_plain_http,
    check_credentials_in_query,
    check_insecure_schemes,
    check_mass_assignment,
    check_rate_limiting,
    check_verbose_errors,
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


def format_sarif(findings: list[Finding], spec_path: str | Path) -> str:
    """Render findings as SARIF 2.1.0 for GitHub code scanning."""
    uri = Path(spec_path).as_posix()
    rules = [
        {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": description},
            "help": {"text": description},
        }
        for rule_id, description in sorted(RULES.items())
    ]
    results = [
        {
            "ruleId": finding.rule_id,
            "level": SARIF_LEVEL[finding.severity],
            "message": {"text": f"{finding.message} Fix: {finding.remediation}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": 1, "startColumn": 1},
                    },
                    "logicalLocations": [{"name": finding.location}],
                }
            ],
            "properties": {"security-severity": SARIF_SECURITY_SEVERITY[finding.severity]},
        }
        for finding in findings
    ]
    log = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "specguard",
                        "version": __version__,
                        "informationUri": "https://github.com/kirtanbhatt10/specguard",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(log, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="specguard",
        description="Security linter for OpenAPI 3.x specifications.",
    )
    parser.add_argument("spec", help="path to an OpenAPI document (YAML or JSON)")
    parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="output format (default: text); sarif is for GitHub code scanning",
    )
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
    if args.format == "sarif":
        output = format_sarif(findings, args.spec)
    elif args.format == "json":
        output = format_json(findings)
    else:
        output = format_text(findings)
    print(output)

    if args.fail_on != "never":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
