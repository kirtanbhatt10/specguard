"""Tests for specguard. Run with: python -m unittest -v"""

import copy
import json
import os
import tempfile
import unittest
import unittest.mock
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

import specguard

HERE = Path(__file__).resolve().parent


def rule_ids(spec):
    return sorted(f.rule_id for f in specguard.audit(spec))


def clean_spec(**overrides):
    """A specification that should produce no findings."""
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "clean", "version": "1"},
        "servers": [{"url": "https://api.example.com"}],
        "security": [{"bearerAuth": []}],
        "paths": {
            "/orders": {
                "get": {"responses": {"200": {"description": "ok"}}},
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"item_id": {"type": "string"}},
                                    "additionalProperties": False,
                                }
                            }
                        }
                    },
                    "responses": {"201": {"description": "created"}},
                },
            }
        },
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
    }
    spec.update(overrides)
    return spec


class MissingAuthTests(unittest.TestCase):
    def test_global_security_covers_every_operation(self):
        self.assertNotIn("SG001", rule_ids(clean_spec()))

    def test_unprotected_write_is_high_severity(self):
        spec = clean_spec(security=None)
        spec.pop("security")
        findings = [f for f in specguard.audit(spec) if f.rule_id == "SG001"]
        self.assertTrue(findings)
        self.assertTrue(all(f.severity == "high" for f in findings if "POST" in f.location))

    def test_unprotected_read_is_medium_severity(self):
        spec = clean_spec()
        spec.pop("security")
        findings = {f.location: f for f in specguard.audit(spec) if f.rule_id == "SG001"}
        self.assertEqual(findings["GET /orders"].severity, "medium")

    def test_explicit_empty_security_is_flagged(self):
        spec = clean_spec()
        spec["paths"]["/orders"]["get"]["security"] = []
        self.assertIn("SG001", rule_ids(spec))


class TransportTests(unittest.TestCase):
    def test_plain_http_to_public_host_is_flagged(self):
        spec = clean_spec(servers=[{"url": "http://api.example.com"}])
        self.assertIn("SG002", rule_ids(spec))

    def test_plain_http_to_localhost_is_allowed(self):
        spec = clean_spec(servers=[{"url": "http://localhost:8000"}])
        self.assertNotIn("SG002", rule_ids(spec))


class CredentialTests(unittest.TestCase):
    def _with_query_param(self, name, location="query"):
        spec = clean_spec()
        spec["paths"]["/orders"]["get"]["parameters"] = [
            {"name": name, "in": location, "schema": {"type": "string"}}
        ]
        return spec

    def test_api_key_in_query_is_flagged(self):
        self.assertIn("SG003", rule_ids(self._with_query_param("api_key")))

    def test_token_in_query_is_flagged(self):
        self.assertIn("SG003", rule_ids(self._with_query_param("access_token")))

    def test_credential_in_header_is_not_flagged(self):
        self.assertNotIn("SG003", rule_ids(self._with_query_param("api_key", location="header")))

    def test_ordinary_query_parameter_is_not_flagged(self):
        self.assertNotIn("SG003", rule_ids(self._with_query_param("customer_id")))


class SchemeTests(unittest.TestCase):
    def test_api_key_in_query_scheme_is_flagged(self):
        spec = clean_spec()
        spec["components"]["securitySchemes"]["legacy"] = {
            "type": "apiKey", "in": "query", "name": "key"
        }
        self.assertIn("SG004", rule_ids(spec))

    def test_basic_auth_scheme_is_flagged(self):
        spec = clean_spec()
        spec["components"]["securitySchemes"]["basic"] = {"type": "http", "scheme": "basic"}
        self.assertIn("SG004", rule_ids(spec))

    def test_bearer_scheme_is_not_flagged(self):
        self.assertNotIn("SG004", rule_ids(clean_spec()))


class MassAssignmentTests(unittest.TestCase):
    def test_open_request_object_is_flagged(self):
        spec = clean_spec()
        schema = spec["paths"]["/orders"]["post"]["requestBody"]["content"]["application/json"]["schema"]
        schema.pop("additionalProperties")
        self.assertIn("SG005", rule_ids(spec))

    def test_additional_properties_true_is_flagged(self):
        spec = clean_spec()
        schema = spec["paths"]["/orders"]["post"]["requestBody"]["content"]["application/json"]["schema"]
        schema["additionalProperties"] = True
        self.assertIn("SG005", rule_ids(spec))

    def test_closed_request_object_is_not_flagged(self):
        self.assertNotIn("SG005", rule_ids(clean_spec()))

    def test_unresolvable_schema_reference_is_skipped(self):
        spec = clean_spec()
        content = spec["paths"]["/orders"]["post"]["requestBody"]["content"]
        content["application/json"]["schema"] = {"$ref": "#/components/schemas/Missing"}
        self.assertNotIn("SG005", rule_ids(spec))

    def test_resolvable_open_reference_is_flagged(self):
        spec = clean_spec()
        spec["components"]["schemas"] = {"Order": {"type": "object", "properties": {"x": {"type": "string"}}}}
        content = spec["paths"]["/orders"]["post"]["requestBody"]["content"]
        content["application/json"]["schema"] = {"$ref": "#/components/schemas/Order"}
        self.assertIn("SG005", rule_ids(spec))

    def test_resolvable_closed_reference_is_not_flagged(self):
        spec = clean_spec()
        spec["components"]["schemas"] = {
            "Order": {"type": "object", "properties": {"x": {"type": "string"}}, "additionalProperties": False}
        }
        content = spec["paths"]["/orders"]["post"]["requestBody"]["content"]
        content["application/json"]["schema"] = {"$ref": "#/components/schemas/Order"}
        self.assertNotIn("SG005", rule_ids(spec))

    def test_additional_properties_schema_is_flagged(self):
        spec = clean_spec()
        schema = spec["paths"]["/orders"]["post"]["requestBody"]["content"]["application/json"]["schema"]
        schema["additionalProperties"] = {"type": "string"}
        self.assertIn("SG005", rule_ids(spec))

    def test_reference_cycle_does_not_crash(self):
        spec = clean_spec()
        spec["components"]["schemas"] = {"A": {"$ref": "#/components/schemas/A"}}
        content = spec["paths"]["/orders"]["post"]["requestBody"]["content"]
        content["application/json"]["schema"] = {"$ref": "#/components/schemas/A"}
        self.assertNotIn("SG005", rule_ids(spec))


class LoaderAndCliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _write(self, name, text):
        path = self.dir / name
        path.write_text(text, encoding="utf-8")
        return str(path)

    def test_loads_json_and_yaml(self):
        as_json = self._write("spec.json", json.dumps(clean_spec()))
        self.assertEqual(specguard.load_spec(as_json)["openapi"], "3.0.3")

    def test_rejects_non_openapi_document(self):
        path = self._write("other.yaml", "name: not-an-api\n")
        with self.assertRaises(ValueError):
            specguard.load_spec(path)

    def test_rejects_unparseable_yaml(self):
        path = self._write("broken.yaml", "openapi: [unclosed\n")
        with self.assertRaises(ValueError):
            specguard.load_spec(path)

    def test_cli_exit_code_is_one_when_threshold_is_reached(self):
        with redirect_stdout(StringIO()):
            code = specguard.main([str(HERE / "vulnerable_api.yaml")])
        self.assertEqual(code, 1)

    def test_cli_exit_code_is_zero_for_clean_spec(self):
        path = self._write("clean.json", json.dumps(clean_spec()))
        with redirect_stdout(StringIO()):
            code = specguard.main([path])
        self.assertEqual(code, 0)

    def test_cli_never_mode_always_succeeds(self):
        with redirect_stdout(StringIO()):
            code = specguard.main([str(HERE / "vulnerable_api.yaml"), "--fail-on", "never"])
        self.assertEqual(code, 0)

    def test_cli_returns_two_for_missing_file(self):
        with redirect_stdout(StringIO()):
            code = specguard.main([str(self.dir / "nope.yaml")])
        self.assertEqual(code, 2)

    def test_json_output_is_valid(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            specguard.main([str(HERE / "vulnerable_api.yaml"), "--format", "json", "--fail-on", "never"])
        payload = json.loads(buffer.getvalue())
        self.assertTrue(payload)
        self.assertEqual(set(payload[0]), {"rule_id", "severity", "location", "message", "remediation"})


class SampleSpecTests(unittest.TestCase):
    def test_sample_triggers_every_rule(self):
        spec = specguard.load_spec(HERE / "vulnerable_api.yaml")
        self.assertEqual(set(rule_ids(spec)), set(specguard.RULES))

    def test_secure_reference_has_no_findings(self):
        spec = specguard.load_spec(HERE / "secure_api.yaml")
        self.assertEqual(specguard.audit(spec), [])

    def test_secure_reference_covers_every_sample_operation(self):
        def operations(name):
            return {(p, m) for p, m, _, _ in specguard._operations(specguard.load_spec(HERE / name))}

        self.assertEqual(operations("secure_api.yaml"), operations("vulnerable_api.yaml"))


class AnonymousAccessTests(unittest.TestCase):
    def test_optional_security_object_is_flagged(self):
        spec = clean_spec()
        spec["paths"]["/orders"]["get"]["security"] = [{}]
        self.assertIn("SG001", rule_ids(spec))

    def test_optional_security_alongside_scheme_is_flagged(self):
        spec = clean_spec()
        spec["paths"]["/orders"]["get"]["security"] = [{}, {"bearerAuth": []}]
        self.assertIn("SG001", rule_ids(spec))


class HostMatchTests(unittest.TestCase):
    def test_localhost_lookalike_host_is_flagged(self):
        spec = clean_spec(servers=[{"url": "http://localhost.attacker.example/v1"}])
        self.assertIn("SG002", rule_ids(spec))

    def test_ipv6_loopback_is_allowed(self):
        spec = clean_spec(servers=[{"url": "http://[::1]:8000"}])
        self.assertNotIn("SG002", rule_ids(spec))


class ReferencedParameterTests(unittest.TestCase):
    def test_referenced_credential_parameter_is_flagged(self):
        spec = clean_spec()
        spec["components"]["parameters"] = {
            "ApiKey": {"name": "api_key", "in": "query", "schema": {"type": "string"}}
        }
        spec["paths"]["/orders"]["get"]["parameters"] = [{"$ref": "#/components/parameters/ApiKey"}]
        self.assertIn("SG003", rule_ids(spec))


class RateLimitTests(unittest.TestCase):
    def _login(self, responses):
        spec = clean_spec()
        spec["paths"]["/auth/login"] = {
            "post": {"security": [], "responses": responses}
        }
        return spec

    def test_login_without_429_is_flagged(self):
        spec = self._login({"200": {"description": "ok"}})
        findings = [f for f in specguard.audit(spec) if f.rule_id == "SG006"]
        self.assertEqual([f.location for f in findings], ["POST /auth/login"])

    def test_login_with_429_is_not_flagged(self):
        spec = self._login({"200": {"description": "ok"}, "429": {"description": "slow down"}})
        self.assertNotIn("SG006", rule_ids(spec))

    def test_ordinary_paths_containing_auth_words_are_not_flagged(self):
        spec = clean_spec()
        spec["paths"]["/authors"] = {"get": {"responses": {"200": {"description": "ok"}}}}
        spec["paths"]["/tokens"] = {"get": {"responses": {"200": {"description": "ok"}}}}
        self.assertNotIn("SG006", rule_ids(spec))


class VerboseErrorTests(unittest.TestCase):
    def _with_error(self, schema=None, example=None):
        spec = clean_spec()
        media = {}
        if schema is not None:
            media["schema"] = schema
        if example is not None:
            media["example"] = example
        spec["paths"]["/orders"]["get"]["responses"]["500"] = {
            "description": "error",
            "content": {"application/json": media},
        }
        return spec

    def test_stack_field_in_error_schema_is_flagged(self):
        schema = {"type": "object", "properties": {"stack": {"type": "string"}}}
        self.assertIn("SG007", rule_ids(self._with_error(schema=schema)))

    def test_traceback_in_error_example_is_flagged(self):
        example = "Traceback (most recent call last): File app.py line 3"
        self.assertIn("SG007", rule_ids(self._with_error(example=example)))

    def test_generic_error_body_is_not_flagged(self):
        schema = {"type": "object", "properties": {"message": {"type": "string"}}}
        self.assertNotIn("SG007", rule_ids(self._with_error(schema=schema)))

    def test_success_response_is_not_checked(self):
        spec = clean_spec()
        spec["paths"]["/orders"]["get"]["responses"]["200"] = {
            "description": "ok",
            "content": {"application/json": {"schema": {"type": "object", "properties": {"stack": {}}}}},
        }
        self.assertNotIn("SG007", rule_ids(spec))


class MalformedInputTests(unittest.TestCase):
    """Malformed specs must never crash the linter; they just yield fewer findings."""

    WEIRD = (None, 0, 1.5, True, "text", [], {}, [1, None], {"$ref": 5}, {"$ref": "#/missing"})

    def _mutations(self):
        def walk(node, path=()):
            if path:
                yield path
            if isinstance(node, dict):
                for key, value in node.items():
                    yield from walk(value, path + (key,))
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    yield from walk(value, path + (index,))

        base = specguard.load_spec(HERE / "vulnerable_api.yaml")
        for path in walk(base):
            for weird in self.WEIRD:
                spec = copy.deepcopy(base)
                target = spec
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = copy.deepcopy(weird)
                yield path, weird, spec

    def test_type_swapped_nodes_never_crash(self):
        for path, weird, spec in self._mutations():
            with self.subTest(path=path, value=weird):
                findings = specguard.audit(spec)
                specguard.format_text(findings)
                specguard.format_sarif(findings, "spec.yaml")


class SarifAndLoaderTests(unittest.TestCase):
    def test_sarif_document_has_expected_shape(self):
        findings = specguard.audit(specguard.load_spec(HERE / "vulnerable_api.yaml"))
        log = json.loads(specguard.format_sarif(findings, "api/openapi.yaml"))
        self.assertEqual(log["version"], "2.1.0")
        run = log["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "specguard")
        self.assertEqual({r["id"] for r in run["tool"]["driver"]["rules"]}, set(specguard.RULES))
        self.assertEqual(len(run["results"]), len(findings))
        first = run["results"][0]
        self.assertEqual(first["level"], "error")
        uri = first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "api/openapi.yaml")

    def test_cli_sarif_output_is_valid_json(self):
        buffer = StringIO()
        with redirect_stdout(buffer):
            code = specguard.main([str(HERE / "vulnerable_api.yaml"), "--format", "sarif", "--fail-on", "never"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(buffer.getvalue())["version"], "2.1.0")

    def test_oversized_spec_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "big.yaml"
            path.write_text("openapi: 3.0.3\n", encoding="utf-8")
            with unittest.mock.patch.object(specguard, "MAX_SPEC_BYTES", 4):
                with self.assertRaises(ValueError):
                    specguard.load_spec(path)


if __name__ == "__main__":
    unittest.main()
