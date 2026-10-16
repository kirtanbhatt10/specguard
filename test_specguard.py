"""Tests for specguard. Run with: python -m unittest -v"""

import json
import os
import tempfile
import unittest
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

    def test_referenced_schema_is_skipped(self):
        spec = clean_spec()
        content = spec["paths"]["/orders"]["post"]["requestBody"]["content"]
        content["application/json"]["schema"] = {"$ref": "#/components/schemas/Order"}
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
        self.assertEqual(
            set(rule_ids(spec)),
            {"SG001", "SG002", "SG003", "SG004", "SG005"},
        )


if __name__ == "__main__":
    unittest.main()
