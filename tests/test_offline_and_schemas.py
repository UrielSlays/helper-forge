from __future__ import annotations

import ast
import json
from pathlib import Path
import sys
import unittest

from tests.support import ROOT


class OfflineBoundaryTests(unittest.TestCase):
    def test_runtime_has_only_standard_library_dependencies(self) -> None:
        package = ROOT / "src" / "hephaestus"
        imported_roots: set[str] = set()
        for path in package.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported_roots.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    imported_roots.add(node.module.split(".")[0])
        non_stdlib = imported_roots - sys.stdlib_module_names
        self.assertEqual(non_stdlib, set())

    def test_runtime_imports_no_network_or_process_clients(self) -> None:
        forbidden = {
            "aiohttp",
            "ftplib",
            "http",
            "httpx",
            "paramiko",
            "requests",
            "smtplib",
            "socket",
            "ssl",
            "subprocess",
            "telnetlib",
            "urllib",
        }
        package = ROOT / "src" / "hephaestus"
        violations: list[str] = []
        for path in package.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                roots: set[str] = set()
                if isinstance(node, ast.Import):
                    roots = {alias.name.split(".")[0] for alias in node.names}
                elif isinstance(node, ast.ImportFrom) and node.module:
                    roots = {node.module.split(".")[0]}
                for root in roots & forbidden:
                    violations.append(f"{path.name}:{getattr(node, 'lineno', 0)}:{root}")
        self.assertEqual(violations, [])


class SchemaTests(unittest.TestCase):
    @staticmethod
    def _refs(value: object) -> list[str]:
        if isinstance(value, dict):
            found = [value["$ref"]] if isinstance(value.get("$ref"), str) else []
            for item in value.values():
                found.extend(SchemaTests._refs(item))
            return found
        if isinstance(value, list):
            found: list[str] = []
            for item in value:
                found.extend(SchemaTests._refs(item))
            return found
        return []

    def test_all_contract_schemas_are_present_and_valid_json(self) -> None:
        expected = {
            "scenario-pack.schema.json": "Hephaestus Prototype Scenario Pack v0",
            "event.schema.json": "Hephaestus Prototype Event v0",
            "signal.schema.json": "Hephaestus Prototype Signal v0",
            "action-proposal.schema.json": "Hephaestus Prototype Action Proposal v0",
            "helper-manifest.schema.json": "Hephaestus Prototype Helper Manifest v0",
            "event-result.schema.json": "Hephaestus Prototype Event Result v0",
            "run-summary.schema.json": "Hephaestus Prototype Run Summary v0",
        }
        schema_directory = ROOT / "schemas"
        self.assertEqual(
            {path.name for path in schema_directory.glob("*.schema.json")}, set(expected)
        )
        for filename, title in expected.items():
            schema = json.loads((schema_directory / filename).read_text(encoding="utf-8"))
            self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertEqual(schema["title"], title)
            self.assertIn("Structural preflight only", schema["$comment"])
            self.assertEqual(schema["type"], "object")
            self.assertFalse(schema["additionalProperties"])
            for reference in self._refs(schema):
                target = reference.split("#", 1)[0]
                if target:
                    self.assertTrue(
                        (schema_directory / target).is_file(),
                        f"{filename} references missing local schema {target}",
                    )

    def test_action_schema_has_no_arbitrary_command_channel(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "action-proposal.schema.json").read_text(
                encoding="utf-8"
            )
        )
        properties = schema["properties"]
        self.assertNotIn("command", properties)
        self.assertNotIn("arguments", properties)
        self.assertNotIn("payload", properties)
        self.assertEqual(properties["approval_state"]["const"], "requires_approval")


if __name__ == "__main__":
    unittest.main()
