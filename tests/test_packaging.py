from __future__ import annotations

import base64
import csv
import hashlib
import io
from pathlib import Path
import tempfile
import tomllib
import unittest
import zipfile

import _hephaestus_build as backend
from tests.support import ROOT


class OfflinePackagingTests(unittest.TestCase):
    def test_build_backend_has_no_bootstrap_dependencies(self) -> None:
        with (ROOT / "pyproject.toml").open("rb") as handle:
            build_system = tomllib.load(handle)["build-system"]
        self.assertEqual(build_system["requires"], [])
        self.assertEqual(build_system["build-backend"], "_hephaestus_build")
        self.assertEqual(build_system["backend-path"], ["."])
        self.assertEqual(backend.get_requires_for_build_wheel(), [])

    def test_backend_builds_a_complete_verifiable_wheel(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            filename = backend.build_wheel(temporary)
            wheel = Path(temporary) / filename
            self.assertEqual(filename, "hephaestus_forge-0.0.0-py3-none-any.whl")

            with zipfile.ZipFile(wheel) as archive:
                names = set(archive.namelist())
                self.assertIn("hephaestus/__init__.py", names)
                self.assertIn("hephaestus/cli.py", names)
                self.assertFalse(any("__pycache__" in name for name in names))
                self.assertFalse(any(name.endswith(".pyc") for name in names))

                dist_info = "hephaestus_forge-0.0.0.dist-info"
                metadata = archive.read(f"{dist_info}/METADATA").decode("utf-8")
                self.assertIn("Name: hephaestus-forge\n", metadata)
                self.assertIn("Version: 0.0.0\n", metadata)
                self.assertEqual(
                    archive.read(f"{dist_info}/entry_points.txt"),
                    b"[console_scripts]\nhephaestus = hephaestus.cli:main\n",
                )

                record_path = f"{dist_info}/RECORD"
                rows = csv.reader(
                    io.StringIO(archive.read(record_path).decode("utf-8"))
                )
                recorded = {row[0]: row[1:] for row in rows}
                self.assertEqual(set(recorded), names)
                self.assertEqual(recorded[record_path], ["", ""])
                for path in names - {record_path}:
                    content = archive.read(path)
                    digest = base64.urlsafe_b64encode(
                        hashlib.sha256(content).digest()
                    ).rstrip(b"=")
                    self.assertEqual(recorded[path][0], f"sha256={digest.decode()}")
                    self.assertEqual(recorded[path][1], str(len(content)))


if __name__ == "__main__":
    unittest.main()
