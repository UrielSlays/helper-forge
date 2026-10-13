"""Small, dependency-free PEP 517 wheel backend for offline installation.

The project intentionally keeps its build path inside the repository so that a
fresh Python environment does not have to download setuptools, wheel, or any
other build dependency.  This backend packages only Python source files under
``src/hephaestus`` plus the console-script metadata declared in ``pyproject``.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
from pathlib import Path
import re
import tomllib
from typing import Any
import zipfile


ROOT = Path(__file__).resolve().parent
PYPROJECT = ROOT / "pyproject.toml"
PACKAGE_ROOT = ROOT / "src" / "hephaestus"


def _project() -> dict[str, Any]:
    with PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)["project"]


def _wheel_component(value: str) -> str:
    """Return the normalized filename component required by the wheel spec."""

    if not value.isascii() or "\n" in value or "\r" in value:
        raise ValueError("wheel metadata identifiers must be single-line ASCII")
    return re.sub(r"[^A-Za-z0-9.]+", "_", value)


def _dist_info(project: dict[str, Any]) -> str:
    return (
        f"{_wheel_component(project['name'])}-"
        f"{_wheel_component(project['version'])}.dist-info"
    )


def _metadata(project: dict[str, Any]) -> bytes:
    fields = {
        "Name": project["name"],
        "Version": project["version"],
        "Summary": project["description"],
        "Requires-Python": project["requires-python"],
    }
    for key, value in fields.items():
        if not isinstance(value, str) or "\n" in value or "\r" in value:
            raise ValueError(f"project.{key} must be a single-line string")

    headers = ["Metadata-Version: 2.1"]
    headers.extend(f"{key}: {value}" for key, value in fields.items())
    return ("\n".join(headers) + "\n").encode("utf-8")


def _wheel_metadata() -> bytes:
    return (
        "Wheel-Version: 1.0\n"
        "Generator: hephaestus-offline-backend\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    ).encode("utf-8")


def _entry_points(project: dict[str, Any]) -> bytes:
    scripts = project.get("scripts", {})
    if not isinstance(scripts, dict):
        raise ValueError("project.scripts must be a table")
    lines = ["[console_scripts]"]
    for name, target in sorted(scripts.items()):
        if not isinstance(name, str) or not isinstance(target, str):
            raise ValueError("project.scripts entries must be strings")
        if any(character in name + target for character in "\r\n"):
            raise ValueError("project.scripts entries must be single-line strings")
        lines.append(f"{name} = {target}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _wheel_files(project: dict[str, Any]) -> dict[str, bytes]:
    if not PACKAGE_ROOT.is_dir():
        raise FileNotFoundError(f"package directory is missing: {PACKAGE_ROOT}")

    files = {
        path.relative_to(ROOT / "src").as_posix(): path.read_bytes()
        for path in sorted(PACKAGE_ROOT.rglob("*.py"))
        if "__pycache__" not in path.parts
    }
    if "hephaestus/__init__.py" not in files:
        raise FileNotFoundError("hephaestus/__init__.py is required")

    dist_info = _dist_info(project)
    files[f"{dist_info}/METADATA"] = _metadata(project)
    files[f"{dist_info}/WHEEL"] = _wheel_metadata()
    files[f"{dist_info}/entry_points.txt"] = _entry_points(project)
    files[f"{dist_info}/top_level.txt"] = b"hephaestus\n"
    return files


def _record(files: dict[str, bytes], record_path: str) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for path in sorted(files):
        content = files[path]
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest())
        writer.writerow((path, f"sha256={digest.rstrip(b'=').decode('ascii')}", len(content)))
    writer.writerow((record_path, "", ""))
    return output.getvalue().encode("utf-8")


def _write_member(archive: zipfile.ZipFile, path: str, content: bytes) -> None:
    member = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
    member.compress_type = zipfile.ZIP_DEFLATED
    member.external_attr = 0o644 << 16
    archive.writestr(member, content)


def get_requires_for_build_wheel(
    config_settings: dict[str, Any] | None = None,
) -> list[str]:
    del config_settings
    return []


def prepare_metadata_for_build_wheel(
    metadata_directory: str,
    config_settings: dict[str, Any] | None = None,
) -> str:
    del config_settings
    project = _project()
    dist_info = _dist_info(project)
    destination = Path(metadata_directory) / dist_info
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "METADATA").write_bytes(_metadata(project))
    (destination / "WHEEL").write_bytes(_wheel_metadata())
    (destination / "entry_points.txt").write_bytes(_entry_points(project))
    (destination / "top_level.txt").write_bytes(b"hephaestus\n")
    return dist_info


def build_wheel(
    wheel_directory: str,
    config_settings: dict[str, Any] | None = None,
    metadata_directory: str | None = None,
) -> str:
    del config_settings, metadata_directory
    project = _project()
    distribution = _wheel_component(project["name"])
    version = _wheel_component(project["version"])
    filename = f"{distribution}-{version}-py3-none-any.whl"
    destination = Path(wheel_directory)
    destination.mkdir(parents=True, exist_ok=True)

    files = _wheel_files(project)
    record_path = f"{_dist_info(project)}/RECORD"
    files[record_path] = _record(files, record_path)
    with zipfile.ZipFile(destination / filename, "w") as archive:
        for path in sorted(files):
            _write_member(archive, path, files[path])
    return filename
