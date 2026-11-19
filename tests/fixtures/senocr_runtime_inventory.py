"""Emit a bounded, deterministic inventory of the isolated hosted runtime.

This helper reads installed distribution metadata only. It never imports model
packages, reads model files, or records machine paths, URLs, or secrets.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import re
import sys
from pathlib import Path


EXPECTED_PYTHON = (3, 13, 17)
ROOT_PINS = (
    ("jinja2", "3.1.6"),
    ("pillow", "13.0.0"),
    ("torch", "2.15.0+cpu"),
    ("transformers", "5.23.0"),
)
MAX_PACKAGE_COUNT = 512
MAX_NAME_BYTES = 128
MAX_VERSION_BYTES = 128
MAX_INVENTORY_BYTES = 256 * 1024
OUTPUT_NAME = "senocr-runtime-inventory.json"
NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.!+_-]*$")


class InventoryError(Exception):
    pass


def _require(condition: bool) -> None:
    if not condition:
        raise InventoryError


def _normalize_name(name: object) -> str:
    _require(type(name) is str and name.isascii() and bool(NAME_PATTERN.fullmatch(name)))
    _require(len(name.encode("ascii")) <= MAX_NAME_BYTES)
    normalized = re.sub(r"[-_.]+", "-", name).lower()
    _require(bool(normalized))
    return normalized


def _bounded_version(version: object) -> str:
    _require(
        type(version) is str
        and version.isascii()
        and bool(VERSION_PATTERN.fullmatch(version))
        and len(version.encode("ascii")) <= MAX_VERSION_BYTES
    )
    return version


def _check_hosted_context() -> tuple[Path, str]:
    expected_head = os.environ.get("LASSOINK_EXPECTED_HEAD_SHA", "")
    required = {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Windows",
        "RUNNER_ARCH": "X64",
        "GITHUB_REPOSITORY": "Herzchens/LassoInk",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_HEAD_REF": "feat/benchmark-fidelity",
        "LASSOINK_EXPECTED_HEAD_REPOSITORY": "Herzchens/LassoInk",
        "LASSOINK_EXPECTED_HEAD_REF": "feat/benchmark-fidelity",
        "LASSOINK_RUN_RUNTIME_INVENTORY": "1",
    }
    _require(sys.platform == "win32" and platform.machine().lower() in {"amd64", "x86_64"})
    _require(all(os.environ.get(key) == value for key, value in required.items()))
    _require(
        len(expected_head) == 40
        and all(character in "0123456789abcdef" for character in expected_head)
        and os.environ.get("LASSOINK_CHECKED_OUT_HEAD_SHA") == expected_head
    )
    runner_temp = Path(os.environ.get("RUNNER_TEMP", ""))
    _require(runner_temp.is_absolute() and runner_temp.is_dir() and not runner_temp.is_symlink())
    return runner_temp.resolve(strict=True), expected_head


def _collect_inventory() -> dict[str, object]:
    _require(sys.version_info[:3] == EXPECTED_PYTHON)
    installed: dict[str, str] = {}
    for distribution in importlib.metadata.distributions():
        name = _normalize_name(distribution.metadata.get("Name"))
        version = _bounded_version(distribution.version)
        _require(name not in installed)
        installed[name] = version
        _require(len(installed) <= MAX_PACKAGE_COUNT)

    root_pins = [{"name": name, "version": version} for name, version in ROOT_PINS]
    for pin in root_pins:
        _require(installed.get(pin["name"]) == pin["version"])

    packages = [
        {"name": name, "version": version}
        for name, version in sorted(installed.items())
    ]
    return {
        "schema_version": 1,
        "python_version": ".".join(str(value) for value in EXPECTED_PYTHON),
        "platform": "windows-x64",
        "artifact_file_count": 1,
        "root_pins": root_pins,
        "installed_distribution_closure": packages,
        "distribution_count": len(packages),
        "closure_scope": "all distributions installed in the isolated venv, including pip bootstrap",
        "wheel_authenticity_claim": False,
    }


def main() -> int:
    try:
        runner_temp, source_head_sha = _check_hosted_context()
        inventory = _collect_inventory()
        inventory["source_head_sha"] = source_head_sha
        canonical = json.dumps(
            inventory, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        document = dict(inventory)
        document["inventory_sha256"] = hashlib.sha256(canonical).hexdigest()
        output = json.dumps(
            document, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8") + b"\n"
        _require(len(output) <= MAX_INVENTORY_BYTES)

        output_path = runner_temp / OUTPUT_NAME
        _require(
            output_path.parent == runner_temp
            and not output_path.exists()
            and not output_path.is_symlink()
        )
        with output_path.open("xb") as stream:
            stream.write(output)
            stream.flush()
        return 0
    except Exception:
        sys.stderr.write("runtime inventory generation failed\n")
        sys.stderr.flush()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
