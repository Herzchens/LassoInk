"""Emit a bounded, deterministic inventory of the isolated hosted runtime.

This helper reads installed distribution metadata only. It never imports model
packages, reads model files, or records machine paths, URLs, or secrets.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools import senocr_runtime_profile as runtime_profile

MAX_PACKAGE_COUNT = 512
MAX_INVENTORY_BYTES = 256 * 1024
OUTPUT_NAME = "senocr-runtime-inventory.json"


class InventoryError(Exception):
    pass


def _require(condition: bool) -> None:
    if not condition:
        raise InventoryError


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
    try:
        profile, profile_sha256 = runtime_profile.load_profile()
        python_version = ".".join(str(value) for value in sys.version_info[:3])
        _require(python_version == profile["python_version"])
        installed = runtime_profile.installed_distribution_versions()
        runtime_profile.validate_installed_distribution_closure(profile, installed)
    except runtime_profile.RuntimeProfileError:
        raise InventoryError from None

    packages = [
        {"name": name, "version": version}
        for name, version in sorted(installed)
    ]
    _require(len(packages) <= MAX_PACKAGE_COUNT)
    return {
        "schema_version": 1,
        "python_version": profile["python_version"],
        "platform": profile["platform"],
        "artifact_file_count": 1,
        "root_pins": profile["root_pins"],
        "installed_distribution_closure": packages,
        "distribution_count": len(packages),
        "runtime_profile_sha256": profile_sha256,
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
