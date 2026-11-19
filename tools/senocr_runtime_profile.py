"""Strict, model-free loader for the checked-in SenOCR runtime closure."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import re
from pathlib import Path
from typing import Iterable


PROFILE_SHA256 = "3d6150df16fc91bf032638d88a02d30be6877f5b4e62da5682fa601d0fe1ac1c"
PROFILE_FILENAME = "senocr_runtime_profile_v1.json"
PROFILE_SCHEMA_VERSION = 1
EXPECTED_PYTHON_VERSION = "3.13.17"
EXPECTED_PLATFORM = "windows-x64"
MAX_PROFILE_BYTES = 64 * 1024
MAX_DISTRIBUTIONS = 512
MAX_DISTRIBUTION_NAME_BYTES = 128
MAX_DISTRIBUTION_VERSION_BYTES = 128
EXPECTED_ROOT_PINS = [
    {"name": "jinja2", "version": "3.1.6"},
    {"name": "pillow", "version": "13.0.0"},
    {"name": "torch", "version": "2.15.0+cpu"},
    {"name": "transformers", "version": "5.23.0"},
]
PROFILE_FIELDS = {
    "distribution_count",
    "installed_distribution_closure",
    "platform",
    "python_version",
    "root_pins",
    "schema_version",
}
_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.!+_-]*$")


class RuntimeProfileError(ValueError):
    """The checked-in profile or installed distribution closure is invalid."""


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise RuntimeProfileError
        value[key] = item
    return value


def normalize_distribution_name(name: object) -> str:
    if (
        type(name) is not str
        or not name.isascii()
        or len(name.encode("ascii")) > MAX_DISTRIBUTION_NAME_BYTES
        or _NAME_PATTERN.fullmatch(name) is None
    ):
        raise RuntimeProfileError
    normalized = re.sub(r"[-_.]+", "-", name).lower()
    if not normalized:
        raise RuntimeProfileError
    return normalized


def _validate_version(version: object) -> str:
    if (
        type(version) is not str
        or not version.isascii()
        or len(version.encode("ascii")) > MAX_DISTRIBUTION_VERSION_BYTES
        or _VERSION_PATTERN.fullmatch(version) is None
    ):
        raise RuntimeProfileError
    return version


def validate_profile_document(profile: object) -> dict[str, object]:
    if type(profile) is not dict or set(profile) != PROFILE_FIELDS:
        raise RuntimeProfileError
    if (
        type(profile["schema_version"]) is not int
        or profile["schema_version"] != PROFILE_SCHEMA_VERSION
        or profile["python_version"] != EXPECTED_PYTHON_VERSION
        or profile["platform"] != EXPECTED_PLATFORM
        or profile["root_pins"] != EXPECTED_ROOT_PINS
    ):
        raise RuntimeProfileError

    packages = profile["installed_distribution_closure"]
    if type(packages) is not list or not 0 < len(packages) <= MAX_DISTRIBUTIONS:
        raise RuntimeProfileError
    package_names: list[str] = []
    package_versions: dict[str, str] = {}
    for package in packages:
        if type(package) is not dict or set(package) != {"name", "version"}:
            raise RuntimeProfileError
        name = normalize_distribution_name(package["name"])
        version = _validate_version(package["version"])
        if name != package["name"] or name in package_versions:
            raise RuntimeProfileError
        package_names.append(name)
        package_versions[name] = version
    if package_names != sorted(package_names):
        raise RuntimeProfileError
    if (
        type(profile["distribution_count"]) is not int
        or profile["distribution_count"] != len(package_versions)
    ):
        raise RuntimeProfileError
    for pin in EXPECTED_ROOT_PINS:
        if package_versions.get(pin["name"]) != pin["version"]:
            raise RuntimeProfileError
    if "pip" not in package_versions or "setuptools" not in package_versions:
        raise RuntimeProfileError
    return profile


def canonical_profile_payload(profile: object) -> bytes:
    validated = validate_profile_document(profile)
    return json.dumps(
        validated, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def load_profile(path: Path | None = None) -> tuple[dict[str, object], str]:
    profile_path = path or Path(__file__).with_name(PROFILE_FILENAME)
    if profile_path.is_symlink() or not profile_path.is_file():
        raise RuntimeProfileError
    try:
        with profile_path.open("rb") as stream:
            raw = stream.read(MAX_PROFILE_BYTES + 1)
    except OSError:
        raise RuntimeProfileError from None
    if not 0 < len(raw) <= MAX_PROFILE_BYTES:
        raise RuntimeProfileError
    if raw.endswith(b"\r\n"):
        payload = raw[:-2]
    elif raw.endswith(b"\n"):
        payload = raw[:-1]
    else:
        payload = raw
    if b"\r" in payload or b"\n" in payload:
        raise RuntimeProfileError
    digest = hashlib.sha256(payload).hexdigest()
    if digest != PROFILE_SHA256:
        raise RuntimeProfileError
    try:
        profile = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise RuntimeProfileError from None
    canonical = canonical_profile_payload(profile)
    if canonical != payload:
        raise RuntimeProfileError
    return profile, digest


def installed_distribution_versions() -> list[tuple[str, str]]:
    installed: list[tuple[str, str]] = []
    try:
        for distribution in importlib.metadata.distributions():
            installed.append(
                (
                    normalize_distribution_name(distribution.metadata.get("Name")),
                    _validate_version(distribution.version),
                )
            )
            if len(installed) > MAX_DISTRIBUTIONS:
                raise RuntimeProfileError
    except RuntimeProfileError:
        raise
    except Exception:
        raise RuntimeProfileError from None
    return installed


def validate_installed_distribution_closure(
    profile: dict[str, object], distributions: Iterable[tuple[object, object]]
) -> None:
    expected = {
        package["name"]: package["version"]
        for package in profile["installed_distribution_closure"]
    }
    actual: dict[str, str] = {}
    for raw_name, raw_version in distributions:
        name = normalize_distribution_name(raw_name)
        version = _validate_version(raw_version)
        if name in actual:
            raise RuntimeProfileError
        actual[name] = version
        if len(actual) > MAX_DISTRIBUTIONS:
            raise RuntimeProfileError
    if actual != expected:
        raise RuntimeProfileError
