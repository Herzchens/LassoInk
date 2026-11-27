#!/usr/bin/env python3
"""Write a sanitized license and MSRV inventory for a locked target graph."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def license_inventory(metadata_path: Path, target: str, output: Path) -> None:
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    resolve = metadata.get("resolve")
    if not isinstance(resolve, dict):
        raise ValueError("target-filtered locked cargo metadata is missing its resolved graph")
    package_by_id = {package["id"]: package for package in metadata.get("packages", [])}
    reached = {node["id"] for node in resolve.get("nodes", [])}
    packages = []
    unresolved_license = []
    unresolved_rust_version = []
    packages_by_license: dict[str, list[str]] = {}

    for package_id in sorted(reached):
        package = package_by_id.get(package_id)
        if package is None:
            raise ValueError("target-filtered locked dependency lacks package metadata")
        license_value = package.get("license")
        raw_license_file = package.get("license_file")
        license_file = Path(raw_license_file).name if raw_license_file else None
        name = str(package.get("name", ""))
        version = str(package.get("version", ""))
        item = {
            "name": name,
            "version": version,
            "license": license_value,
            "license_file": license_file,
            "rust_version": package.get("rust_version"),
        }
        packages.append(item)
        expression_key = str(license_value) if license_value else "(missing license metadata)"
        packages_by_license.setdefault(expression_key, []).append(f"{name}@{version}")
        if not license_value and not license_file:
            unresolved_license.append({"name": name, "version": version})
        if not item["rust_version"]:
            unresolved_rust_version.append({"name": name, "version": version})

    inventory = {
        "scope": "locked target-filtered resolved workspace graph",
        "target": target,
        "package_count": len(packages),
        "license_expression_counts": {
            expression: len(identities)
            for expression, identities in sorted(packages_by_license.items())
        },
        "packages_by_license_expression": {
            expression: sorted(identities)
            for expression, identities in sorted(packages_by_license.items())
        },
        "packages": packages,
        "unresolved_license_metadata": unresolved_license,
        "unresolved_rust_version_metadata": unresolved_rust_version,
        "missing_license_metadata_is_unresolved_not_inferred": True,
        "missing_rust_version_metadata_is_unresolved_not_inferred": True,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    license_inventory(args.metadata, args.target, args.output)


if __name__ == "__main__":
    main()
