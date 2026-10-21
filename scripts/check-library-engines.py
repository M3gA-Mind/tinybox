#!/usr/bin/env python3
"""Keep storage implementations out of TinyBox library dependency trees."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIBRARY_KINDS = {
    "lib",
    "rlib",
    "dylib",
    "cdylib",
    "staticlib",
    "proc-macro",
}
ALLOWED_STORAGE_PACKAGES = {
    "tinystoragedrivers-api",
    "tinystoragedrivers-types",
    # The busproxy uses this serialized contract; it contains no backend.
    "tinystoragedrivers-bus",
    "tinystoragedrivers-busproxy",
}
STORAGE_IMPLEMENTATION = re.compile(r"^tinystoragedrivers(?:-|$)")
OTHER_ENGINES = {
    "rusqlite",
    "sqlx",
    "mongodb",
    "keyring",
    "sled",
    "redb",
}


def tree_names(output: str) -> list[str]:
    """Extract package names from cargo tree's formatted output."""
    names: list[str] = []
    for raw_line in output.splitlines():
        line = raw_line.strip().lstrip("│├└─ ").strip()
        if not line:
            continue
        name = line.split()[0]
        if name:
            names.append(name)
    return names


def forbidden(names: list[str]) -> list[str]:
    """Return storage engines while allowing only the public port contracts."""
    return sorted(
        {
            name
            for name in names
            if (
                STORAGE_IMPLEMENTATION.match(name)
                and name not in ALLOWED_STORAGE_PACKAGES
            )
            or name in OTHER_ENGINES
        }
    )


def self_test() -> None:
    parsed = tree_names(
        "tinybox-core v0.1.40\r\n"
        "├── tinystoragedrivers-api v2.0.2\r\n"
        "└── tinystoragedrivers-types v2.0.2\r\n"
    )
    assert parsed == [
        "tinybox-core",
        "tinystoragedrivers-api",
        "tinystoragedrivers-types",
    ], parsed
    assert forbidden(parsed) == []
    assert forbidden(["tinybox-core", "tinystoragedrivers-document"]) == [
        "tinystoragedrivers-document"
    ]
    assert forbidden(["tinybox-core", "rusqlite"]) == ["rusqlite"]
    assert tree_names("\r\n") == []
    if not tree_names("tinybox-core v0.1.40\r\n"):
        raise AssertionError("tree parser accepted no root package")


def cargo_json(args: list[str]) -> dict:
    result = subprocess.run(
        ["cargo", *args], cwd=ROOT, text=True, capture_output=True, check=False
    )
    if result.returncode:
        raise RuntimeError(
            f"cargo {' '.join(args)} failed ({result.returncode}):\n{result.stderr}"
        )
    return json.loads(result.stdout)


def main() -> int:
    self_test()
    if sys.argv[1:] == ["--self-test"]:
        print("library engine gate matcher self-tests passed")
        return 0
    if sys.argv[1:]:
        print("usage: check-library-engines.py [--self-test]", file=sys.stderr)
        return 2

    metadata = cargo_json(["metadata", "--locked", "--format-version", "1", "--no-deps"])
    packages_by_id = {package["id"]: package for package in metadata["packages"]}
    members = metadata.get("workspace_members", [])
    if not members:
        raise RuntimeError("cargo metadata reported no workspace members")

    packages: dict[str, dict] = {}
    for member_id in members:
        package = packages_by_id.get(member_id)
        if package is None:
            raise RuntimeError(f"workspace member ID was not returned: {member_id}")
        if any(set(target["kind"]) & LIBRARY_KINDS for target in package["targets"]):
            packages[package["name"]] = package
    if not packages:
        raise RuntimeError("no workspace library targets found; refusing empty pass")

    failures: list[str] = []
    for package_name in sorted(packages):
        for feature_mode, feature_args in (
            ("default", ["--no-default-features"]),
            ("all", ["--all-features"]),
        ):
            command = [
                "tree",
                "--locked",
                "--format",
                "{p}",
                "--prefix",
                "none",
                "-e",
                "normal,build",
                "-p",
                package_name,
                *feature_args,
            ]
            result = subprocess.run(
                ["cargo", *command],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            if result.returncode:
                failures.append(
                    f"{package_name} ({feature_mode}): cargo {' '.join(command)} "
                    f"failed ({result.returncode})\n{result.stderr}"
                )
                continue
            names = tree_names(result.stdout)
            if package_name not in names:
                failures.append(
                    f"{package_name} ({feature_mode}): tree omitted its root package"
                )
                continue
            blocked = forbidden(names)
            if blocked:
                failures.append(
                    f"{package_name} ({feature_mode}): forbidden storage engines: "
                    + ", ".join(blocked)
                )
            print(f"{package_name} ({feature_mode}): {len(names)} packages, clean")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"checked {len(packages)} workspace libraries in default and all features")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, json.JSONDecodeError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
