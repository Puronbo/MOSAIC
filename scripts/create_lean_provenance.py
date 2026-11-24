"""Create a machine-readable provenance manifest for the pinned Lean/Mathlib project.

This records the declared and observed environment after pinned dependencies
are installed. CI signs this manifest into each proof receipt, then publishes a
GitHub artifact attestation only if the subsequent proof and replay checks pass.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "formal" / "polynomial"
EXPECTED_TOOLCHAIN = "leanprover/lean4:v4.36.0"
EXPECTED_MATHLIB_REVISION = "fc4f59e577feb1a4956671bc04ac18aaaf8cd842"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def executable_sha256(name: str) -> str:
    executable = shutil.which(name)
    if executable is None:
        raise SystemExit(f"required executable not found on PATH: {name}")
    return sha256(Path(executable).resolve())



def required_ci_metadata() -> dict[str, str]:
    """Return complete GitHub Actions identity or fail before writing provenance."""
    required = {
        "repository": "GITHUB_REPOSITORY",
        "workflow": "GITHUB_WORKFLOW",
        "run_id": "GITHUB_RUN_ID",
        "run_attempt": "GITHUB_RUN_ATTEMPT",
        "runner_os": "RUNNER_OS",
    }
    values = {key: os.environ.get(variable, "").strip() for key, variable in required.items()}
    missing = [key for key, value in values.items() if not value]
    if missing:
        raise SystemExit(
            "missing required GitHub Actions provenance metadata: "
            + ", ".join(missing)
        )
    if not re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*/[A-Za-z0-9_-][A-Za-z0-9_.-]*", values["repository"]):
        raise SystemExit("GITHUB_REPOSITORY must have owner/repository form")
    for key in ("run_id", "run_attempt"):
        if not values[key].isdigit() or int(values[key]) < 1:
            raise SystemExit(f"{required[key]} must be a positive integer")
    if values["runner_os"] not in {"Linux", "Windows", "macOS"}:
        raise SystemExit("RUNNER_OS must be Linux, Windows, or macOS")
    return values


def main() -> None:
    toolchain_path = PROJECT / "lean-toolchain"
    root_toolchain_path = ROOT / "lean-toolchain"
    toolchain = toolchain_path.read_text(encoding="utf-8").strip()
    root_toolchain = root_toolchain_path.read_text(encoding="utf-8").strip()
    if root_toolchain != toolchain:
        raise SystemExit("root and formal/polynomial Lean toolchain pins differ")
    if toolchain != EXPECTED_TOOLCHAIN:
        raise SystemExit(f"unexpected Lean toolchain: {toolchain!r}")
    manifest_path = PROJECT / "lake-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    mathlib = [p for p in manifest.get("packages", []) if p.get("name") == "mathlib"]
    if len(mathlib) != 1 or mathlib[0].get("rev") != EXPECTED_MATHLIB_REVISION:
        raise SystemExit("lake-manifest.json does not pin the expected Mathlib revision")
    lean = subprocess.run(
        ["lake", "env", "lean", "--version"],
        cwd=PROJECT, check=True, capture_output=True, text=True,
    ).stdout.strip()
    lake = subprocess.run(
        ["lake", "--version"], cwd=PROJECT, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    elan = subprocess.run(
        ["elan", "--version"], cwd=PROJECT, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    if "4.36.0" not in lean:
        raise SystemExit(f"observed Lean version does not match pinned toolchain: {lean!r}")
    mathlib_path = PROJECT / ".lake" / "packages" / "mathlib"
    observed_mathlib_revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=mathlib_path, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    if observed_mathlib_revision != EXPECTED_MATHLIB_REVISION:
        raise SystemExit(
            "installed Mathlib checkout does not match lake-manifest.json: "
            f"{observed_mathlib_revision!r}"
        )
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    if len(commit) != 40 or any(ch not in "0123456789abcdef" for ch in commit):
        raise SystemExit(f"git returned an invalid full commit ID: {commit!r}")
    ci = required_ci_metadata()
    payload = {
        "schema_version": "mosaic.lean-build-provenance.v1",
        "source": {
            "repository": ci["repository"],
            "commit": commit,
        },
        "environment": {
            "lean_toolchain": toolchain,
            "lean_version_output": lean,
            "lake_version_output": lake,
            "elan_version_output": elan,
            "lean_binary_sha256": executable_sha256("lean"),
            "lake_binary_sha256": executable_sha256("lake"),
            "elan_binary_sha256": executable_sha256("elan"),
            "root_lean_toolchain_sha256": sha256(root_toolchain_path),
            "formal_lean_toolchain_sha256": sha256(toolchain_path),
            "mathlib_revision": EXPECTED_MATHLIB_REVISION,
            "observed_mathlib_revision": observed_mathlib_revision,
            "lake_manifest_sha256": sha256(manifest_path),
            "lakefile_sha256": sha256(PROJECT / "lakefile.lean"),
            "lean_entrypoint_sha256": sha256(PROJECT / "Main.lean"),
            "python_version": sys.version.split()[0],
            "platform": platform.platform(),
        },
        "execution": {
            "workflow": ci["workflow"],
            "run_id": ci["run_id"],
            "run_attempt": ci["run_attempt"],
            "runner_os": ci["runner_os"],
        },
        "scope": (
            "Environment and source provenance for the Lean polynomial project. "
            "CI creates this manifest before request-bound proof checks, but only "
            "attests it after those checks and exact-source replay pass. It is "
            "not itself a proof or a record of every theorem invocation."
        ),
    }
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "lean-provenance.json"
    output.write_text(
        json.dumps(payload, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {output}")


if __name__ == "__main__":
    main()
