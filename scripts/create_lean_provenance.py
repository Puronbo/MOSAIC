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
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "formal" / "polynomial"
EXPECTED_TOOLCHAIN = "leanprover/lean4:v4.36.0"
EXPECTED_MATHLIB_REVISION = "fc4f59e577feb1a4956671bc04ac18aaaf8cd842"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    toolchain = (PROJECT / "lean-toolchain").read_text(encoding="utf-8").strip()
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
    if "4.36.0" not in lean:
        raise SystemExit(f"observed Lean version does not match pinned toolchain: {lean!r}")
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    payload = {
        "schema_version": "mosaic.lean-build-provenance.v1",
        "source": {
            "repository": os.environ.get("GITHUB_REPOSITORY", "local"),
            "commit": commit,
        },
        "environment": {
            "lean_toolchain": toolchain,
            "lean_version_output": lean,
            "mathlib_revision": EXPECTED_MATHLIB_REVISION,
            "lake_manifest_sha256": sha256(manifest_path),
            "lakefile_sha256": sha256(PROJECT / "lakefile.lean"),
            "lean_entrypoint_sha256": sha256(PROJECT / "Main.lean"),
            "python_version": sys.version.split()[0],
            "platform": platform.platform(),
        },
        "execution": {
            "workflow": os.environ.get("GITHUB_WORKFLOW"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "runner_os": os.environ.get("RUNNER_OS"),
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
