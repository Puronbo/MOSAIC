"""Regression tests for the repository's pinned Lean build inputs."""
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "formal" / "polynomial"
EXPECTED_TOOLCHAIN = "leanprover/lean4:v4.36.0"
EXPECTED_MATHLIB = "fc4f59e577feb1a4956671bc04ac18aaaf8cd842"


def test_root_and_formal_lean_toolchains_are_identical_and_pinned():
    root_pin = (ROOT / "lean-toolchain").read_text(encoding="utf-8").strip()
    project_pin = (PROJECT / "lean-toolchain").read_text(encoding="utf-8").strip()
    assert root_pin == project_pin == EXPECTED_TOOLCHAIN


def test_lake_manifest_pins_mathlib_and_every_git_dependency_by_commit():
    manifest = json.loads((PROJECT / "lake-manifest.json").read_text(encoding="utf-8"))
    packages = manifest["packages"]
    mathlib = [package for package in packages if package["name"] == "mathlib"]
    assert len(mathlib) == 1
    assert mathlib[0]["rev"] == EXPECTED_MATHLIB
    assert all(
        re.fullmatch(r"[0-9a-f]{40}", package["rev"])
        for package in packages
        if package["type"] == "git"
    )


def test_lean_provenance_generator_checks_observed_mathlib_checkout():
    source = (ROOT / "scripts" / "create_lean_provenance.py").read_text(
        encoding="utf-8"
    )
    assert '["git", "rev-parse", "HEAD"]' in source
    assert "observed_mathlib_revision != EXPECTED_MATHLIB_REVISION" in source
    assert '"observed_mathlib_revision": observed_mathlib_revision' in source
    assert '"lake_version_output": lake' in source
    assert '"elan_version_output": elan' in source
    assert 'executable_sha256("lean")' in source
    assert 'executable_sha256("lake")' in source
    assert 'executable_sha256("elan")' in source
    assert '"root_lean_toolchain_sha256": sha256(root_toolchain_path)' in source



def test_lean_provenance_schema_requires_nonempty_ci_execution_identity():
    schema = json.loads(
        (ROOT / "schemas" / "lean-build-provenance-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    execution = schema["properties"]["execution"]
    assert set(execution["required"]) == {
        "workflow", "run_id", "run_attempt", "runner_os"
    }
    properties = execution["properties"]
    assert properties["workflow"] == {"type": "string", "minLength": 1}
    assert properties["runner_os"] == {"type": "string", "minLength": 1}
    assert properties["run_id"]["type"] == "string"
    assert properties["run_id"]["pattern"] == "^[0-9]+$"
    assert properties["run_attempt"]["type"] == "string"
    assert properties["run_attempt"]["pattern"] == "^[0-9]+$"
