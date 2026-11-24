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
    assert '"root_lean_toolchain_sha256": sha256(root_toolchain_path)' in source
