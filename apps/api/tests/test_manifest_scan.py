from pathlib import Path

from redcalibur_api.models import Mode, RiskTier, ScopeDeclaration
from redcalibur_api.tools.manifest_scan import ManifestScanAdapter
from redcalibur_api.tools.registry import ToolInput

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _demo_scope() -> ScopeDeclaration:
    return ScopeDeclaration(
        id="demo-scope",
        workspace_id="demo-ai-coding-stack",
        mode=Mode.demo,
        allowed_roots=["fixtures/demo-ai-stack"],
        excluded_roots=["fixtures/demo-ai-stack/secrets"],
        allowed_targets=[],
        max_risk_tier=RiskTier.passive_read_only,
        authorization_text="Demo fixture scope.",
    )


def test_manifest_scan_finds_package_json() -> None:
    adapter = ManifestScanAdapter()
    result = adapter.run(
        ToolInput(
            workspace_id="demo-ai-coding-stack",
            scope=_demo_scope(),
            project_root=PROJECT_ROOT,
            params={},
        )
    )

    assert result.success
    manifest_names = [e.normalized["manifest"] for e in result.evidence]
    assert "package.json" in manifest_names


def test_manifest_scan_finds_pyproject_toml() -> None:
    adapter = ManifestScanAdapter()
    result = adapter.run(
        ToolInput(
            workspace_id="demo-ai-coding-stack",
            scope=_demo_scope(),
            project_root=PROJECT_ROOT,
            params={},
        )
    )

    assert result.success
    manifest_names = [e.normalized["manifest"] for e in result.evidence]
    assert "pyproject.toml" in manifest_names


def test_manifest_scan_extracts_npm_packages() -> None:
    adapter = ManifestScanAdapter()
    result = adapter.run(
        ToolInput(
            workspace_id="demo-ai-coding-stack",
            scope=_demo_scope(),
            project_root=PROJECT_ROOT,
            params={},
        )
    )

    npm_evidence = next(e for e in result.evidence if e.normalized["manifest"] == "package.json")
    packages = npm_evidence.normalized["packages"]
    ecosystems = {p["ecosystem"] for p in packages}
    assert "npm" in ecosystems
    names = [p["name"] for p in packages]
    assert "demo-vulnerable-package" in names


def test_manifest_scan_extracts_pypi_packages() -> None:
    adapter = ManifestScanAdapter()
    result = adapter.run(
        ToolInput(
            workspace_id="demo-ai-coding-stack",
            scope=_demo_scope(),
            project_root=PROJECT_ROOT,
            params={},
        )
    )

    py_evidence = next(e for e in result.evidence if e.normalized["manifest"] == "pyproject.toml")
    packages = py_evidence.normalized["packages"]
    names = [p["name"] for p in packages]
    assert "requests" in names
    assert "anthropic" in names


def test_manifest_scan_skips_nonexistent_root() -> None:
    scope = ScopeDeclaration(
        id="s",
        workspace_id="w",
        mode=Mode.demo,
        allowed_roots=["fixtures/does-not-exist"],
        excluded_roots=[],
        allowed_targets=[],
        max_risk_tier=RiskTier.passive_read_only,
        authorization_text="",
    )
    adapter = ManifestScanAdapter()
    result = adapter.run(
        ToolInput(workspace_id="w", scope=scope, project_root=PROJECT_ROOT, params={})
    )

    assert result.success
    assert result.evidence == []
    assert result.output_summary["manifests_found"] == 0


def test_manifest_scan_skips_excluded_root(tmp_path) -> None:
    # An allowed root containing a manifest inside an excluded subdir.
    allowed = tmp_path / "proj"
    excluded = allowed / "vendor"
    excluded.mkdir(parents=True)
    (allowed / "package.json").write_text('{"dependencies": {"a": "1.0.0"}}', encoding="utf-8")
    (excluded / "package.json").write_text('{"dependencies": {"secret-dep": "9.9.9"}}', encoding="utf-8")

    scope = ScopeDeclaration(
        id="s",
        workspace_id="w",
        mode=Mode.demo,
        allowed_roots=["proj"],
        excluded_roots=["proj/vendor"],
        allowed_targets=[],
        max_risk_tier=RiskTier.passive_read_only,
        authorization_text="",
    )
    adapter = ManifestScanAdapter()
    result = adapter.run(
        ToolInput(workspace_id="w", scope=scope, project_root=tmp_path, params={})
    )

    all_names = [p["name"] for e in result.evidence for p in e.normalized["packages"]]
    assert "a" in all_names
    assert "secret-dep" not in all_names
    assert result.output_summary["skipped_excluded"] == 1


def test_manifest_scan_output_summary_counts() -> None:
    adapter = ManifestScanAdapter()
    result = adapter.run(
        ToolInput(
            workspace_id="demo-ai-coding-stack",
            scope=_demo_scope(),
            project_root=PROJECT_ROOT,
            params={},
        )
    )

    assert result.output_summary["manifests_found"] == len(result.evidence)
    assert result.output_summary["total_packages"] > 0
