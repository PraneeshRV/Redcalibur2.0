from pathlib import Path

from redcalibur_api.models import Mode, RiskTier, ScopeDeclaration
from redcalibur_api.tools.ai_config_scan import AiConfigScanAdapter
from redcalibur_api.tools.registry import ToolInput

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _demo_scope() -> ScopeDeclaration:
    return ScopeDeclaration(
        id="demo-scope",
        workspace_id="demo-ai-coding-stack",
        mode=Mode.demo,
        allowed_roots=["fixtures/demo-ai-stack"],
        excluded_roots=[],
        allowed_targets=[],
        max_risk_tier=RiskTier.passive_read_only,
        authorization_text="Demo fixture scope.",
    )


def test_ai_scan_finds_claude_md() -> None:
    adapter = AiConfigScanAdapter()
    result = adapter.run(
        ToolInput(workspace_id="demo-ai-coding-stack", scope=_demo_scope(), project_root=PROJECT_ROOT, params={})
    )

    assert result.success
    titles = [e.title for e in result.evidence]
    assert any("Claude instructions" in t for t in titles)


def test_ai_scan_detects_claude_tool() -> None:
    adapter = AiConfigScanAdapter()
    result = adapter.run(
        ToolInput(workspace_id="demo-ai-coding-stack", scope=_demo_scope(), project_root=PROJECT_ROOT, params={})
    )

    assert "claude" in result.output_summary["tools_detected"]


def test_ai_scan_evidence_type_is_ai_config() -> None:
    adapter = AiConfigScanAdapter()
    result = adapter.run(
        ToolInput(workspace_id="demo-ai-coding-stack", scope=_demo_scope(), project_root=PROJECT_ROOT, params={})
    )

    for record in result.evidence:
        assert record.evidence_type == "ai_config"


def test_ai_scan_detects_cursor(tmp_path) -> None:
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "rules.md").write_text("be helpful")

    scope = ScopeDeclaration(
        id="s", workspace_id="w", mode=Mode.demo,
        allowed_roots=["."], excluded_roots=[],
        allowed_targets=[], max_risk_tier=RiskTier.passive_read_only,
        authorization_text="",
    )
    adapter = AiConfigScanAdapter()
    result = adapter.run(ToolInput(workspace_id="w", scope=scope, project_root=tmp_path, params={}))

    assert "cursor" in result.output_summary["tools_detected"]


def test_ai_scan_detects_aider(tmp_path) -> None:
    (tmp_path / ".aider.conf.yml").write_text("model: gpt-4")

    scope = ScopeDeclaration(
        id="s", workspace_id="w", mode=Mode.demo,
        allowed_roots=["."], excluded_roots=[],
        allowed_targets=[], max_risk_tier=RiskTier.passive_read_only,
        authorization_text="",
    )
    adapter = AiConfigScanAdapter()
    result = adapter.run(ToolInput(workspace_id="w", scope=scope, project_root=tmp_path, params={}))

    assert "aider" in result.output_summary["tools_detected"]


def test_ai_scan_skips_excluded(tmp_path) -> None:
    # Two sibling roots; one is excluded entirely.
    keep_root = tmp_path / "proj-keep"
    skip_root = tmp_path / "proj-skip"
    keep_root.mkdir()
    skip_root.mkdir()
    (keep_root / "CLAUDE.md").write_text("keep me")
    (skip_root / "CLAUDE.md").write_text("skip me")

    scope = ScopeDeclaration(
        id="s", workspace_id="w", mode=Mode.demo,
        allowed_roots=["proj-keep", "proj-skip"],
        excluded_roots=["proj-skip"],
        allowed_targets=[], max_risk_tier=RiskTier.passive_read_only,
        authorization_text="",
    )
    adapter = AiConfigScanAdapter()
    result = adapter.run(ToolInput(workspace_id="w", scope=scope, project_root=tmp_path, params={}))

    files_found = [e.normalized.get("file", "") for e in result.evidence]
    assert any("proj-keep" in f for f in files_found)
    assert not any("proj-skip" in f for f in files_found)
    assert result.output_summary["skipped_excluded"] >= 1


def test_ai_scan_empty_when_no_root(tmp_path) -> None:
    scope = ScopeDeclaration(
        id="s", workspace_id="w", mode=Mode.demo,
        allowed_roots=["does-not-exist"], excluded_roots=[],
        allowed_targets=[], max_risk_tier=RiskTier.passive_read_only,
        authorization_text="",
    )
    adapter = AiConfigScanAdapter()
    result = adapter.run(ToolInput(workspace_id="w", scope=scope, project_root=tmp_path, params={}))

    assert result.success
    assert result.evidence == []
