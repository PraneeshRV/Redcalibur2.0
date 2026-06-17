from pathlib import Path

from redcalibur_api.models import Mode, RiskTier, ScopeDeclaration
from redcalibur_api.tools.mcp_config_scan import McpConfigScanAdapter
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


def test_mcp_scan_finds_mcp_json() -> None:
    adapter = McpConfigScanAdapter()
    result = adapter.run(
        ToolInput(workspace_id="demo-ai-coding-stack", scope=_demo_scope(), project_root=PROJECT_ROOT, params={})
    )

    assert result.success
    config_files = [e.normalized["config_file"] for e in result.evidence]
    assert any("mcp.json" in cf for cf in config_files)


def test_mcp_scan_finds_claude_settings() -> None:
    adapter = McpConfigScanAdapter()
    result = adapter.run(
        ToolInput(workspace_id="demo-ai-coding-stack", scope=_demo_scope(), project_root=PROJECT_ROOT, params={})
    )

    assert result.success
    all_servers = [s for e in result.evidence for s in e.normalized["servers"]]
    server_names = [s["name"] for s in all_servers]
    assert "demo-mcp-server" in server_names


def test_mcp_scan_extracts_server_fields() -> None:
    adapter = McpConfigScanAdapter()
    result = adapter.run(
        ToolInput(workspace_id="demo-ai-coding-stack", scope=_demo_scope(), project_root=PROJECT_ROOT, params={})
    )

    all_servers = [s for e in result.evidence for s in e.normalized["servers"]]
    for server in all_servers:
        assert "name" in server
        assert "command" in server
        assert "args" in server
        assert "env_keys" in server


def test_mcp_scan_env_keys_not_values(tmp_path) -> None:
    cfg = tmp_path / ".mcp.json"
    cfg.write_text('{"mcpServers": {"s": {"command": "node", "env": {"SECRET_KEY": "hunter2"}}}}')

    scope = ScopeDeclaration(
        id="s", workspace_id="w", mode=Mode.demo,
        allowed_roots=["."], excluded_roots=[],
        allowed_targets=[], max_risk_tier=RiskTier.passive_read_only,
        authorization_text="",
    )
    adapter = McpConfigScanAdapter()
    result = adapter.run(ToolInput(workspace_id="w", scope=scope, project_root=tmp_path, params={}))

    all_servers = [s for e in result.evidence for s in e.normalized["servers"]]
    assert all_servers[0]["env_keys"] == ["SECRET_KEY"]
    # The value "hunter2" must not appear anywhere in the output
    import json
    assert "hunter2" not in json.dumps(result.output_summary)
    assert "hunter2" not in json.dumps([e.normalized for e in result.evidence])


def test_mcp_scan_skips_excluded_root(tmp_path) -> None:
    allowed = tmp_path / "proj"
    excluded = allowed / "vendor"
    excluded.mkdir(parents=True)
    (allowed / ".mcp.json").write_text('{"mcpServers": {"keep": {"command": "node"}}}')
    (excluded / ".mcp.json").write_text('{"mcpServers": {"drop": {"command": "node"}}}')

    scope = ScopeDeclaration(
        id="s", workspace_id="w", mode=Mode.demo,
        allowed_roots=["proj"], excluded_roots=["proj/vendor"],
        allowed_targets=[], max_risk_tier=RiskTier.passive_read_only,
        authorization_text="",
    )
    adapter = McpConfigScanAdapter()
    result = adapter.run(ToolInput(workspace_id="w", scope=scope, project_root=tmp_path, params={}))

    all_names = [s["name"] for e in result.evidence for s in e.normalized["servers"]]
    assert "keep" in all_names
    assert "drop" not in all_names
    assert result.output_summary["skipped_excluded"] == 1


def test_mcp_scan_empty_when_no_root(tmp_path) -> None:
    scope = ScopeDeclaration(
        id="s", workspace_id="w", mode=Mode.demo,
        allowed_roots=["does-not-exist"], excluded_roots=[],
        allowed_targets=[], max_risk_tier=RiskTier.passive_read_only,
        authorization_text="",
    )
    adapter = McpConfigScanAdapter()
    result = adapter.run(ToolInput(workspace_id="w", scope=scope, project_root=tmp_path, params={}))

    assert result.success
    assert result.evidence == []
