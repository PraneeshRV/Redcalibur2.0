import asyncio
from pathlib import Path

import httpx

from redcalibur_api.models import Mode, RiskTier, ScopeDeclaration
from redcalibur_api.tools.secrets_baseline import SecretsBaselineAdapter
from redcalibur_api.tools.registry import ToolInput

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _demo_scope_with_secrets() -> ScopeDeclaration:
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


def test_secrets_scan_finds_fake_openai_key() -> None:
    adapter = SecretsBaselineAdapter()
    result = adapter.run(
        ToolInput(workspace_id="demo-ai-coding-stack", scope=_demo_scope_with_secrets(), project_root=PROJECT_ROOT, params={})
    )

    assert result.success
    all_patterns = [f["pattern"] for e in result.evidence for f in e.normalized["findings"]]
    assert "openai_api_key" in all_patterns


def test_secrets_scan_finds_fake_github_token() -> None:
    adapter = SecretsBaselineAdapter()
    result = adapter.run(
        ToolInput(workspace_id="demo-ai-coding-stack", scope=_demo_scope_with_secrets(), project_root=PROJECT_ROOT, params={})
    )

    all_patterns = [f["pattern"] for e in result.evidence for f in e.normalized["findings"]]
    assert "github_token" in all_patterns or "github_classic_token" in all_patterns


def test_secrets_scan_never_stores_secret_value(tmp_path) -> None:
    secret_file = tmp_path / "config.env"
    secret_file.write_text('OPENAI_API_KEY=sk-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n')

    scope = ScopeDeclaration(
        id="s", workspace_id="w", mode=Mode.demo,
        allowed_roots=["."], excluded_roots=[],
        allowed_targets=[], max_risk_tier=RiskTier.passive_read_only,
        authorization_text="",
    )
    adapter = SecretsBaselineAdapter()
    result = adapter.run(ToolInput(workspace_id="w", scope=scope, project_root=tmp_path, params={}))

    import json
    output_str = json.dumps([e.normalized for e in result.evidence])
    assert "sk-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" not in output_str


def test_secrets_scan_finding_has_pattern_and_line(tmp_path) -> None:
    (tmp_path / "creds.env").write_text('GITHUB_TOKEN=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n')

    scope = ScopeDeclaration(
        id="s", workspace_id="w", mode=Mode.demo,
        allowed_roots=["."], excluded_roots=[],
        allowed_targets=[], max_risk_tier=RiskTier.passive_read_only,
        authorization_text="",
    )
    adapter = SecretsBaselineAdapter()
    result = adapter.run(ToolInput(workspace_id="w", scope=scope, project_root=tmp_path, params={}))

    assert result.evidence
    finding = result.evidence[0].normalized["findings"][0]
    assert "pattern" in finding
    assert "line" in finding
    assert "file" in finding


def test_secrets_scan_skips_excluded(tmp_path) -> None:
    allowed = tmp_path / "proj"
    excluded = allowed / "secrets"
    excluded.mkdir(parents=True)
    (allowed / "safe.txt").write_text("nothing here")
    (excluded / "real.env").write_text('OPENAI_API_KEY=sk-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\n')

    scope = ScopeDeclaration(
        id="s", workspace_id="w", mode=Mode.demo,
        allowed_roots=["proj"], excluded_roots=["proj/secrets"],
        allowed_targets=[], max_risk_tier=RiskTier.passive_read_only,
        authorization_text="",
    )
    adapter = SecretsBaselineAdapter()
    result = adapter.run(ToolInput(workspace_id="w", scope=scope, project_root=tmp_path, params={}))

    all_files = [f["file"] for e in result.evidence for f in e.normalized["findings"]]
    assert not any("secrets" in f for f in all_files)
    assert result.output_summary["skipped_excluded"] >= 1


def test_secrets_scan_evidence_type() -> None:
    adapter = SecretsBaselineAdapter()
    result = adapter.run(
        ToolInput(workspace_id="demo-ai-coding-stack", scope=_demo_scope_with_secrets(), project_root=PROJECT_ROOT, params={})
    )

    for record in result.evidence:
        assert record.evidence_type == "secret_finding"


# --- Adapter execution contract: no unsafe subprocess/shell calls ---

def test_secrets_baseline_adapter_has_no_subprocess_calls() -> None:
    """Adapter source must not call subprocess, os.system, or os.popen."""
    import ast, inspect
    from redcalibur_api.tools import secrets_baseline as mod

    source = inspect.getsource(mod)
    tree = ast.parse(source)

    forbidden = {"subprocess", "os.system", "os.popen", "eval", "exec", "__import__"}
    calls_found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in forbidden or alias.name.startswith("subprocess"):
                    calls_found.append(alias.name)
        if isinstance(node, ast.ImportFrom):
            if node.module and (node.module in forbidden or node.module.startswith("subprocess")):
                calls_found.append(node.module)

    assert calls_found == [], f"Forbidden imports in secrets_baseline: {calls_found}"


def test_mcp_config_scan_adapter_has_no_subprocess_calls() -> None:
    import ast, inspect
    from redcalibur_api.tools import mcp_config_scan as mod

    source = inspect.getsource(mod)
    tree = ast.parse(source)

    forbidden_modules = {"subprocess"}
    calls_found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in forbidden_modules:
                    calls_found.append(alias.name)
        if isinstance(node, ast.ImportFrom):
            if node.module and node.module in forbidden_modules:
                calls_found.append(node.module)

    assert calls_found == [], f"Forbidden imports in mcp_config_scan: {calls_found}"


def test_ai_config_scan_adapter_has_no_subprocess_calls() -> None:
    import ast, inspect
    from redcalibur_api.tools import ai_config_scan as mod

    source = inspect.getsource(mod)
    tree = ast.parse(source)

    forbidden_modules = {"subprocess"}
    calls_found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in forbidden_modules:
                    calls_found.append(alias.name)
        if isinstance(node, ast.ImportFrom):
            if node.module and node.module in forbidden_modules:
                calls_found.append(node.module)

    assert calls_found == [], f"Forbidden imports in ai_config_scan: {calls_found}"


def test_manifest_scan_adapter_has_no_subprocess_calls() -> None:
    import ast, inspect
    from redcalibur_api.tools import manifest_scan as mod

    source = inspect.getsource(mod)
    tree = ast.parse(source)

    forbidden_modules = {"subprocess"}
    calls_found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in forbidden_modules:
                    calls_found.append(alias.name)
        if isinstance(node, ast.ImportFrom):
            if node.module and node.module in forbidden_modules:
                calls_found.append(node.module)

    assert calls_found == [], f"Forbidden imports in manifest_scan: {calls_found}"


# --- API-level: new run kinds accepted ---

def test_mcp_config_scan_run_via_api(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    from redcalibur_api.main import create_app

    async def exercise():
        transport = httpx.ASGITransport(app=create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            await client.get("/health")
            return await client.post(
                "/workspaces/demo-ai-coding-stack/runs",
                json={"kind": "mcp_config_scan"},
            )

    resp = asyncio.run(exercise())
    assert resp.status_code == 201
    body = resp.json()
    assert body["run"]["status"] == "complete"
    assert body["run"]["kind"] == "mcp_config_scan"


def test_ai_config_scan_run_via_api(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    from redcalibur_api.main import create_app

    async def exercise():
        transport = httpx.ASGITransport(app=create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            await client.get("/health")
            return await client.post(
                "/workspaces/demo-ai-coding-stack/runs",
                json={"kind": "ai_config_scan"},
            )

    resp = asyncio.run(exercise())
    assert resp.status_code == 201
    body = resp.json()
    assert body["run"]["status"] == "complete"
    assert body["run"]["kind"] == "ai_config_scan"


def test_secrets_baseline_run_via_api(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    from redcalibur_api.main import create_app

    async def exercise():
        transport = httpx.ASGITransport(app=create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            await client.get("/health")
            return await client.post(
                "/workspaces/demo-ai-coding-stack/runs",
                json={"kind": "secrets_baseline"},
            )

    resp = asyncio.run(exercise())
    assert resp.status_code == 201
    body = resp.json()
    assert body["run"]["status"] == "complete"
    assert body["run"]["kind"] == "secrets_baseline"
