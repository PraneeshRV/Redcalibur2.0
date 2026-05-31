from pathlib import Path

from redcalibur_api.models import Mode, PolicyDecision, RiskTier, ScopeDeclaration, TargetType
from redcalibur_api.policy import preview_policy


PROJECT_ROOT = Path(__file__).resolve().parents[3]


def demo_scope(max_risk_tier: RiskTier = RiskTier.passive_read_only) -> ScopeDeclaration:
    return ScopeDeclaration(
        id="demo-scope",
        workspace_id="demo-ai-coding-stack",
        mode=Mode.demo,
        allowed_roots=["fixtures/demo-ai-stack"],
        excluded_roots=["fixtures/demo-ai-stack/secrets"],
        allowed_targets=[],
        max_risk_tier=max_risk_tier,
        authorization_text="Demo fixture scope.",
    )


def test_allows_local_fixture_path_inside_allowed_root() -> None:
    response = preview_policy(
        demo_scope(),
        str(PROJECT_ROOT / "fixtures" / "demo-ai-stack" / "package.json"),
        TargetType.local_path,
        RiskTier.passive_read_only,
        project_root=PROJECT_ROOT,
    )

    assert response.decision == PolicyDecision.allowed


def test_blocks_excluded_local_path() -> None:
    response = preview_policy(
        demo_scope(),
        str(PROJECT_ROOT / "fixtures" / "demo-ai-stack" / "secrets" / "token.txt"),
        TargetType.local_path,
        RiskTier.offline_demo,
        project_root=PROJECT_ROOT,
    )

    assert response.decision == PolicyDecision.blocked
    assert "excluded" in " ".join(response.reasons).lower()


def test_blocks_external_url_in_demo_mode() -> None:
    response = preview_policy(
        demo_scope(),
        "https://example.com",
        TargetType.url,
        RiskTier.offline_demo,
        project_root=PROJECT_ROOT,
    )

    assert response.decision == PolicyDecision.blocked
    assert "Demo mode" in " ".join(response.reasons)


def test_blocks_public_ip_target_in_demo_mode() -> None:
    response = preview_policy(
        demo_scope(),
        "8.8.8.8",
        TargetType.ip,
        RiskTier.offline_demo,
        project_root=PROJECT_ROOT,
    )

    assert response.decision == PolicyDecision.blocked
    assert "Demo mode" in " ".join(response.reasons)


def test_blocks_private_ip_target() -> None:
    response = preview_policy(
        demo_scope(),
        "192.168.1.10",
        TargetType.ip,
        RiskTier.offline_demo,
        project_root=PROJECT_ROOT,
    )

    assert response.decision == PolicyDecision.blocked
    assert "private" in " ".join(response.reasons).lower()


def test_blocks_missing_scope() -> None:
    response = preview_policy(
        None,
        str(PROJECT_ROOT / "fixtures" / "demo-ai-stack" / "package.json"),
        TargetType.local_path,
        RiskTier.offline_demo,
        project_root=PROJECT_ROOT,
    )

    assert response.decision == PolicyDecision.blocked
    assert "No scope" in " ".join(response.reasons)


def test_blocks_requested_risk_above_workspace_max() -> None:
    response = preview_policy(
        demo_scope(),
        str(PROJECT_ROOT / "fixtures" / "demo-ai-stack" / "mcp.json"),
        TargetType.local_path,
        RiskTier.low_impact_active,
        project_root=PROJECT_ROOT,
    )

    assert response.decision == PolicyDecision.blocked
    assert "risk" in " ".join(response.reasons).lower()
