import ipaddress
from pathlib import Path
from urllib.parse import urlparse

from redcalibur_api.models import POLICY_VERSION, Mode, PolicyDecision, RiskTier, RunPreviewResponse, ScopeDeclaration, TargetType


ROOT = Path(__file__).resolve().parents[3]


def _resolve_scoped_path(value: str, project_root: Path) -> Path | None:
    raw_path = Path(value)
    if ".." in raw_path.parts:
        return None
    path = raw_path if raw_path.is_absolute() else project_root / raw_path
    return path.resolve(strict=False)


def _is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _is_private_ip(value: str) -> bool:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return False
    return parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_reserved


def preview_policy(
    scope: ScopeDeclaration | None,
    target: str,
    target_type: TargetType,
    risk_tier: RiskTier,
    project_root: Path = ROOT,
) -> RunPreviewResponse:
    reasons: list[str] = []
    normalized_target = target.strip()

    if scope is None:
        return RunPreviewResponse(
            decision=PolicyDecision.blocked,
            reasons=["No scope declaration exists for this workspace."],
            policy_version=POLICY_VERSION,
            normalized_target=normalized_target,
        )

    if int(risk_tier) > int(scope.max_risk_tier):
        reasons.append(f"Requested risk tier {int(risk_tier)} exceeds workspace max risk tier {int(scope.max_risk_tier)}.")

    if target_type in {TargetType.url, TargetType.domain} and scope.mode == Mode.demo:
        reasons.append("Demo mode blocks arbitrary network targets.")

    if target_type == TargetType.url:
        host = urlparse(normalized_target).hostname or ""
        if host and _is_private_ip(host):
            reasons.append("Target is a private, loopback, link-local, or reserved IP.")

    if target_type == TargetType.ip and _is_private_ip(normalized_target):
        reasons.append("Target is a private, loopback, link-local, or reserved IP.")

    if target_type == TargetType.local_path:
        resolved_target = _resolve_scoped_path(normalized_target, project_root)
        if resolved_target is None:
            reasons.append("Local path is invalid or attempts to traverse outside scope.")
        else:
            normalized_target = resolved_target.as_posix()
            excluded_roots = [
                (project_root / excluded).resolve(strict=False)
                for excluded in scope.excluded_roots
            ]
            allowed_roots = [
                (project_root / allowed).resolve(strict=False)
                for allowed in scope.allowed_roots
            ]
            if any(_is_within(resolved_target, excluded_root) for excluded_root in excluded_roots):
                reasons.append("Local path is inside an excluded scope root.")
            elif not any(_is_within(resolved_target, allowed_root) for allowed_root in allowed_roots):
                reasons.append("Local path is outside all allowed scope roots.")

    if reasons:
        return RunPreviewResponse(
            decision=PolicyDecision.blocked,
            reasons=reasons,
            policy_version=POLICY_VERSION,
            normalized_target=normalized_target,
        )

    return RunPreviewResponse(
        decision=PolicyDecision.allowed,
        reasons=["Target is within declared scope and risk tier."],
        policy_version=POLICY_VERSION,
        normalized_target=normalized_target,
    )
