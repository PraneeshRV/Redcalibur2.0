from enum import IntEnum, StrEnum
from typing import Literal

from pydantic import BaseModel, Field


POLICY_VERSION = "2026-05-30.product-spine-preview"


class Mode(StrEnum):
    demo = "demo"
    learning = "learning"
    authorized_assessment = "authorized_assessment"


class RiskTier(IntEnum):
    offline_demo = 0
    passive_read_only = 1
    low_impact_active = 2
    intrusive_active = 3
    prohibited = 4


class TargetType(StrEnum):
    local_path = "local_path"
    url = "url"
    domain = "domain"
    ip = "ip"
    repo = "repo"
    package = "package"


class PolicyDecision(StrEnum):
    allowed = "allowed"
    blocked = "blocked"
    requires_approval = "requires_approval"
    demo_only = "demo_only"


class Workspace(BaseModel):
    id: str
    name: str
    mode: Mode
    purpose: str


class WorkspaceCreate(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")
    name: str = Field(min_length=1)
    mode: Mode
    purpose: str = Field(min_length=1)


class ScopeDeclaration(BaseModel):
    id: str
    workspace_id: str
    mode: Mode
    allowed_roots: list[str] = Field(default_factory=list)
    excluded_roots: list[str] = Field(default_factory=list)
    allowed_targets: list[str] = Field(default_factory=list)
    max_risk_tier: RiskTier
    authorization_text: str
    policy_version: str = POLICY_VERSION


class RunPreviewRequest(BaseModel):
    target: str = Field(min_length=1)
    target_type: TargetType
    risk_tier: RiskTier


class RunPreviewResponse(BaseModel):
    decision: PolicyDecision
    reasons: list[str]
    policy_version: str
    normalized_target: str


class AuditEvent(BaseModel):
    id: str
    workspace_id: str
    mode: Mode
    action: Literal["run_preview"]
    target: str
    risk_tier: RiskTier
    decision: PolicyDecision
    policy_version: str
    input_summary: str
    redacted_input_hash: str
    created_at: str
