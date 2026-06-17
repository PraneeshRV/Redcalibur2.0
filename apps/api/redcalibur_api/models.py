from enum import IntEnum, StrEnum
from typing import Any, Literal

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
    action: Literal["run_preview", "run"]
    target: str
    risk_tier: RiskTier
    decision: PolicyDecision
    policy_version: str
    input_summary: str
    redacted_input_hash: str
    created_at: str


class RunKind(StrEnum):
    manifest_scan = "manifest_scan"
    mcp_config_scan = "mcp_config_scan"
    ai_config_scan = "ai_config_scan"
    secrets_baseline = "secrets_baseline"
    baseline = "baseline"


class RunStatus(StrEnum):
    queued = "queued"
    running = "running"
    complete = "complete"
    failed = "failed"
    cancelling = "cancelling"
    cancelled = "cancelled"


_TERMINAL_RUN_STATUSES = frozenset(
    {RunStatus.complete, RunStatus.failed, RunStatus.cancelled}
)


def is_terminal_run_status(status: "RunStatus") -> bool:
    return status in _TERMINAL_RUN_STATUSES


class JobStatus(StrEnum):
    queued = "queued"
    running = "running"
    complete = "complete"
    failed = "failed"
    cancelled = "cancelled"


class Run(BaseModel):
    id: str
    workspace_id: str
    kind: RunKind
    status: RunStatus
    policy_snapshot: dict[str, Any]
    started_at: str
    finished_at: str | None = None


class Job(BaseModel):
    id: str
    run_id: str
    tool_id: str
    status: JobStatus
    input: dict[str, Any]
    output_summary: dict[str, Any] | None = None
    error: str | None = None
    started_at: str
    finished_at: str | None = None


class EvidenceItem(BaseModel):
    id: str
    workspace_id: str
    run_id: str
    source_tool: str
    evidence_type: str
    title: str
    summary: str
    normalized: dict[str, Any]
    collected_at: str


class RunEvent(BaseModel):
    id: str
    run_id: str
    seq: int
    event_type: str
    payload: dict[str, Any]
    created_at: str


class RunStartRequest(BaseModel):
    kind: RunKind
    # When true (default) the request blocks until the run reaches a terminal
    # state and returns the full result — preserves the simple synchronous
    # contract. When false the run is enqueued and a queued snapshot returns
    # immediately so the UI can stream live progress.
    wait: bool = True


class RunResponse(BaseModel):
    run: Run
    jobs: list[Job]
    evidence: list[EvidenceItem]
