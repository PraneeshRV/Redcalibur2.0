import hashlib
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from redcalibur_api import db
from redcalibur_api.models import (
    AuditEvent,
    EvidenceItem,
    Job,
    JobStatus,
    PolicyDecision,
    Run,
    RunKind,
    RunPreviewRequest,
    RunPreviewResponse,
    RunResponse,
    RunStartRequest,
    RunStatus,
    ScopeDeclaration,
    WorkspaceCreate,
)
from redcalibur_api.policy import preview_policy
from redcalibur_api.tools import manifest_scan as _manifest_scan_module  # noqa: F401 — registers adapter
from redcalibur_api.tools.registry import ToolInput, get as get_tool


def _redacted_target_label(target: str) -> str:
    return f"redacted:{hashlib.sha256(target.encode('utf-8')).hexdigest()[:12]}"


ROOT = Path(__file__).resolve().parents[3]

_KIND_TO_TOOL = {
    RunKind.manifest_scan: "redcalibur.developer_surface.manifest_scan",
}


def create_app() -> FastAPI:
    app = FastAPI(title="RedCalibur 2.0 API", version="0.1.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT"],
        allow_headers=["*"],
    )

    @app.get("/health")
    async def health() -> dict[str, str]:
        db.initialize_database()
        return {"status": "ok"}

    @app.get("/workspaces")
    async def workspaces():
        db.initialize_database()
        return db.list_workspaces()

    @app.post("/workspaces", status_code=201)
    async def create_workspace(workspace: WorkspaceCreate):
        db.initialize_database()
        try:
            return db.create_workspace(workspace)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/workspaces/{workspace_id}")
    async def workspace(workspace_id: str):
        db.initialize_database()
        found = db.get_workspace(workspace_id)
        if found is None:
            raise HTTPException(status_code=404, detail="Workspace not found")
        return found

    @app.get("/workspaces/{workspace_id}/scope")
    async def get_scope(workspace_id: str):
        db.initialize_database()
        scope = db.get_scope(workspace_id)
        if scope is None:
            raise HTTPException(status_code=404, detail="Scope declaration not found")
        return scope

    @app.put("/workspaces/{workspace_id}/scope")
    async def put_scope(workspace_id: str, scope: ScopeDeclaration):
        db.initialize_database()
        if workspace_id != scope.workspace_id:
            raise HTTPException(status_code=400, detail="Scope workspace_id must match path")
        if db.get_workspace(workspace_id) is None:
            raise HTTPException(status_code=404, detail="Workspace not found")
        return db.save_scope(scope)

    @app.post("/workspaces/{workspace_id}/run-preview", response_model=RunPreviewResponse)
    async def run_preview(workspace_id: str, request: RunPreviewRequest):
        db.initialize_database()
        workspace = db.get_workspace(workspace_id)
        if workspace is None:
            raise HTTPException(status_code=404, detail="Workspace not found")

        scope = db.get_scope(workspace_id)
        decision = preview_policy(scope, request.target, request.target_type, request.risk_tier)

        raw_input_summary = f"{request.target_type.value}:{request.target}:risk-{int(request.risk_tier)}"
        redacted_hash = hashlib.sha256(raw_input_summary.encode("utf-8")).hexdigest()
        redacted_target = _redacted_target_label(request.target)
        db.insert_audit_event(
            AuditEvent(
                id=db.new_audit_event_id(),
                workspace_id=workspace_id,
                mode=workspace.mode,
                action="run_preview",
                target=redacted_target,
                risk_tier=request.risk_tier,
                decision=decision.decision,
                policy_version=decision.policy_version,
                input_summary=f"{request.target_type.value}:{redacted_target}:risk-{int(request.risk_tier)}",
                redacted_input_hash=redacted_hash,
                created_at=db.utc_now(),
            )
        )
        return decision

    @app.get("/workspaces/{workspace_id}/audit-events")
    async def audit_events(workspace_id: str):
        db.initialize_database()
        if db.get_workspace(workspace_id) is None:
            raise HTTPException(status_code=404, detail="Workspace not found")
        return db.list_audit_events(workspace_id)

    @app.post("/workspaces/{workspace_id}/runs", response_model=RunResponse, status_code=201)
    async def start_run(workspace_id: str, request: RunStartRequest):
        db.initialize_database()
        workspace = db.get_workspace(workspace_id)
        if workspace is None:
            raise HTTPException(status_code=404, detail="Workspace not found")
        scope = db.get_scope(workspace_id)
        if scope is None:
            raise HTTPException(status_code=400, detail="Workspace has no scope declaration.")

        tool_id = _KIND_TO_TOOL.get(request.kind)
        adapter = get_tool(tool_id) if tool_id else None
        if adapter is None:
            raise HTTPException(status_code=400, detail=f"No adapter registered for run kind '{request.kind}'.")

        # Policy gate: every tool run must pass through deterministic policy.
        # A tool may not execute above the workspace's declared max risk tier.
        tool_risk = adapter.meta.risk_tier
        policy_decision = (
            PolicyDecision.allowed
            if int(tool_risk) <= int(scope.max_risk_tier)
            else PolicyDecision.blocked
        )
        policy_reason = (
            "Tool risk tier within declared scope."
            if policy_decision == PolicyDecision.allowed
            else f"Tool risk tier {int(tool_risk)} exceeds workspace max risk tier {int(scope.max_risk_tier)}."
        )

        now = db.utc_now()
        policy_snapshot = {
            "mode": scope.mode.value,
            "max_risk_tier": int(scope.max_risk_tier),
            "tool_risk_tier": int(tool_risk),
            "policy_version": scope.policy_version,
            "decision": policy_decision.value,
        }

        def _write_run_audit(decision: PolicyDecision) -> None:
            input_summary = f"run:{request.kind.value}:tool-{tool_id}:risk-{int(tool_risk)}"
            db.insert_audit_event(
                AuditEvent(
                    id=db.new_audit_event_id(),
                    workspace_id=workspace_id,
                    mode=workspace.mode,
                    action="run",
                    target=tool_id,
                    risk_tier=tool_risk,
                    decision=decision,
                    policy_version=scope.policy_version,
                    input_summary=input_summary,
                    redacted_input_hash=hashlib.sha256(input_summary.encode("utf-8")).hexdigest(),
                    created_at=db.utc_now(),
                )
            )

        # Blocked by policy: record the run as failed, persist audit, run nothing.
        if policy_decision == PolicyDecision.blocked:
            run = db.create_run(
                Run(
                    id=db.new_id(),
                    workspace_id=workspace_id,
                    kind=request.kind,
                    status=RunStatus.failed,
                    policy_snapshot=policy_snapshot,
                    started_at=now,
                    finished_at=now,
                )
            )
            job = db.create_job(
                Job(
                    id=db.new_id(),
                    run_id=run.id,
                    tool_id=tool_id,
                    status=JobStatus.failed,
                    input={"allowed_roots": scope.allowed_roots},
                    error=policy_reason,
                    started_at=now,
                    finished_at=now,
                )
            )
            _write_run_audit(PolicyDecision.blocked)
            run = db.get_run(run.id)
            return RunResponse(run=run, jobs=[job], evidence=[])

        run = db.create_run(
            Run(
                id=db.new_id(),
                workspace_id=workspace_id,
                kind=request.kind,
                status=RunStatus.running,
                policy_snapshot=policy_snapshot,
                started_at=now,
            )
        )
        job = db.create_job(
            Job(
                id=db.new_id(),
                run_id=run.id,
                tool_id=tool_id,
                status=JobStatus.running,
                input={"allowed_roots": scope.allowed_roots},
                started_at=now,
            )
        )
        _write_run_audit(PolicyDecision.allowed)

        # Capture adapter failures as job/run results instead of surfacing a 500.
        try:
            tool_result = adapter.run(
                ToolInput(
                    workspace_id=workspace_id,
                    scope=scope,
                    project_root=ROOT,
                    params={},
                )
            )
        except Exception as exc:  # noqa: BLE001 — adapter faults must not crash the API.
            finished_at = db.utc_now()
            job.status = JobStatus.failed
            job.error = f"{type(exc).__name__}: {exc}"
            job.finished_at = finished_at
            db.update_job(job)
            db.update_run_status(run.id, RunStatus.failed, finished_at)
            run = db.get_run(run.id)
            return RunResponse(run=run, jobs=[job], evidence=[])

        finished_at = db.utc_now()
        evidence_items: list[EvidenceItem] = []
        for record in tool_result.evidence:
            item = db.insert_evidence_item(
                EvidenceItem(
                    id=db.new_id(),
                    workspace_id=workspace_id,
                    run_id=run.id,
                    source_tool=tool_id,
                    evidence_type=record.evidence_type,
                    title=record.title,
                    summary=record.summary,
                    normalized=record.normalized,
                    collected_at=finished_at,
                )
            )
            evidence_items.append(item)

        job.status = JobStatus.complete if tool_result.success else JobStatus.failed
        job.output_summary = tool_result.output_summary
        job.error = tool_result.error
        job.finished_at = finished_at
        db.update_job(job)

        run_status = RunStatus.complete if tool_result.success else RunStatus.failed
        db.update_run_status(run.id, run_status, finished_at)
        run = db.get_run(run.id)

        return RunResponse(run=run, jobs=[job], evidence=evidence_items)

    @app.get("/workspaces/{workspace_id}/runs")
    async def list_runs(workspace_id: str):
        db.initialize_database()
        if db.get_workspace(workspace_id) is None:
            raise HTTPException(status_code=404, detail="Workspace not found")
        return db.list_runs(workspace_id)

    @app.get("/runs/{run_id}", response_model=RunResponse)
    async def get_run(run_id: str):
        db.initialize_database()
        run = db.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        return RunResponse(
            run=run,
            jobs=db.list_jobs(run_id),
            evidence=db.list_evidence_items(run_id),
        )

    return app


app = create_app()
