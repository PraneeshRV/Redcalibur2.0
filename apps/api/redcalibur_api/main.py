import asyncio
import hashlib
import json
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse, HTMLResponse

from redcalibur_api import db
from redcalibur_api.ai import gateway as analyst_gateway
from redcalibur_api import reporting
from redcalibur_api.findings import derive_findings
from redcalibur_api.models import (
    AnalystRequest,
    AnalystResponse,
    AuditEvent,
    FindingState,
    FindingStatus,
    FindingStatusUpdate,
    Job,
    JobStatus,
    Run,
    RunPreviewRequest,
    RunPreviewResponse,
    RunResponse,
    RunStartRequest,
    RunStatus,
    ScopeDeclaration,
    WorkspaceCreate,
    is_terminal_run_status,
)
from redcalibur_api.lab import suites as lab_suites
from redcalibur_api.lab.mock_app import MockAIApp
from redcalibur_api.recon import gate as recon_gate
from redcalibur_api.recon.asset_graph import build_asset_graph
from redcalibur_api.orchestrator import RunOrchestrator, tools_for_kind
from redcalibur_api.policy import preview_policy
from redcalibur_api.tools import manifest_scan as _manifest_scan_module  # noqa: F401 — registers adapter
from redcalibur_api.tools import mcp_config_scan as _mcp_config_scan_module  # noqa: F401 — registers adapter
from redcalibur_api.tools import ai_config_scan as _ai_config_scan_module  # noqa: F401 — registers adapter
from redcalibur_api.tools import secrets_baseline as _secrets_baseline_module  # noqa: F401 — registers adapter
from redcalibur_api.tools import vuln_scan as _vuln_scan_module  # noqa: F401 — registers adapter
from redcalibur_api.tools import ai_eval as _ai_eval_module  # noqa: F401 — registers adapter

# How long a synchronous (wait=True) run request will block before returning a
# still-running snapshot. Generous enough for the deterministic local adapters.
_SYNC_RUN_TIMEOUT_SECONDS = 60


def _redacted_target_label(target: str) -> str:
    return f"redacted:{hashlib.sha256(target.encode('utf-8')).hexdigest()[:12]}"


ROOT = Path(__file__).resolve().parents[3]


def create_app() -> FastAPI:
    app = FastAPI(title="RedCalibur 2.0 API", version="0.1.0")
    orchestrator = RunOrchestrator(project_root=ROOT)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH"],
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

    # NOTE: a plain ``def`` (not ``async def``) — Starlette runs it in a
    # threadpool, so the synchronous wait below never blocks the event loop.
    @app.get("/workspaces/{workspace_id}/findings")
    async def findings(workspace_id: str):
        db.initialize_database()
        if db.get_workspace(workspace_id) is None:
            raise HTTPException(status_code=404, detail="Workspace not found")
        evidence = db.list_workspace_evidence(workspace_id)
        states = db.get_finding_states(workspace_id)
        return derive_findings(workspace_id, evidence, states)

    def _derived_findings(workspace_id: str):
        evidence = db.list_workspace_evidence(workspace_id)
        states = db.get_finding_states(workspace_id)
        return derive_findings(workspace_id, evidence, states)

    @app.patch("/workspaces/{workspace_id}/findings/{finding_id}")
    async def update_finding(workspace_id: str, finding_id: str, update: FindingStatusUpdate):
        db.initialize_database()
        if db.get_workspace(workspace_id) is None:
            raise HTTPException(status_code=404, detail="Workspace not found")
        # The finding must currently exist (no orphan status rows for stale ids).
        if not any(f.id == finding_id for f in _derived_findings(workspace_id)):
            raise HTTPException(status_code=404, detail="Finding not found")
        state = db.set_finding_state(
            FindingState(
                finding_id=finding_id,
                workspace_id=workspace_id,
                status=update.status,
                note=update.note,
                updated_at=db.utc_now(),
            )
        )
        return state

    @app.post("/workspaces/{workspace_id}/findings/{finding_id}/verify")
    async def verify_finding(workspace_id: str, finding_id: str):
        db.initialize_database()
        if db.get_workspace(workspace_id) is None:
            raise HTTPException(status_code=404, detail="Workspace not found")
        finding = next((f for f in _derived_findings(workspace_id) if f.id == finding_id), None)
        if finding is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        # Only ai_eval findings carry a re-runnable probe. Verification re-runs the
        # probe against a hardened ("fixed") target; if it no longer triggers, the
        # finding is marked verified — a regression check, fully offline.
        if finding.finding_kind.value != "ai_eval":
            raise HTTPException(status_code=400, detail="Only ai_eval findings support automated verification.")
        # The probe id is the finding's vuln_id (stable, not parsed from the path).
        probe_id = finding.vuln_id
        result = lab_suites.evaluate_probe(MockAIApp(hardened=True), probe_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Probe not found for finding.")
        new_status = FindingStatus.verified if not result.vulnerable else FindingStatus.open
        state = db.set_finding_state(
            FindingState(
                finding_id=finding_id,
                workspace_id=workspace_id,
                status=new_status,
                note="Re-ran probe against hardened target." if not result.vulnerable else "Probe still vulnerable.",
                updated_at=db.utc_now(),
            )
        )
        return {"finding_id": finding_id, "verified": not result.vulnerable, "state": state, "probe_result": result}

    @app.get("/workspaces/{workspace_id}/asset-graph")
    async def asset_graph(workspace_id: str):
        db.initialize_database()
        workspace = db.get_workspace(workspace_id)
        if workspace is None:
            raise HTTPException(status_code=404, detail="Workspace not found")
        evidence = db.list_workspace_evidence(workspace_id)
        return build_asset_graph(workspace, evidence)

    @app.post("/workspaces/{workspace_id}/recon")
    async def recon(workspace_id: str):
        db.initialize_database()
        if db.get_workspace(workspace_id) is None:
            raise HTTPException(status_code=404, detail="Workspace not found")
        # v2 network recon is gated off by the safety policy. Refuse explicitly.
        if not recon_gate.network_recon_enabled():
            raise HTTPException(status_code=403, detail=recon_gate.deferred_reason())
        raise HTTPException(status_code=501, detail="Recon execution not implemented.")

    @app.get("/lab/probes")
    async def lab_probes():
        probes = lab_suites.list_probes()
        return [
            {"id": p.id, "category": p.category, "title": p.title}
            for p in probes
        ]

    @app.get("/workspaces/{workspace_id}/report")
    async def report(workspace_id: str, format: str = "md"):
        db.initialize_database()
        workspace = db.get_workspace(workspace_id)
        if workspace is None:
            raise HTTPException(status_code=404, detail="Workspace not found")
        if format not in ("md", "html"):
            raise HTTPException(status_code=400, detail="format must be 'md' or 'html'")
        runs = db.list_runs(workspace_id)
        evidence = db.list_workspace_evidence(workspace_id)
        states = db.get_finding_states(workspace_id)
        if format == "html":
            return HTMLResponse(reporting.build_html(workspace, runs, evidence, states=states))
        return PlainTextResponse(
            reporting.build_markdown(workspace, runs, evidence, states=states),
            media_type="text/markdown",
        )

    @app.post("/workspaces/{workspace_id}/analyst", response_model=AnalystResponse)
    async def analyst(workspace_id: str, request: AnalystRequest):
        db.initialize_database()
        if db.get_workspace(workspace_id) is None:
            raise HTTPException(status_code=404, detail="Workspace not found")
        if request.run_id is not None:
            evidence = db.list_evidence_items(request.run_id)
        else:
            evidence = db.list_workspace_evidence(workspace_id)
        # Mock provider only — no live AI calls. The gateway validates every
        # claim's citations against this evidence set and rejects ungrounded ones.
        return analyst_gateway.analyze(request.kind, evidence)

    @app.post("/workspaces/{workspace_id}/runs", response_model=RunResponse, status_code=201)
    def start_run(workspace_id: str, request: RunStartRequest):
        db.initialize_database()
        workspace = db.get_workspace(workspace_id)
        if workspace is None:
            raise HTTPException(status_code=404, detail="Workspace not found")
        scope = db.get_scope(workspace_id)
        if scope is None:
            raise HTTPException(status_code=400, detail="Workspace has no scope declaration.")

        tool_ids = tools_for_kind(request.kind)
        if not tool_ids:
            raise HTTPException(status_code=400, detail=f"No adapter registered for run kind '{request.kind}'.")

        now = db.utc_now()
        policy_snapshot = {
            "mode": scope.mode.value,
            "max_risk_tier": int(scope.max_risk_tier),
            "policy_version": scope.policy_version,
            "kind": request.kind.value,
            "tool_ids": tool_ids,
        }
        run = db.create_run(
            Run(
                id=db.new_id(),
                workspace_id=workspace_id,
                kind=request.kind,
                status=RunStatus.queued,
                policy_snapshot=policy_snapshot,
                started_at=now,
            )
        )
        # Pre-create one queued job per tool so the UI can render the plan
        # immediately, before the worker picks the run up.
        for tool_id in tool_ids:
            db.create_job(
                Job(
                    id=db.new_id(),
                    run_id=run.id,
                    tool_id=tool_id,
                    status=JobStatus.queued,
                    input={"allowed_roots": scope.allowed_roots},
                    started_at=now,
                )
            )

        orchestrator.enqueue(run.id)

        if request.wait:
            orchestrator.wait(run.id, timeout=_SYNC_RUN_TIMEOUT_SECONDS)

        run = db.get_run(run.id)
        return RunResponse(
            run=run,
            jobs=db.list_jobs(run.id),
            evidence=db.list_evidence_items(run.id),
        )

    @app.post("/runs/{run_id}/cancel", response_model=RunResponse)
    def cancel_run(run_id: str):
        db.initialize_database()
        run = db.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")
        if is_terminal_run_status(run.status):
            raise HTTPException(status_code=409, detail=f"Run already {run.status.value}; cannot cancel.")
        # Persist the intent so the worker observes it even across threads, and
        # signal the in-process orchestrator directly.
        db.update_run_status(run_id, RunStatus.cancelling)
        db.append_run_event(run_id, "cancel_requested", {})
        orchestrator.request_cancel(run_id)
        run = db.get_run(run_id)
        return RunResponse(
            run=run,
            jobs=db.list_jobs(run_id),
            evidence=db.list_evidence_items(run_id),
        )

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

    @app.get("/runs/{run_id}/events")
    async def run_events(run_id: str, request: Request):
        db.initialize_database()
        run = db.get_run(run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Run not found")

        # Wall-clock ceiling so a wedged run cannot hold the connection forever
        # (0.2s poll * 1500 = 5 minutes).
        max_polls = 1500

        async def event_stream():
            last_seq = 0

            def _flush(events):
                nonlocal last_seq
                lines = []
                for event in events:
                    last_seq = event.seq
                    lines.append(
                        f"event: {event.event_type}\n"
                        f"data: {json.dumps(event.model_dump(mode='json'))}\n\n"
                    )
                return lines

            for _ in range(max_polls):
                if await request.is_disconnected():
                    return
                for line in _flush(db.list_run_events(run_id, after_seq=last_seq)):
                    yield line
                current = db.get_run_status(run_id)
                if current is not None and is_terminal_run_status(current):
                    # Final flush of any events written alongside the terminal status.
                    for line in _flush(db.list_run_events(run_id, after_seq=last_seq)):
                        yield line
                    yield f"event: stream_end\ndata: {json.dumps({'status': current.value})}\n\n"
                    return
                await asyncio.sleep(0.2)
            yield f"event: stream_timeout\ndata: {json.dumps({'run_id': run_id})}\n\n"

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    return app


app = create_app()
