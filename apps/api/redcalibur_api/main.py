import hashlib

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from redcalibur_api import db
from redcalibur_api.models import AuditEvent, RunPreviewRequest, RunPreviewResponse, ScopeDeclaration
from redcalibur_api.policy import preview_policy


def create_app() -> FastAPI:
    app = FastAPI(title="RedCalibur 2.0 API", version="0.1.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_credentials=True,
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

        input_summary = f"{request.target_type.value}:{request.target}:risk-{int(request.risk_tier)}"
        redacted_hash = hashlib.sha256(input_summary.encode("utf-8")).hexdigest()
        db.insert_audit_event(
            AuditEvent(
                id=db.new_audit_event_id(),
                workspace_id=workspace_id,
                mode=workspace.mode,
                action="run_preview",
                target=request.target,
                risk_tier=request.risk_tier,
                decision=decision.decision,
                policy_version=decision.policy_version,
                input_summary=input_summary,
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

    return app


app = create_app()
