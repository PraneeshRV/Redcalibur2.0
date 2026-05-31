# Product Spine Preview Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first working RedCalibur 2.0 spine: local startup, workspace/scope model, deterministic policy preview, blocked-target UX, and audit persistence.

**Architecture:** Use a modular local app: Next.js in `apps/web`, FastAPI in `apps/api`, and SQLite in project-local `data/redcalibur.db`. The backend owns policy decisions and audit persistence; the frontend renders Command Center, Scope, and Run Preview surfaces from API responses.

**Tech Stack:** Next.js, TypeScript, FastAPI, Pydantic, SQLite, pytest, Playwright.

---

## File Map

Create these files:

- `.gitignore` - ignore local data, dependencies, caches, build outputs.
- `package.json` - root npm workspace scripts.
- `apps/api/pyproject.toml` - Python API dependencies and pytest config.
- `apps/api/redcalibur_api/__init__.py` - package marker.
- `apps/api/redcalibur_api/models.py` - domain enums and Pydantic schemas.
- `apps/api/redcalibur_api/db.py` - SQLite connection, schema, seed helper.
- `apps/api/redcalibur_api/policy.py` - deterministic policy engine.
- `apps/api/redcalibur_api/main.py` - FastAPI app and routes.
- `apps/api/tests/test_policy.py` - policy unit tests.
- `apps/api/tests/test_api.py` - API and audit tests.
- `apps/web/package.json` - web app dependencies and scripts.
- `apps/web/next.config.mjs` - Next.js config.
- `apps/web/tsconfig.json` - TypeScript config.
- `apps/web/app/globals.css` - operator-console styling.
- `apps/web/app/layout.tsx` - app shell metadata.
- `apps/web/app/page.tsx` - Command Center and Scope UI.
- `apps/web/tests/product-spine.spec.ts` - Playwright blocked-preview test.
- `fixtures/demo-ai-stack/package.json` - harmless demo fixture manifest.
- `fixtures/demo-ai-stack/mcp.json` - harmless demo fixture MCP config.

Modify these files:

- `PROJECT.md` - add implementation status after the slice is complete.
- `docs/planning/product-spine-preview-plan.md` - mark executed status after the slice is complete.

Do not create scanner adapters, AI providers, OSV/CVE integrations, report generators, or network target checkers in this plan.

## Task 1: Root Project Skeleton

**Files:**
- Create: `.gitignore`
- Create: `package.json`
- Create: `fixtures/demo-ai-stack/package.json`
- Create: `fixtures/demo-ai-stack/mcp.json`

- [ ] **Step 1: Create root ignore rules**

Add `.gitignore`:

```gitignore
node_modules/
.next/
dist/
build/
.turbo/
.pytest_cache/
__pycache__/
*.pyc
.venv/
venv/
data/
coverage/
playwright-report/
test-results/
.env
.env.local
```

- [ ] **Step 2: Create root workspace scripts**

Add `package.json`:

```json
{
  "name": "redcalibur-2",
  "private": true,
  "workspaces": [
    "apps/web"
  ],
  "scripts": {
    "dev": "concurrently -n api,web -c red,cyan \"npm run dev:api\" \"npm run dev:web\"",
    "dev:api": "cd apps/api && .venv/bin/python -m uvicorn redcalibur_api.main:app --reload --port 8000",
    "dev:web": "npm --workspace apps/web run dev",
    "test:api": "cd apps/api && .venv/bin/python -m pytest -q",
    "test:web": "npm --workspace apps/web run test",
    "test": "npm run test:api && npm run test:web"
  },
  "devDependencies": {
    "concurrently": "^9.1.2"
  }
}
```

- [ ] **Step 3: Initialize git if needed**

Run:

```bash
git status --short || git init
```

Expected: either existing git status output or `Initialized empty Git repository`.

- [ ] **Step 4: Add harmless demo fixtures**

Add `fixtures/demo-ai-stack/package.json`:

```json
{
  "name": "redcalibur-demo-ai-stack",
  "version": "0.1.0",
  "private": true,
  "dependencies": {
    "demo-vulnerable-package": "1.0.0"
  }
}
```

Add `fixtures/demo-ai-stack/mcp.json`:

```json
{
  "servers": {
    "demo-filesystem": {
      "command": "node",
      "args": ["./safe-demo-server.js"],
      "env": {
        "DEMO_TOKEN": "redacted-demo-token"
      }
    }
  }
}
```

- [ ] **Step 5: Verify skeleton files exist**

Run:

```bash
test -f package.json && test -f fixtures/demo-ai-stack/package.json && test -f fixtures/demo-ai-stack/mcp.json
```

Expected: exit code `0`.

- [ ] **Step 6: Commit**

```bash
git add .gitignore package.json fixtures/demo-ai-stack/package.json fixtures/demo-ai-stack/mcp.json
git commit -m "chore: add RedCalibur project skeleton"
```

## Task 2: API Domain Models

**Files:**
- Create: `apps/api/pyproject.toml`
- Create: `apps/api/redcalibur_api/__init__.py`
- Create: `apps/api/redcalibur_api/models.py`
- Test: `apps/api/tests/test_policy.py`

- [ ] **Step 1: Add API package config**

Create `apps/api/pyproject.toml`:

```toml
[project]
name = "redcalibur-api"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
  "fastapi>=0.116.0",
  "uvicorn[standard]>=0.35.0",
  "pydantic>=2.11.0"
]

[project.optional-dependencies]
test = [
  "httpx>=0.28.0",
  "pytest>=8.3.0"
]

[tool.pytest.ini_options]
pythonpath = ["."]
testpaths = ["tests"]
```

- [ ] **Step 2: Add package marker**

Create `apps/api/redcalibur_api/__init__.py`:

```python
"""RedCalibur 2.0 API package."""
```

- [ ] **Step 3: Add domain models**

Create `apps/api/redcalibur_api/models.py`:

```python
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


POLICY_VERSION = "2026-05-30.product-spine-preview"


class Mode(str, Enum):
    demo = "demo"
    learning = "learning"
    authorized_assessment = "authorized_assessment"


class RiskTier(int, Enum):
    offline_demo = 0
    passive_read_only = 1
    low_impact_active = 2
    intrusive_active = 3
    prohibited = 4


class TargetType(str, Enum):
    local_path = "local_path"
    url = "url"
    domain = "domain"
    ip = "ip"


class PolicyDecision(str, Enum):
    allowed = "allowed"
    blocked = "blocked"
    requires_approval = "requires_approval"
    demo_only = "demo_only"


class Workspace(BaseModel):
    id: str
    name: str
    mode: Mode
    purpose: str


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
    target: str
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
```

- [ ] **Step 4: Create API virtualenv and install test dependencies**

Run:

```bash
cd apps/api && python3 -m venv .venv && .venv/bin/python -m pip install -e '.[test]'
```

Expected: editable install succeeds and `pytest` is available inside `apps/api/.venv`.

- [ ] **Step 5: Add first failing model import test**

Create `apps/api/tests/test_policy.py` with a temporary model test:

```python
from redcalibur_api.models import Mode, PolicyDecision, RiskTier


def test_domain_enums_have_expected_values():
    assert Mode.demo.value == "demo"
    assert RiskTier.passive_read_only.value == 1
    assert PolicyDecision.blocked.value == "blocked"
```

- [ ] **Step 6: Run test**

Run:

```bash
cd apps/api && .venv/bin/python -m pytest tests/test_policy.py -q
```

Expected: `1 passed`.

- [ ] **Step 7: Commit**

```bash
git add apps/api/pyproject.toml apps/api/redcalibur_api/__init__.py apps/api/redcalibur_api/models.py apps/api/tests/test_policy.py
git commit -m "feat: define RedCalibur API domain models"
```

## Task 3: SQLite Persistence And Seed Data

**Files:**
- Create: `apps/api/redcalibur_api/db.py`
- Modify: `apps/api/tests/test_api.py`

- [ ] **Step 1: Add SQLite schema and repository helpers**

Create `apps/api/redcalibur_api/db.py`:

```python
import json
import os
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from redcalibur_api.models import (
    POLICY_VERSION,
    AuditEvent,
    Mode,
    PolicyDecision,
    RiskTier,
    ScopeDeclaration,
    Workspace,
)


ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = Path(os.environ.get("REDCALIBUR_DATA_DIR", ROOT / "data"))
DB_PATH = DATA_DIR / "redcalibur.db"
DEMO_WORKSPACE_ID = "demo-ai-coding-stack"
DEMO_SCOPE_ID = "demo-ai-coding-stack-scope"


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def migrate() -> None:
    with connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS workspaces (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              mode TEXT NOT NULL,
              purpose TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scope_declarations (
              id TEXT PRIMARY KEY,
              workspace_id TEXT NOT NULL,
              mode TEXT NOT NULL,
              allowed_roots_json TEXT NOT NULL,
              excluded_roots_json TEXT NOT NULL,
              allowed_targets_json TEXT NOT NULL,
              max_risk_tier INTEGER NOT NULL,
              authorization_text TEXT NOT NULL,
              policy_version TEXT NOT NULL,
              FOREIGN KEY(workspace_id) REFERENCES workspaces(id)
            );

            CREATE TABLE IF NOT EXISTS audit_events (
              id TEXT PRIMARY KEY,
              workspace_id TEXT NOT NULL,
              mode TEXT NOT NULL,
              action TEXT NOT NULL,
              target TEXT NOT NULL,
              risk_tier INTEGER NOT NULL,
              decision TEXT NOT NULL,
              policy_version TEXT NOT NULL,
              input_summary TEXT NOT NULL,
              redacted_input_hash TEXT NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(workspace_id) REFERENCES workspaces(id)
            );
            """
        )


def seed_demo_workspace() -> None:
    migrate()
    with connect() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO workspaces (id, name, mode, purpose)
            VALUES (?, ?, ?, ?)
            """,
            (
                DEMO_WORKSPACE_ID,
                "RedCalibur Demo - AI Coding Stack",
                Mode.demo.value,
                "Demo-only local fixture workspace for RedCalibur planning and UI validation.",
            ),
        )
        conn.execute(
            """
            INSERT OR REPLACE INTO scope_declarations (
              id, workspace_id, mode, allowed_roots_json, excluded_roots_json,
              allowed_targets_json, max_risk_tier, authorization_text, policy_version
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                DEMO_SCOPE_ID,
                DEMO_WORKSPACE_ID,
                Mode.demo.value,
                json.dumps(["fixtures/demo-ai-stack"]),
                json.dumps(["fixtures/demo-ai-stack/secrets"]),
                json.dumps([]),
                RiskTier.passive_read_only.value,
                "Demo-only local fixture workspace for RedCalibur planning and UI validation.",
                POLICY_VERSION,
            ),
        )


def list_workspaces() -> list[Workspace]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM workspaces ORDER BY name").fetchall()
    return [Workspace(id=row["id"], name=row["name"], mode=row["mode"], purpose=row["purpose"]) for row in rows]


def get_workspace(workspace_id: str) -> Workspace | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM workspaces WHERE id = ?", (workspace_id,)).fetchone()
    if row is None:
        return None
    return Workspace(id=row["id"], name=row["name"], mode=row["mode"], purpose=row["purpose"])


def get_scope(workspace_id: str) -> ScopeDeclaration | None:
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM scope_declarations WHERE workspace_id = ?",
            (workspace_id,),
        ).fetchone()
    if row is None:
        return None
    return ScopeDeclaration(
        id=row["id"],
        workspace_id=row["workspace_id"],
        mode=row["mode"],
        allowed_roots=json.loads(row["allowed_roots_json"]),
        excluded_roots=json.loads(row["excluded_roots_json"]),
        allowed_targets=json.loads(row["allowed_targets_json"]),
        max_risk_tier=row["max_risk_tier"],
        authorization_text=row["authorization_text"],
        policy_version=row["policy_version"],
    )


def save_scope(scope: ScopeDeclaration) -> ScopeDeclaration:
    with connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO scope_declarations (
              id, workspace_id, mode, allowed_roots_json, excluded_roots_json,
              allowed_targets_json, max_risk_tier, authorization_text, policy_version
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scope.id,
                scope.workspace_id,
                scope.mode.value,
                json.dumps(scope.allowed_roots),
                json.dumps(scope.excluded_roots),
                json.dumps(scope.allowed_targets),
                int(scope.max_risk_tier.value),
                scope.authorization_text,
                scope.policy_version,
            ),
        )
    return scope


def insert_audit_event(event: AuditEvent) -> AuditEvent:
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO audit_events (
              id, workspace_id, mode, action, target, risk_tier, decision,
              policy_version, input_summary, redacted_input_hash, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.id,
                event.workspace_id,
                event.mode.value,
                event.action,
                event.target,
                int(event.risk_tier.value),
                event.decision.value,
                event.policy_version,
                event.input_summary,
                event.redacted_input_hash,
                event.created_at,
            ),
        )
    return event


def list_audit_events(workspace_id: str) -> list[AuditEvent]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_events WHERE workspace_id = ? ORDER BY created_at DESC",
            (workspace_id,),
        ).fetchall()
    return [
        AuditEvent(
            id=row["id"],
            workspace_id=row["workspace_id"],
            mode=row["mode"],
            action="run_preview",
            target=row["target"],
            risk_tier=row["risk_tier"],
            decision=PolicyDecision(row["decision"]),
            policy_version=row["policy_version"],
            input_summary=row["input_summary"],
            redacted_input_hash=row["redacted_input_hash"],
            created_at=row["created_at"],
        )
        for row in rows
    ]


def new_audit_event_id() -> str:
    return str(uuid.uuid4())


def utc_now() -> str:
    return datetime.now(UTC).isoformat()
```

- [ ] **Step 2: Add migration and seed tests**

Create `apps/api/tests/test_api.py`:

```python
import importlib


def test_migration_and_seed_are_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    import redcalibur_api.db as db

    db = importlib.reload(db)
    db.seed_demo_workspace()
    db.seed_demo_workspace()

    workspaces = db.list_workspaces()
    assert len(workspaces) == 1
    assert workspaces[0].id == "demo-ai-coding-stack"

    scope = db.get_scope("demo-ai-coding-stack")
    assert scope is not None
    assert scope.allowed_roots == ["fixtures/demo-ai-stack"]
```

- [ ] **Step 3: Run persistence tests**

Run:

```bash
cd apps/api && .venv/bin/python -m pytest tests/test_api.py -q
```

Expected: `1 passed`.

- [ ] **Step 4: Commit**

```bash
git add apps/api/redcalibur_api/db.py apps/api/tests/test_api.py
git commit -m "feat: add SQLite persistence and demo seed"
```

## Task 4: Deterministic Policy Engine

**Files:**
- Create: `apps/api/redcalibur_api/policy.py`
- Modify: `apps/api/tests/test_policy.py`

- [ ] **Step 1: Replace policy tests with behavior coverage**

Replace `apps/api/tests/test_policy.py`:

```python
from redcalibur_api.models import Mode, PolicyDecision, RiskTier, ScopeDeclaration, TargetType
from redcalibur_api.policy import preview_policy


def demo_scope() -> ScopeDeclaration:
    return ScopeDeclaration(
        id="scope-1",
        workspace_id="workspace-1",
        mode=Mode.demo,
        allowed_roots=["fixtures/demo-ai-stack"],
        excluded_roots=["fixtures/demo-ai-stack/secrets"],
        allowed_targets=[],
        max_risk_tier=RiskTier.passive_read_only,
        authorization_text="Demo fixture scope.",
    )


def test_allowed_local_fixture():
    response = preview_policy(demo_scope(), "fixtures/demo-ai-stack/package.json", TargetType.local_path, RiskTier.passive_read_only)
    assert response.decision == PolicyDecision.allowed


def test_excluded_local_path_is_blocked():
    response = preview_policy(demo_scope(), "fixtures/demo-ai-stack/secrets/.env", TargetType.local_path, RiskTier.passive_read_only)
    assert response.decision == PolicyDecision.blocked
    assert "excluded" in " ".join(response.reasons)


def test_external_url_in_demo_mode_is_blocked():
    response = preview_policy(demo_scope(), "https://example.com", TargetType.url, RiskTier.passive_read_only)
    assert response.decision == PolicyDecision.blocked
    assert "Demo mode" in " ".join(response.reasons)


def test_private_ip_is_blocked():
    response = preview_policy(demo_scope(), "127.0.0.1", TargetType.ip, RiskTier.passive_read_only)
    assert response.decision == PolicyDecision.blocked
    assert "private" in " ".join(response.reasons)


def test_excessive_risk_tier_is_blocked():
    response = preview_policy(demo_scope(), "fixtures/demo-ai-stack/package.json", TargetType.local_path, RiskTier.low_impact_active)
    assert response.decision == PolicyDecision.blocked
    assert "risk tier" in " ".join(response.reasons)
```

- [ ] **Step 2: Run tests and verify failure**

Run:

```bash
cd apps/api && .venv/bin/python -m pytest tests/test_policy.py -q
```

Expected: failure with `ModuleNotFoundError: No module named 'redcalibur_api.policy'`.

- [ ] **Step 3: Add policy engine**

Create `apps/api/redcalibur_api/policy.py`:

```python
import ipaddress
from pathlib import PurePosixPath
from urllib.parse import urlparse

from redcalibur_api.models import (
    POLICY_VERSION,
    PolicyDecision,
    RiskTier,
    RunPreviewResponse,
    ScopeDeclaration,
    TargetType,
)


def _normalize_local_path(value: str) -> str:
    path = PurePosixPath(value.replace("\\", "/"))
    parts = [part for part in path.parts if part not in ("", ".")]
    if ".." in parts:
        return ""
    return "/".join(parts)


def _is_within(path: str, root: str) -> bool:
    normalized_path = _normalize_local_path(path)
    normalized_root = _normalize_local_path(root)
    return normalized_path == normalized_root or normalized_path.startswith(f"{normalized_root}/")


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

    if risk_tier.value > scope.max_risk_tier.value:
        reasons.append(f"Requested risk tier {risk_tier.value} exceeds workspace max risk tier {scope.max_risk_tier.value}.")

    if target_type in {TargetType.url, TargetType.domain} and scope.mode.value == "demo":
        reasons.append("Demo mode blocks arbitrary network targets.")

    if target_type == TargetType.url:
        parsed = urlparse(normalized_target)
        host = parsed.hostname or ""
        if host and _is_private_ip(host):
            reasons.append("Target resolves to a private, loopback, link-local, or reserved IP.")

    if target_type == TargetType.ip and _is_private_ip(normalized_target):
        reasons.append("Target is a private, loopback, link-local, or reserved IP.")

    if target_type == TargetType.local_path:
        normalized_target = _normalize_local_path(normalized_target)
        if not normalized_target:
            reasons.append("Local path is invalid or attempts to traverse outside scope.")
        if any(_is_within(normalized_target, excluded) for excluded in scope.excluded_roots):
            reasons.append("Local path is inside an excluded scope root.")
        elif not any(_is_within(normalized_target, allowed) for allowed in scope.allowed_roots):
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
```

- [ ] **Step 4: Run policy tests**

Run:

```bash
cd apps/api && .venv/bin/python -m pytest tests/test_policy.py -q
```

Expected: `5 passed`.

- [ ] **Step 5: Commit**

```bash
git add apps/api/redcalibur_api/policy.py apps/api/tests/test_policy.py
git commit -m "feat: add Product Spine policy preview"
```

## Task 5: FastAPI Routes And Audit Events

**Files:**
- Create: `apps/api/redcalibur_api/main.py`
- Modify: `apps/api/tests/test_api.py`

- [ ] **Step 1: Add API route tests**

Append to `apps/api/tests/test_api.py`:

```python

def test_health_and_workspace_routes(tmp_path, monkeypatch):
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    import redcalibur_api.db as db
    import redcalibur_api.main as main

    importlib.reload(db)
    main = importlib.reload(main)

    from fastapi.testclient import TestClient

    client = TestClient(main.app)
    assert client.get("/health").json() == {"status": "ok"}

    workspaces = client.get("/workspaces").json()
    assert workspaces[0]["id"] == "demo-ai-coding-stack"


def test_run_preview_writes_audit_event(tmp_path, monkeypatch):
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    import redcalibur_api.db as db
    import redcalibur_api.main as main

    importlib.reload(db)
    main = importlib.reload(main)

    from fastapi.testclient import TestClient

    client = TestClient(main.app)
    response = client.post(
        "/workspaces/demo-ai-coding-stack/run-preview",
        json={"target": "https://example.com", "target_type": "url", "risk_tier": 1},
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "blocked"

    events = client.get("/workspaces/demo-ai-coding-stack/audit-events").json()
    assert len(events) == 1
    assert events[0]["decision"] == "blocked"
    assert events[0]["target"] == "https://example.com"
```

- [ ] **Step 2: Run API tests and verify failure**

Run:

```bash
cd apps/api && .venv/bin/python -m pytest tests/test_api.py -q
```

Expected: failure with `ModuleNotFoundError: No module named 'redcalibur_api.main'`.

- [ ] **Step 3: Add FastAPI app**

Create `apps/api/redcalibur_api/main.py`:

```python
import hashlib

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from redcalibur_api import db
from redcalibur_api.models import AuditEvent, RunPreviewRequest, RunPreviewResponse, ScopeDeclaration
from redcalibur_api.policy import preview_policy


app = FastAPI(title="RedCalibur 2.0 API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    db.seed_demo_workspace()


@app.get("/health")
def health() -> dict[str, str]:
    db.migrate()
    return {"status": "ok"}


@app.get("/workspaces")
def workspaces():
    db.seed_demo_workspace()
    return db.list_workspaces()


@app.get("/workspaces/{workspace_id}")
def workspace(workspace_id: str):
    db.seed_demo_workspace()
    found = db.get_workspace(workspace_id)
    if found is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return found


@app.get("/workspaces/{workspace_id}/scope")
def get_scope(workspace_id: str):
    db.seed_demo_workspace()
    scope = db.get_scope(workspace_id)
    if scope is None:
        raise HTTPException(status_code=404, detail="Scope declaration not found")
    return scope


@app.put("/workspaces/{workspace_id}/scope")
def put_scope(workspace_id: str, scope: ScopeDeclaration):
    db.seed_demo_workspace()
    if workspace_id != scope.workspace_id:
        raise HTTPException(status_code=400, detail="Scope workspace_id must match path")
    if db.get_workspace(workspace_id) is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return db.save_scope(scope)


@app.post("/workspaces/{workspace_id}/run-preview", response_model=RunPreviewResponse)
def run_preview(workspace_id: str, request: RunPreviewRequest):
    db.seed_demo_workspace()
    workspace = db.get_workspace(workspace_id)
    if workspace is None:
        raise HTTPException(status_code=404, detail="Workspace not found")

    scope = db.get_scope(workspace_id)
    decision = preview_policy(scope, request.target, request.target_type, request.risk_tier)

    input_summary = f"{request.target_type.value}:{request.target}:risk-{request.risk_tier.value}"
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
def audit_events(workspace_id: str):
    db.seed_demo_workspace()
    if db.get_workspace(workspace_id) is None:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return db.list_audit_events(workspace_id)
```

- [ ] **Step 4: Run API tests**

Run:

```bash
cd apps/api && .venv/bin/python -m pytest tests/test_api.py tests/test_policy.py -q
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add apps/api/redcalibur_api/main.py apps/api/tests/test_api.py
git commit -m "feat: expose workspace scope and run preview APIs"
```

## Task 6: Next.js Operator Console

**Files:**
- Create: `apps/web/package.json`
- Create: `apps/web/next.config.mjs`
- Create: `apps/web/tsconfig.json`
- Create: `apps/web/app/layout.tsx`
- Create: `apps/web/app/globals.css`
- Create: `apps/web/app/page.tsx`

- [ ] **Step 1: Add web package config**

Create `apps/web/package.json`:

```json
{
  "name": "@redcalibur/web",
  "private": true,
  "scripts": {
    "dev": "next dev --port 3000",
    "build": "next build",
    "test": "playwright test"
  },
  "dependencies": {
    "next": "^15.3.0",
    "react": "^19.1.0",
    "react-dom": "^19.1.0",
    "lucide-react": "^0.511.0"
  },
  "devDependencies": {
    "@playwright/test": "^1.52.0",
    "@types/node": "^22.15.0",
    "@types/react": "^19.1.0",
    "@types/react-dom": "^19.1.0",
    "typescript": "^5.8.0"
  }
}
```

- [ ] **Step 2: Add Next.js config**

Create `apps/web/next.config.mjs`:

```javascript
const nextConfig = {};

export default nextConfig;
```

- [ ] **Step 3: Add TypeScript config**

Create `apps/web/tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["dom", "dom.iterable", "es2022"],
    "allowJs": false,
    "skipLibCheck": true,
    "strict": true,
    "noEmit": true,
    "esModuleInterop": true,
    "module": "esnext",
    "moduleResolution": "bundler",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "jsx": "preserve",
    "incremental": true,
    "plugins": [{ "name": "next" }]
  },
  "include": ["next-env.d.ts", "**/*.ts", "**/*.tsx", ".next/types/**/*.ts"],
  "exclude": ["node_modules"]
}
```

- [ ] **Step 4: Add app shell**

Create `apps/web/app/layout.tsx`:

```tsx
import "./globals.css";

export const metadata = {
  title: "RedCalibur 2.0",
  description: "AI security and developer exposure workbench",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
```

- [ ] **Step 5: Add operator-console styles**

Create `apps/web/app/globals.css` with compact console styling:

```css
:root {
  color-scheme: dark;
  --bg: #0d1117;
  --panel: #151b23;
  --panel-2: #1f2630;
  --text: #eef2f6;
  --muted: #91a1b5;
  --border: #303a46;
  --red: #ef4444;
  --green: #22c55e;
  --blue: #38bdf8;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

button,
input,
select,
textarea {
  font: inherit;
}

.shell {
  min-height: 100vh;
  display: grid;
  grid-template-columns: 240px 1fr;
}

.nav {
  border-right: 1px solid var(--border);
  background: #0a0e14;
  padding: 20px;
}

.brand {
  font-size: 18px;
  font-weight: 700;
  margin-bottom: 24px;
}

.nav-item {
  display: block;
  color: var(--muted);
  padding: 10px 0;
}

.main {
  padding: 24px;
}

.grid {
  display: grid;
  grid-template-columns: 1.1fr 0.9fr;
  gap: 16px;
}

.panel {
  border: 1px solid var(--border);
  background: var(--panel);
  border-radius: 8px;
  padding: 16px;
}

.panel h2,
.panel h3 {
  margin: 0 0 12px;
}

.meta {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
}

.chip {
  display: inline-flex;
  align-items: center;
  min-height: 28px;
  padding: 4px 9px;
  border-radius: 999px;
  background: var(--panel-2);
  border: 1px solid var(--border);
  color: var(--text);
  font-size: 12px;
}

.allowed {
  color: var(--green);
}

.blocked {
  color: var(--red);
}

.form {
  display: grid;
  gap: 10px;
}

.field {
  display: grid;
  gap: 6px;
}

.field label {
  color: var(--muted);
  font-size: 12px;
}

.field input,
.field select,
.field textarea {
  width: 100%;
  color: var(--text);
  background: #0b1018;
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 9px 10px;
}

.button {
  border: 0;
  border-radius: 6px;
  background: var(--blue);
  color: #041018;
  padding: 10px 12px;
  font-weight: 700;
  cursor: pointer;
}

.event {
  border-top: 1px solid var(--border);
  padding: 10px 0;
  color: var(--muted);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
}
```

- [ ] **Step 6: Add Command Center UI**

Create `apps/web/app/page.tsx`:

```tsx
"use client";

import { ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000";

type Workspace = {
  id: string;
  name: string;
  mode: string;
  purpose: string;
};

type Scope = {
  allowed_roots: string[];
  excluded_roots: string[];
  max_risk_tier: number;
  authorization_text: string;
  policy_version: string;
};

type AuditEvent = {
  id: string;
  target: string;
  risk_tier: number;
  decision: string;
  created_at: string;
};

type Preview = {
  decision: string;
  reasons: string[];
  policy_version: string;
  normalized_target: string;
};

export default function Home() {
  const [workspace, setWorkspace] = useState<Workspace | null>(null);
  const [scope, setScope] = useState<Scope | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [target, setTarget] = useState("https://example.com");
  const [targetType, setTargetType] = useState("url");
  const [riskTier, setRiskTier] = useState(1);
  const [preview, setPreview] = useState<Preview | null>(null);

  async function refresh() {
    const workspaces = (await fetch(`${API_BASE}/workspaces`).then((res) => res.json())) as Workspace[];
    const active = workspaces[0];
    setWorkspace(active);
    setScope(await fetch(`${API_BASE}/workspaces/${active.id}/scope`).then((res) => res.json()));
    setEvents(await fetch(`${API_BASE}/workspaces/${active.id}/audit-events`).then((res) => res.json()));
  }

  useEffect(() => {
    refresh();
  }, []);

  async function runPreview() {
    if (!workspace) return;
    const response = await fetch(`${API_BASE}/workspaces/${workspace.id}/run-preview`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, target_type: targetType, risk_tier: riskTier }),
    });
    setPreview(await response.json());
    await refresh();
  }

  return (
    <div className="shell">
      <aside className="nav">
        <div className="brand">RedCalibur 2.0</div>
        <span className="nav-item">Command Center</span>
        <span className="nav-item">Scopes</span>
        <span className="nav-item">Run Preview</span>
        <span className="nav-item">Audit</span>
      </aside>
      <main className="main">
        <h1>Command Center</h1>
        <div className="grid">
          <section className="panel">
            <h2><ShieldCheck size={18} /> Workspace</h2>
            <div className="meta">
              <span className="chip">{workspace?.name ?? "Loading"}</span>
              <span className="chip">Mode: {workspace?.mode ?? "loading"}</span>
              <span className="chip">Max risk: {scope?.max_risk_tier ?? "-"}</span>
              <span className="chip">Policy: {scope?.policy_version ?? "-"}</span>
            </div>
            <h3>Scope</h3>
            <p>Allowed roots: {scope?.allowed_roots.join(", ")}</p>
            <p>Excluded roots: {scope?.excluded_roots.join(", ")}</p>
            <p>{scope?.authorization_text}</p>
          </section>

          <section className="panel">
            <h2>Run Preview</h2>
            <div className="form">
              <div className="field">
                <label>Target</label>
                <input value={target} onChange={(event) => setTarget(event.target.value)} />
              </div>
              <div className="field">
                <label>Target type</label>
                <select value={targetType} onChange={(event) => setTargetType(event.target.value)}>
                  <option value="local_path">Local path</option>
                  <option value="url">URL</option>
                  <option value="domain">Domain</option>
                  <option value="ip">IP</option>
                </select>
              </div>
              <div className="field">
                <label>Risk tier</label>
                <select value={riskTier} onChange={(event) => setRiskTier(Number(event.target.value))}>
                  <option value={0}>0 - Offline/demo</option>
                  <option value={1}>1 - Passive read-only</option>
                  <option value={2}>2 - Low-impact active</option>
                  <option value={3}>3 - Intrusive active</option>
                  <option value={4}>4 - Prohibited</option>
                </select>
              </div>
              <button className="button" type="button" onClick={runPreview}>Preview Decision</button>
            </div>
            {preview ? (
              <div>
                <h3 className={preview.decision === "allowed" ? "allowed" : "blocked"}>{preview.decision}</h3>
                <ul>
                  {preview.reasons.map((reason) => <li key={reason}>{reason}</li>)}
                </ul>
              </div>
            ) : null}
          </section>
        </div>

        <section className="panel" style={{ marginTop: 16 }}>
          <h2>Audit Events</h2>
          {events.map((event) => (
            <div className="event" key={event.id}>
              {event.created_at} | {event.decision} | risk {event.risk_tier} | {event.target}
            </div>
          ))}
        </section>
      </main>
    </div>
  );
}
```

- [ ] **Step 7: Build the web app**

Run first:

```bash
npm install
```

Expected: root and web dependencies install successfully.

Run:

```bash
npm --workspace apps/web run build
```

Expected: Next.js build exits with code `0`.

- [ ] **Step 8: Commit**

```bash
git add apps/web/package.json apps/web/next.config.mjs apps/web/tsconfig.json apps/web/app/layout.tsx apps/web/app/globals.css apps/web/app/page.tsx
git commit -m "feat: add Product Spine operator console"
```

## Task 7: Browser Smoke Test

**Files:**
- Create: `apps/web/playwright.config.ts`
- Create: `apps/web/tests/product-spine.spec.ts`

- [ ] **Step 1: Add Playwright config**

Create `apps/web/playwright.config.ts`:

```ts
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  use: {
    baseURL: "http://localhost:3000",
  },
});
```

- [ ] **Step 2: Add product-spine test**

Create `apps/web/tests/product-spine.spec.ts`:

```ts
import { expect, test } from "@playwright/test";

test("shows demo workspace and blocks external URL in Demo mode", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText("RedCalibur Demo - AI Coding Stack")).toBeVisible();
  await expect(page.getByText("Mode: demo")).toBeVisible();
  await page.getByRole("button", { name: "Preview Decision" }).click();
  await expect(page.getByText("blocked")).toBeVisible();
  await expect(page.getByText("Demo mode blocks arbitrary network targets.")).toBeVisible();
});
```

- [ ] **Step 3: Run full app smoke test**

Run in one terminal:

```bash
npm run dev
```

Expected:

```txt
api | Uvicorn running on http://127.0.0.1:8000
web | Local: http://localhost:3000
```

Run in another terminal:

```bash
npm --workspace apps/web run test
```

Expected: Playwright test passes.

- [ ] **Step 4: Commit**

```bash
git add apps/web/playwright.config.ts apps/web/tests/product-spine.spec.ts
git commit -m "test: cover Product Spine blocked preview"
```

## Task 8: Final Verification And Stop-Line Check

**Files:**
- Modify: `PROJECT.md`
- Modify: `docs/planning/product-spine-preview-plan.md`

- [ ] **Step 1: Run backend tests**

Run:

```bash
npm run test:api
```

Expected: all pytest tests pass.

- [ ] **Step 2: Run frontend build**

Run:

```bash
npm --workspace apps/web run build
```

Expected: Next.js build exits with code `0`.

- [ ] **Step 3: Run stop-line search**

Run:

```bash
rg -n "osv|cve|kev|epss|anthropic|openai|scanner|report export|subprocess|requests\\.get|fetch\\(" apps/api apps/web
```

Expected:

- no API scanner, live AI provider, report export, or network target check implementation
- frontend `fetch(` calls only call the local RedCalibur API

- [ ] **Step 4: Update planning status**

Append to `PROJECT.md`:

```markdown

## Product Spine Preview Status

Implemented after approval:

- local app startup
- workspace and scope model
- deterministic policy preview
- blocked external target in Demo mode
- audit persistence
- minimal Command Center and Scopes UI

Stop line preserved:

- no scanner execution
- no live AI provider calls
- no report export
- no open-data integrations
- no network target checks
```

Append to `docs/planning/product-spine-preview-plan.md`:

```markdown

## Execution Result

Status: Complete after verification.

Verification:

- API tests passed.
- Web build passed.
- Playwright blocked-preview smoke test passed.
- Stop-line search confirmed no scanner, live AI, report, open-data, or network-target execution path.
```

- [ ] **Step 5: Commit**

```bash
git add PROJECT.md docs/planning/product-spine-preview-plan.md
git commit -m "docs: record Product Spine Preview completion"
```

## Self-Review Checklist

- Spec coverage: Product Spine Preview requirements are covered by Tasks 1-8.
- Stop line: scanners, live AI, reports, open data, and network checks are explicitly excluded.
- Safety: blocked external Demo-mode preview and audit persistence are tested.
- Type consistency: modes, risk tiers, target types, and decisions come from backend models.
- Missing requirements: none known before implementation begins.

## Execution Choice

Plan complete and saved to `docs/superpowers/plans/2026-05-30-product-spine-preview.md`.

Two execution options:

1. Subagent-Driven (recommended) - dispatch a fresh subagent per task, review between tasks, fast iteration.
2. Inline Execution - execute tasks in this session using executing-plans, batch execution with checkpoints.
