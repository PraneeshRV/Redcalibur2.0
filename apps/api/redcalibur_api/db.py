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
    WorkspaceCreate,
)


ROOT = Path(__file__).resolve().parents[3]
DEMO_WORKSPACE_ID = "demo-ai-coding-stack"
DEMO_SCOPE_ID = "demo-ai-coding-stack-scope"


def data_dir() -> Path:
    return Path(os.environ.get("REDCALIBUR_DATA_DIR", ROOT / "data"))


def db_path() -> Path:
    return data_dir() / "redcalibur.db"


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    data_dir().mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(data_dir(), 0o700)
    except PermissionError:
        pass
    conn = sqlite3.connect(db_path())
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
            INSERT OR IGNORE INTO scope_declarations (
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
                int(RiskTier.passive_read_only),
                "Demo-only local fixture workspace for RedCalibur planning and UI validation.",
                POLICY_VERSION,
            ),
        )


def initialize_database() -> None:
    seed_demo_workspace()
    try:
        os.chmod(db_path(), 0o600)
    except FileNotFoundError:
        pass
    except PermissionError:
        pass


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


def create_workspace(workspace: WorkspaceCreate) -> Workspace:
    with connect() as conn:
        try:
            conn.execute(
                """
                INSERT INTO workspaces (id, name, mode, purpose)
                VALUES (?, ?, ?, ?)
                """,
                (workspace.id, workspace.name, workspace.mode.value, workspace.purpose),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("Workspace already exists") from exc
    return Workspace(id=workspace.id, name=workspace.name, mode=workspace.mode, purpose=workspace.purpose)


def get_scope(workspace_id: str) -> ScopeDeclaration | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scope_declarations WHERE workspace_id = ?", (workspace_id,)).fetchone()
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
                int(scope.max_risk_tier),
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
                int(event.risk_tier),
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
