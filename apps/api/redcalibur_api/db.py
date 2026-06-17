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
    EvidenceItem,
    Job,
    JobStatus,
    Mode,
    PolicyDecision,
    RiskTier,
    Run,
    RunEvent,
    RunKind,
    RunStatus,
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


def artifacts_dir() -> Path:
    return data_dir() / "artifacts"


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    data_dir().mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(data_dir(), 0o700)
    except PermissionError:
        pass
    # A generous busy timeout keeps the worker thread and request threads from
    # tripping over each other on SQLite's single-writer lock.
    conn = sqlite3.connect(db_path(), timeout=30.0)
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

            CREATE TABLE IF NOT EXISTS runs (
              id TEXT PRIMARY KEY,
              workspace_id TEXT NOT NULL,
              kind TEXT NOT NULL,
              status TEXT NOT NULL,
              policy_snapshot_json TEXT NOT NULL,
              started_at TEXT NOT NULL,
              finished_at TEXT,
              FOREIGN KEY(workspace_id) REFERENCES workspaces(id)
            );

            CREATE TABLE IF NOT EXISTS jobs (
              id TEXT PRIMARY KEY,
              run_id TEXT NOT NULL,
              tool_id TEXT NOT NULL,
              status TEXT NOT NULL,
              input_json TEXT NOT NULL,
              output_summary_json TEXT,
              error TEXT,
              started_at TEXT NOT NULL,
              finished_at TEXT,
              FOREIGN KEY(run_id) REFERENCES runs(id)
            );

            CREATE TABLE IF NOT EXISTS evidence_items (
              id TEXT PRIMARY KEY,
              workspace_id TEXT NOT NULL,
              run_id TEXT NOT NULL,
              source_tool TEXT NOT NULL,
              evidence_type TEXT NOT NULL,
              title TEXT NOT NULL,
              summary TEXT NOT NULL,
              normalized_json TEXT NOT NULL,
              collected_at TEXT NOT NULL,
              FOREIGN KEY(workspace_id) REFERENCES workspaces(id),
              FOREIGN KEY(run_id) REFERENCES runs(id)
            );

            CREATE TABLE IF NOT EXISTS run_events (
              id TEXT PRIMARY KEY,
              run_id TEXT NOT NULL,
              seq INTEGER NOT NULL,
              event_type TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              UNIQUE(run_id, seq),
              FOREIGN KEY(run_id) REFERENCES runs(id)
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
            action=row["action"],
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


def new_id() -> str:
    return str(uuid.uuid4())


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def create_run(run: Run) -> Run:
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO runs (id, workspace_id, kind, status, policy_snapshot_json, started_at, finished_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (run.id, run.workspace_id, run.kind.value, run.status.value,
             json.dumps(run.policy_snapshot), run.started_at, run.finished_at),
        )
    return run


def update_run_status(run_id: str, status: RunStatus, finished_at: str | None = None) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE runs SET status = ?, finished_at = ? WHERE id = ?",
            (status.value, finished_at, run_id),
        )


def get_run(run_id: str) -> Run | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if row is None:
        return None
    return Run(
        id=row["id"],
        workspace_id=row["workspace_id"],
        kind=RunKind(row["kind"]),
        status=RunStatus(row["status"]),
        policy_snapshot=json.loads(row["policy_snapshot_json"]),
        started_at=row["started_at"],
        finished_at=row["finished_at"],
    )


def list_runs(workspace_id: str) -> list[Run]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM runs WHERE workspace_id = ? ORDER BY started_at DESC",
            (workspace_id,),
        ).fetchall()
    return [
        Run(
            id=row["id"],
            workspace_id=row["workspace_id"],
            kind=RunKind(row["kind"]),
            status=RunStatus(row["status"]),
            policy_snapshot=json.loads(row["policy_snapshot_json"]),
            started_at=row["started_at"],
            finished_at=row["finished_at"],
        )
        for row in rows
    ]


def create_job(job: Job) -> Job:
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO jobs (id, run_id, tool_id, status, input_json, output_summary_json, error, started_at, finished_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (job.id, job.run_id, job.tool_id, job.status.value,
             json.dumps(job.input),
             json.dumps(job.output_summary) if job.output_summary is not None else None,
             job.error, job.started_at, job.finished_at),
        )
    return job


def update_job(job: Job) -> None:
    with connect() as conn:
        conn.execute(
            """
            UPDATE jobs SET status = ?, output_summary_json = ?, error = ?, finished_at = ?
            WHERE id = ?
            """,
            (job.status.value,
             json.dumps(job.output_summary) if job.output_summary is not None else None,
             job.error, job.finished_at, job.id),
        )


def list_jobs(run_id: str) -> list[Job]:
    with connect() as conn:
        # Order by insertion (rowid): jobs in one run share a started_at, so
        # this keeps job order stable and deterministic across reads.
        rows = conn.execute(
            "SELECT * FROM jobs WHERE run_id = ? ORDER BY rowid",
            (run_id,),
        ).fetchall()
    return [
        Job(
            id=row["id"],
            run_id=row["run_id"],
            tool_id=row["tool_id"],
            status=JobStatus(row["status"]),
            input=json.loads(row["input_json"]),
            output_summary=json.loads(row["output_summary_json"]) if row["output_summary_json"] else None,
            error=row["error"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
        )
        for row in rows
    ]


def insert_evidence_item(item: EvidenceItem) -> EvidenceItem:
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO evidence_items
              (id, workspace_id, run_id, source_tool, evidence_type, title, summary, normalized_json, collected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (item.id, item.workspace_id, item.run_id, item.source_tool,
             item.evidence_type, item.title, item.summary,
             json.dumps(item.normalized), item.collected_at),
        )
    return item


def list_evidence_items(run_id: str) -> list[EvidenceItem]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM evidence_items WHERE run_id = ? ORDER BY collected_at",
            (run_id,),
        ).fetchall()
    return [
        EvidenceItem(
            id=row["id"],
            workspace_id=row["workspace_id"],
            run_id=row["run_id"],
            source_tool=row["source_tool"],
            evidence_type=row["evidence_type"],
            title=row["title"],
            summary=row["summary"],
            normalized=json.loads(row["normalized_json"]),
            collected_at=row["collected_at"],
        )
        for row in rows
    ]


def get_run_status(run_id: str) -> RunStatus | None:
    """Cheap status read used by the worker to honor cancellation requests."""
    with connect() as conn:
        row = conn.execute("SELECT status FROM runs WHERE id = ?", (run_id,)).fetchone()
    if row is None:
        return None
    return RunStatus(row["status"])


def append_run_event(run_id: str, event_type: str, payload: dict) -> RunEvent:
    """Append an ordered run event. The seq is monotonic per run.

    The seq is computed and inserted in a single atomic statement so that two
    concurrent writers (e.g. the worker thread and the cancel request thread)
    can never compute the same seq. A UNIQUE(run_id, seq) constraint backstops
    this; on the rare collision we retry.
    """
    event_id = new_id()
    created_at = utc_now()
    payload_json = json.dumps(payload)
    for _ in range(5):
        try:
            with connect() as conn:
                conn.execute(
                    """
                    INSERT INTO run_events (id, run_id, seq, event_type, payload_json, created_at)
                    SELECT ?, ?, COALESCE(MAX(seq), 0) + 1, ?, ?, ?
                    FROM run_events WHERE run_id = ?
                    """,
                    (event_id, run_id, event_type, payload_json, created_at, run_id),
                )
                row = conn.execute(
                    "SELECT seq FROM run_events WHERE id = ?", (event_id,)
                ).fetchone()
            return RunEvent(
                id=event_id,
                run_id=run_id,
                seq=int(row["seq"]),
                event_type=event_type,
                payload=payload,
                created_at=created_at,
            )
        except sqlite3.IntegrityError:
            continue
    raise RuntimeError(f"Could not append run event for run {run_id} after retries")


def list_run_events(run_id: str, after_seq: int = 0) -> list[RunEvent]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM run_events WHERE run_id = ? AND seq > ? ORDER BY seq",
            (run_id, after_seq),
        ).fetchall()
    return [
        RunEvent(
            id=row["id"],
            run_id=row["run_id"],
            seq=row["seq"],
            event_type=row["event_type"],
            payload=json.loads(row["payload_json"]),
            created_at=row["created_at"],
        )
        for row in rows
    ]


def write_run_artifact(run: Run, jobs: list[Job], evidence: list[EvidenceItem]) -> Path:
    """Persist a durable JSON snapshot of a finished run to data/artifacts/.

    Local-only file write — no network. The snapshot is the same shape the API
    returns so a run remains inspectable even outside the app.
    """
    target_dir = artifacts_dir()
    target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(target_dir, 0o700)
    except PermissionError:
        pass
    artifact_path = target_dir / f"{run.id}.json"
    snapshot = {
        "run": run.model_dump(mode="json"),
        "jobs": [job.model_dump(mode="json") for job in jobs],
        "evidence": [item.model_dump(mode="json") for item in evidence],
    }
    artifact_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    try:
        os.chmod(artifact_path, 0o600)
    except PermissionError:
        pass
    return artifact_path
