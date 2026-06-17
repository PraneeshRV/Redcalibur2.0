"""Run orchestration worker.

A single background thread drains a queue of run ids and executes each run's
jobs sequentially. Execution stays inside the existing safety envelope:

- every job passes the deterministic policy gate (tool risk tier vs declared
  scope max) before its adapter runs;
- each adapter runs in a worker thread with a hard wall-clock timeout;
- adapter faults and timeouts are captured as failed jobs, never as a crash;
- cooperative cancellation is checked before each job;
- ordered run events are appended so the API can stream live progress;
- a durable JSON artifact is written when the run reaches a terminal state.

The orchestrator owns no database connections of its own — it calls the same
``db`` helpers the request handlers use, so there is exactly one persistence
path.
"""

from __future__ import annotations

import hashlib
import queue
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from pathlib import Path

from redcalibur_api import db
from redcalibur_api.models import (
    AuditEvent,
    EvidenceItem,
    Job,
    JobStatus,
    PolicyDecision,
    RunKind,
    RunStatus,
)
from redcalibur_api.tools.registry import ToolInput, get as get_tool

ADAPTER_TIMEOUT_SECONDS = 30

# A run kind expands to an ordered list of tool ids. Single-tool kinds keep the
# original one-job behavior; ``baseline`` fans out across the full developer
# surface as several jobs under one run.
_KIND_TO_TOOLS: dict[RunKind, list[str]] = {
    RunKind.manifest_scan: ["redcalibur.developer_surface.manifest_scan"],
    RunKind.mcp_config_scan: ["redcalibur.developer_surface.mcp_config_scan"],
    RunKind.ai_config_scan: ["redcalibur.developer_surface.ai_config_scan"],
    RunKind.secrets_baseline: ["redcalibur.developer_surface.secrets_baseline"],
    RunKind.vuln_scan: ["redcalibur.vuln_intel.vuln_scan"],
    RunKind.ai_eval: ["redcalibur.ai_lab.ai_eval"],
    RunKind.baseline: [
        "redcalibur.developer_surface.manifest_scan",
        "redcalibur.developer_surface.mcp_config_scan",
        "redcalibur.developer_surface.ai_config_scan",
        "redcalibur.developer_surface.secrets_baseline",
        "redcalibur.vuln_intel.vuln_scan",
    ],
}


def tools_for_kind(kind: RunKind) -> list[str]:
    return list(_KIND_TO_TOOLS.get(kind, []))


class RunOrchestrator:
    """Owns the worker thread, run queue, and per-run completion signals."""

    def __init__(self, project_root: Path) -> None:
        self._project_root = project_root
        self._queue: "queue.Queue[str]" = queue.Queue()
        self._lock = threading.Lock()
        self._done: dict[str, threading.Event] = {}
        self._cancel: set[str] = set()
        self._thread = threading.Thread(
            target=self._loop, name="redcalibur-run-worker", daemon=True
        )
        self._thread.start()

    # -- public API ---------------------------------------------------------

    def enqueue(self, run_id: str) -> None:
        with self._lock:
            self._done[run_id] = threading.Event()
        self._queue.put(run_id)

    def request_cancel(self, run_id: str) -> None:
        with self._lock:
            self._cancel.add(run_id)

    def wait(self, run_id: str, timeout: float | None = None) -> bool:
        with self._lock:
            event = self._done.get(run_id)
        if event is None:
            return True
        return event.wait(timeout)

    # -- worker loop --------------------------------------------------------

    def _loop(self) -> None:
        while True:
            run_id = self._queue.get()
            try:
                self._execute(run_id)
            except Exception:  # noqa: BLE001 — a worker must never die.
                try:
                    db.update_run_status(run_id, RunStatus.failed, db.utc_now())
                except Exception:  # noqa: BLE001
                    pass
            finally:
                self._finalize_artifact(run_id)
                # Pop (not just read) the completion event so the dict does not
                # grow unbounded over the life of the server. A late wait() that
                # finds no event treats the run as already done (returns True).
                with self._lock:
                    self._cancel.discard(run_id)
                    event = self._done.pop(run_id, None)
                if event is not None:
                    event.set()
                self._queue.task_done()

    def _is_cancel_requested(self, run_id: str) -> bool:
        with self._lock:
            if run_id in self._cancel:
                return True
        # A cancel can also be signalled via the run's persisted status.
        return db.get_run_status(run_id) == RunStatus.cancelling

    def _execute(self, run_id: str) -> None:
        run = db.get_run(run_id)
        if run is None:
            return
        scope = db.get_scope(run.workspace_id)
        workspace = db.get_workspace(run.workspace_id)
        if scope is None or workspace is None:
            db.update_run_status(run_id, RunStatus.failed, db.utc_now())
            db.append_run_event(run_id, "run_failed", {"reason": "missing scope or workspace"})
            return

        jobs = db.list_jobs(run_id)
        db.update_run_status(run_id, RunStatus.running)
        db.append_run_event(run_id, "run_started", {"kind": run.kind.value, "job_count": len(jobs)})

        any_failed = False
        cancelled = False

        for job in jobs:
            if self._is_cancel_requested(run_id):
                cancelled = True
                self._mark_job_cancelled(job)
                db.append_run_event(run_id, "job_cancelled", {"job_id": job.id, "tool_id": job.tool_id})
                continue

            outcome = self._run_one_job(run_id, run.kind, scope, workspace.mode, job)
            if outcome != JobStatus.complete:
                any_failed = True

        finished_at = db.utc_now()
        if cancelled:
            # Any jobs that had already started running still need a terminal mark.
            for job in db.list_jobs(run_id):
                if job.status in (JobStatus.queued, JobStatus.running):
                    self._mark_job_cancelled(job)
            db.update_run_status(run_id, RunStatus.cancelled, finished_at)
            db.append_run_event(run_id, "run_cancelled", {})
        elif any_failed:
            db.update_run_status(run_id, RunStatus.failed, finished_at)
            db.append_run_event(run_id, "run_failed", {})
        else:
            db.update_run_status(run_id, RunStatus.complete, finished_at)
            db.append_run_event(run_id, "run_completed", {})

    def _mark_job_cancelled(self, job: Job) -> None:
        job.status = JobStatus.cancelled
        job.error = "Run cancelled before this job completed."
        job.finished_at = db.utc_now()
        db.update_job(job)

    def _run_one_job(self, run_id, kind, scope, mode, job: Job) -> JobStatus:
        tool_id = job.tool_id
        adapter = get_tool(tool_id)
        now = db.utc_now()

        if adapter is None:
            job.status = JobStatus.failed
            job.error = f"No adapter registered for tool '{tool_id}'."
            job.finished_at = now
            db.update_job(job)
            db.append_run_event(run_id, "job_failed", {"job_id": job.id, "tool_id": tool_id, "error": job.error})
            return JobStatus.failed

        # Per-job deterministic policy gate.
        tool_risk = adapter.meta.risk_tier
        allowed = int(tool_risk) <= int(scope.max_risk_tier)
        decision = PolicyDecision.allowed if allowed else PolicyDecision.blocked
        self._write_run_audit(run_id, job.run_id, kind, mode, scope, tool_id, tool_risk, decision)

        if not allowed:
            reason = (
                f"Tool risk tier {int(tool_risk)} exceeds workspace "
                f"max risk tier {int(scope.max_risk_tier)}."
            )
            job.status = JobStatus.failed
            job.error = reason
            job.finished_at = db.utc_now()
            db.update_job(job)
            db.append_run_event(run_id, "job_blocked", {"job_id": job.id, "tool_id": tool_id, "reason": reason})
            return JobStatus.failed

        job.status = JobStatus.running
        job.started_at = db.utc_now()
        db.update_job(job)
        db.append_run_event(run_id, "job_started", {"job_id": job.id, "tool_id": tool_id})

        tool_input = ToolInput(
            workspace_id=scope.workspace_id,
            scope=scope,
            project_root=self._project_root,
            params={},
        )
        pool = ThreadPoolExecutor(max_workers=1)
        try:
            future = pool.submit(adapter.run, tool_input)
            tool_result = future.result(timeout=ADAPTER_TIMEOUT_SECONDS)
            # Adapter returned in time — wait for clean executor teardown.
            pool.shutdown(wait=True)
        except FuturesTimeoutError:
            # Do NOT block on the runaway adapter thread; let the worker move on.
            # (Adapters are local, read-only and size-capped, so a true hang is
            # not expected — this is defensive so one slow adapter can't wedge
            # the whole queue.)
            pool.shutdown(wait=False)
            job.status = JobStatus.failed
            job.error = f"AdapterTimeout: adapter did not complete within {ADAPTER_TIMEOUT_SECONDS}s"
            job.finished_at = db.utc_now()
            db.update_job(job)
            db.append_run_event(run_id, "job_failed", {"job_id": job.id, "tool_id": tool_id, "error": job.error})
            return JobStatus.failed
        except Exception as exc:  # noqa: BLE001 — adapter faults must not crash the worker.
            pool.shutdown(wait=False)
            job.status = JobStatus.failed
            job.error = f"{type(exc).__name__}: {exc}"
            job.finished_at = db.utc_now()
            db.update_job(job)
            db.append_run_event(run_id, "job_failed", {"job_id": job.id, "tool_id": tool_id, "error": job.error})
            return JobStatus.failed

        finished_at = db.utc_now()
        evidence_count = 0
        for record in tool_result.evidence:
            db.insert_evidence_item(
                EvidenceItem(
                    id=db.new_id(),
                    workspace_id=scope.workspace_id,
                    run_id=run_id,
                    source_tool=tool_id,
                    evidence_type=record.evidence_type,
                    title=record.title,
                    summary=record.summary,
                    normalized=record.normalized,
                    collected_at=finished_at,
                )
            )
            evidence_count += 1

        job.status = JobStatus.complete if tool_result.success else JobStatus.failed
        job.output_summary = tool_result.output_summary
        job.error = tool_result.error
        job.finished_at = finished_at
        db.update_job(job)
        db.append_run_event(
            run_id,
            "job_completed" if tool_result.success else "job_failed",
            {"job_id": job.id, "tool_id": tool_id, "evidence_count": evidence_count},
        )
        return job.status

    def _write_run_audit(self, run_id, job_run_id, kind, mode, scope, tool_id, tool_risk, decision) -> None:
        input_summary = f"run:{kind.value}:tool-{tool_id}:risk-{int(tool_risk)}"
        db.insert_audit_event(
            AuditEvent(
                id=db.new_audit_event_id(),
                workspace_id=scope.workspace_id,
                mode=mode,
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

    def _finalize_artifact(self, run_id: str) -> None:
        run = db.get_run(run_id)
        if run is None:
            return
        try:
            db.write_run_artifact(run, db.list_jobs(run_id), db.list_evidence_items(run_id))
        except Exception:  # noqa: BLE001 — artifact write is best-effort, never fatal.
            pass
