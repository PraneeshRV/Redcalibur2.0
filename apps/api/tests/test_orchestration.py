import asyncio
import json
import time
from pathlib import Path

import httpx


def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def test_baseline_run_fans_out_to_multiple_jobs(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    from redcalibur_api.main import create_app

    async def exercise():
        async with _client(create_app()) as client:
            await client.get("/health")
            run = await client.post(
                "/workspaces/demo-ai-coding-stack/runs",
                json={"kind": "baseline"},
            )
            return run

    run = asyncio.run(exercise())
    assert run.status_code == 201
    body = run.json()
    assert body["run"]["kind"] == "baseline"
    assert body["run"]["status"] == "complete"
    # Four developer-surface adapters => four jobs under one run.
    assert len(body["jobs"]) == 4
    tool_ids = {job["tool_id"] for job in body["jobs"]}
    assert any("manifest_scan" in t for t in tool_ids)
    assert any("secrets_baseline" in t for t in tool_ids)
    assert all(job["status"] == "complete" for job in body["jobs"])
    # Every finding links back to a job's tool.
    for item in body["evidence"]:
        assert item["source_tool"] in tool_ids


def test_async_run_returns_queued_then_completes(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    from redcalibur_api.main import create_app

    async def exercise():
        async with _client(create_app()) as client:
            await client.get("/health")
            created = (
                await client.post(
                    "/workspaces/demo-ai-coding-stack/runs",
                    json={"kind": "baseline", "wait": False},
                )
            ).json()
            run_id = created["run"]["id"]
            # Poll until terminal.
            final = None
            for _ in range(100):
                final = (await client.get(f"/runs/{run_id}")).json()
                if final["run"]["status"] in ("complete", "failed", "cancelled"):
                    break
                await asyncio.sleep(0.05)
            return created, final

    created, final = asyncio.run(exercise())
    assert created["run"]["status"] in ("queued", "running", "complete")
    assert final is not None
    assert final["run"]["status"] == "complete"
    assert len(final["jobs"]) == 4


def test_run_emits_ordered_events(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    from redcalibur_api.main import create_app

    async def exercise():
        async with _client(create_app()) as client:
            await client.get("/health")
            created = (
                await client.post(
                    "/workspaces/demo-ai-coding-stack/runs",
                    json={"kind": "baseline"},
                )
            ).json()
            run_id = created["run"]["id"]
            resp = await client.get(f"/runs/{run_id}/events")
            return resp

    resp = asyncio.run(exercise())
    assert resp.status_code == 200
    text = resp.text
    assert "event: run_started" in text
    assert "event: run_completed" in text
    assert "event: stream_end" in text
    # Events carry monotonically increasing seq numbers.
    seqs = []
    for line in text.splitlines():
        if line.startswith("data: "):
            payload = json.loads(line[len("data: "):])
            if "seq" in payload:
                seqs.append(payload["seq"])
    assert seqs == sorted(seqs)
    assert len(seqs) >= 4


def test_cancel_before_run_starts_marks_cancelled(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    from redcalibur_api import db
    from redcalibur_api.main import create_app

    async def exercise():
        async with _client(create_app()) as client:
            await client.get("/health")
            # Queue a run without waiting, then immediately request cancel.
            created = (
                await client.post(
                    "/workspaces/demo-ai-coding-stack/runs",
                    json={"kind": "baseline", "wait": False},
                )
            ).json()
            run_id = created["run"]["id"]
            cancel = await client.post(f"/runs/{run_id}/cancel")
            # Wait for terminal state.
            final = None
            for _ in range(100):
                final = (await client.get(f"/runs/{run_id}")).json()
                if final["run"]["status"] in ("complete", "failed", "cancelled"):
                    break
                await asyncio.sleep(0.05)
            return cancel, final

    cancel, final = asyncio.run(exercise())
    assert cancel.status_code in (200, 409)
    assert final is not None
    # The run resolves to a terminal state; cancellation is best-effort and may
    # land as cancelled (common) or complete if the worker already finished.
    assert final["run"]["status"] in ("cancelled", "complete")


def test_cancel_terminal_run_returns_409(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    from redcalibur_api.main import create_app

    async def exercise():
        async with _client(create_app()) as client:
            await client.get("/health")
            created = (
                await client.post(
                    "/workspaces/demo-ai-coding-stack/runs",
                    json={"kind": "manifest_scan"},
                )
            ).json()
            return await client.post(f"/runs/{created['run']['id']}/cancel")

    resp = asyncio.run(exercise())
    assert resp.status_code == 409


def test_run_writes_durable_artifact(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    from redcalibur_api.main import create_app

    async def exercise():
        async with _client(create_app()) as client:
            await client.get("/health")
            return (
                await client.post(
                    "/workspaces/demo-ai-coding-stack/runs",
                    json={"kind": "manifest_scan"},
                )
            ).json()

    body = asyncio.run(exercise())
    run_id = body["run"]["id"]
    artifact = Path(tmp_path) / "artifacts" / f"{run_id}.json"
    assert artifact.exists()
    snapshot = json.loads(artifact.read_text())
    assert snapshot["run"]["id"] == run_id
    assert len(snapshot["jobs"]) == 1
    assert snapshot["run"]["status"] == "complete"


def test_baseline_blocked_jobs_when_scope_too_low(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    from redcalibur_api.main import create_app

    async def exercise():
        async with _client(create_app()) as client:
            await client.get("/health")
            scope = (await client.get("/workspaces/demo-ai-coding-stack/scope")).json()
            scope["max_risk_tier"] = 0
            await client.put("/workspaces/demo-ai-coding-stack/scope", json=scope)
            run = await client.post("/workspaces/demo-ai-coding-stack/runs", json={"kind": "baseline"})
            events = await client.get("/workspaces/demo-ai-coding-stack/audit-events")
            return run, events

    run, events = asyncio.run(exercise())
    body = run.json()
    # All tiers exceed max 0, so every job fails the policy gate and the run fails.
    assert body["run"]["status"] == "failed"
    assert all(job["status"] == "failed" for job in body["jobs"])
    assert all("exceeds" in (job["error"] or "") for job in body["jobs"])
    assert body["evidence"] == []
    run_events = [e for e in events.json() if e["action"] == "run"]
    # One audit event per job, all blocked.
    assert len(run_events) == len(body["jobs"])
    assert all(e["decision"] == "blocked" for e in run_events)
