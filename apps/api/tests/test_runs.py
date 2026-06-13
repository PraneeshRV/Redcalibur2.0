import asyncio

import httpx


def test_manifest_scan_run_creates_evidence(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))

    from redcalibur_api.main import create_app

    async def exercise():
        transport = httpx.ASGITransport(app=create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            await client.get("/health")
            run = await client.post(
                "/workspaces/demo-ai-coding-stack/runs",
                json={"kind": "manifest_scan"},
            )
            return run

    run = asyncio.run(exercise())

    assert run.status_code == 201
    body = run.json()
    assert body["run"]["status"] == "complete"
    assert body["run"]["kind"] == "manifest_scan"
    assert len(body["jobs"]) == 1
    assert body["jobs"][0]["status"] == "complete"
    assert body["jobs"][0]["output_summary"]["manifests_found"] >= 1
    assert len(body["evidence"]) >= 1
    assert body["evidence"][0]["evidence_type"] == "package_inventory"


def test_list_runs_returns_completed_run(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))

    from redcalibur_api.main import create_app

    async def exercise():
        transport = httpx.ASGITransport(app=create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            await client.get("/health")
            await client.post(
                "/workspaces/demo-ai-coding-stack/runs",
                json={"kind": "manifest_scan"},
            )
            return await client.get("/workspaces/demo-ai-coding-stack/runs")

    runs = asyncio.run(exercise())

    assert runs.status_code == 200
    assert len(runs.json()) == 1
    assert runs.json()[0]["status"] == "complete"


def test_get_run_returns_full_response(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))

    from redcalibur_api.main import create_app

    async def exercise():
        transport = httpx.ASGITransport(app=create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            await client.get("/health")
            created = (
                await client.post(
                    "/workspaces/demo-ai-coding-stack/runs",
                    json={"kind": "manifest_scan"},
                )
            ).json()
            fetched = await client.get(f"/runs/{created['run']['id']}")
            return fetched

    fetched = asyncio.run(exercise())

    assert fetched.status_code == 200
    body = fetched.json()
    assert body["run"]["kind"] == "manifest_scan"
    assert len(body["evidence"]) >= 1


def test_run_writes_audit_event(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))

    from redcalibur_api.main import create_app

    async def exercise():
        transport = httpx.ASGITransport(app=create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            await client.get("/health")
            await client.post("/workspaces/demo-ai-coding-stack/runs", json={"kind": "manifest_scan"})
            return await client.get("/workspaces/demo-ai-coding-stack/audit-events")

    events = asyncio.run(exercise())

    assert events.status_code == 200
    run_events = [e for e in events.json() if e["action"] == "run"]
    assert len(run_events) == 1
    assert run_events[0]["decision"] == "allowed"
    assert run_events[0]["risk_tier"] == 1


def test_run_blocked_when_tool_risk_exceeds_scope(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))

    from redcalibur_api.main import create_app

    async def exercise():
        transport = httpx.ASGITransport(app=create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # Lower the workspace max risk tier below the tool's tier (manifest scan = 1).
            scope = (await client.get("/workspaces/demo-ai-coding-stack/scope")).json()
            scope["max_risk_tier"] = 0
            await client.put("/workspaces/demo-ai-coding-stack/scope", json=scope)
            run = await client.post("/workspaces/demo-ai-coding-stack/runs", json={"kind": "manifest_scan"})
            events = await client.get("/workspaces/demo-ai-coding-stack/audit-events")
            return run, events

    run, events = asyncio.run(exercise())

    assert run.status_code == 201
    body = run.json()
    assert body["run"]["status"] == "failed"
    assert body["jobs"][0]["status"] == "failed"
    assert "exceeds" in body["jobs"][0]["error"]
    assert body["evidence"] == []
    run_events = [e for e in events.json() if e["action"] == "run"]
    assert run_events[0]["decision"] == "blocked"


def test_start_run_on_missing_workspace_returns_404(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))

    from redcalibur_api.main import create_app

    async def exercise():
        transport = httpx.ASGITransport(app=create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            await client.get("/health")
            return await client.post("/workspaces/nonexistent/runs", json={"kind": "manifest_scan"})

    resp = asyncio.run(exercise())

    assert resp.status_code == 404
