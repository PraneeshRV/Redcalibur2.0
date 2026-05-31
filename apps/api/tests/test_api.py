import asyncio

import httpx


def test_migration_and_seed_are_idempotent(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))

    from redcalibur_api.db import initialize_database, list_workspaces

    initialize_database()
    initialize_database()

    workspaces = list_workspaces()
    workspace_ids = [workspace.id for workspace in workspaces]

    assert (tmp_path / "redcalibur.db").exists()
    assert workspace_ids.count("demo-ai-coding-stack") == 1


def test_health_and_workspace_routes(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))

    from redcalibur_api.main import create_app

    async def exercise_routes():
        transport = httpx.ASGITransport(app=create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return (
                await client.get("/health"),
                await client.get("/workspaces"),
                await client.get("/workspaces/demo-ai-coding-stack"),
                await client.get("/workspaces/demo-ai-coding-stack/scope"),
            )

    health, workspaces, workspace, scope = asyncio.run(exercise_routes())

    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    assert workspaces.status_code == 200
    assert [item["id"] for item in workspaces.json()] == ["demo-ai-coding-stack"]
    assert workspace.status_code == 200
    assert workspace.json()["name"] == "RedCalibur Demo - AI Coding Stack"
    assert workspace.json()["mode"] == "demo"
    assert scope.status_code == 200
    assert scope.json()["allowed_roots"] == ["fixtures/demo-ai-stack"]
    assert scope.json()["excluded_roots"] == ["fixtures/demo-ai-stack/secrets"]
    assert scope.json()["max_risk_tier"] == 1


def test_create_workspace_route(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))

    from redcalibur_api.main import create_app

    async def exercise_routes():
        transport = httpx.ASGITransport(app=create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            created = await client.post(
                "/workspaces",
                json={
                    "id": "learning-lab",
                    "name": "Learning Lab",
                    "mode": "learning",
                    "purpose": "Local learning workspace.",
                },
            )
            workspaces = await client.get("/workspaces")
            return created, workspaces

    created, workspaces = asyncio.run(exercise_routes())

    assert created.status_code == 201
    assert created.json()["id"] == "learning-lab"
    assert "learning-lab" in [workspace["id"] for workspace in workspaces.json()]


def test_scope_update_is_durable(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))

    from redcalibur_api.main import create_app

    async def exercise_routes():
        transport = httpx.ASGITransport(app=create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            existing = (await client.get("/workspaces/demo-ai-coding-stack/scope")).json()
            existing["allowed_roots"] = ["fixtures/demo-ai-stack", "fixtures/extra-demo"]
            saved = await client.put("/workspaces/demo-ai-coding-stack/scope", json=existing)
            fetched = await client.get("/workspaces/demo-ai-coding-stack/scope")
            await client.get("/health")
            fetched_after_init = await client.get("/workspaces/demo-ai-coding-stack/scope")
            return saved, fetched, fetched_after_init

    saved, fetched, fetched_after_init = asyncio.run(exercise_routes())

    assert saved.status_code == 200
    assert fetched.json()["allowed_roots"] == ["fixtures/demo-ai-stack", "fixtures/extra-demo"]
    assert fetched_after_init.json()["allowed_roots"] == ["fixtures/demo-ai-stack", "fixtures/extra-demo"]


def test_blocked_preview_writes_audit_event(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))

    from redcalibur_api.main import create_app

    async def exercise_routes():
        transport = httpx.ASGITransport(app=create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            preview = await client.post(
                "/workspaces/demo-ai-coding-stack/run-preview",
                json={
                    "target_type": "url",
                    "target": "https://example.com",
                    "risk_tier": 1,
                },
            )
            audit_events = await client.get("/workspaces/demo-ai-coding-stack/audit-events")
            return preview, audit_events

    preview, audit_events = asyncio.run(exercise_routes())

    assert preview.status_code == 200
    assert preview.json()["decision"] == "blocked"
    assert preview.json()["reasons"] == ["Demo mode blocks arbitrary network targets."]
    assert audit_events.status_code == 200
    assert len(audit_events.json()) == 1
    assert audit_events.json()[0]["workspace_id"] == "demo-ai-coding-stack"
    assert audit_events.json()[0]["decision"] == "blocked"
    assert audit_events.json()[0]["target"].startswith("redacted:")
    assert audit_events.json()[0]["target"] != "https://example.com"
    assert "https://example.com" not in audit_events.json()[0]["input_summary"]


def test_allowed_preview_writes_audit_event(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))

    from redcalibur_api.main import create_app

    async def exercise_routes():
        transport = httpx.ASGITransport(app=create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            preview = await client.post(
                "/workspaces/demo-ai-coding-stack/run-preview",
                json={
                    "target_type": "local_path",
                    "target": "fixtures/demo-ai-stack/package.json",
                    "risk_tier": 1,
                },
            )
            audit_events = await client.get("/workspaces/demo-ai-coding-stack/audit-events")
            return preview, audit_events

    preview, audit_events = asyncio.run(exercise_routes())

    assert preview.status_code == 200
    assert preview.json()["decision"] == "allowed"
    assert audit_events.status_code == 200
    assert len(audit_events.json()) == 1
    assert audit_events.json()[0]["decision"] == "allowed"
    assert audit_events.json()[0]["target"].startswith("redacted:")
