import asyncio

import httpx


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def test_asset_graph_built_from_local_evidence(monkeypatch, tmp_path):
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    from redcalibur_api.main import create_app

    async def exercise():
        async with _client(create_app()) as client:
            await client.get("/health")
            await client.post("/workspaces/demo-ai-coding-stack/runs", json={"kind": "baseline"})
            return await client.get("/workspaces/demo-ai-coding-stack/asset-graph")

    resp = asyncio.run(exercise())
    assert resp.status_code == 200
    graph = resp.json()
    kinds = {n["kind"] for n in graph["nodes"]}
    assert "workspace" in kinds
    assert "package" in kinds
    assert "vulnerability" in kinds
    relations = {e["relation"] for e in graph["edges"]}
    assert "affected_by" in relations
    assert "gated" in graph["note"] or "not executed" in graph["note"]


def test_network_recon_is_gated_off(monkeypatch, tmp_path):
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    from redcalibur_api.main import create_app

    async def exercise():
        async with _client(create_app()) as client:
            await client.get("/health")
            return await client.post("/workspaces/demo-ai-coding-stack/recon")

    resp = asyncio.run(exercise())
    assert resp.status_code == 403
    assert "deferred" in resp.json()["detail"].lower()
