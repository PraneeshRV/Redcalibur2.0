import asyncio

import httpx


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def test_vuln_scan_run_produces_vulnerability_evidence(monkeypatch, tmp_path):
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    from redcalibur_api.main import create_app

    async def exercise():
        async with _client(create_app()) as client:
            await client.get("/health")
            return await client.post(
                "/workspaces/demo-ai-coding-stack/runs",
                json={"kind": "vuln_scan"},
            )

    run = asyncio.run(exercise())
    assert run.status_code == 201
    body = run.json()
    assert body["run"]["status"] == "complete"
    assert len(body["evidence"]) >= 1
    types = {e["evidence_type"] for e in body["evidence"]}
    assert "vulnerability_match" in types
    # Demo npm package should be among matches with a high priority.
    pkgs = {e["normalized"]["package"] for e in body["evidence"]}
    assert "demo-vulnerable-package" in pkgs


def test_baseline_includes_vuln_scan(monkeypatch, tmp_path):
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    from redcalibur_api.main import create_app

    async def exercise():
        async with _client(create_app()) as client:
            await client.get("/health")
            return await client.post(
                "/workspaces/demo-ai-coding-stack/runs",
                json={"kind": "baseline"},
            )

    body = asyncio.run(exercise()).json()
    # Baseline now fans out to five jobs (4 dev-surface + vuln scan).
    assert len(body["jobs"]) == 5
    tool_ids = {j["tool_id"] for j in body["jobs"]}
    assert any("vuln_scan" in t for t in tool_ids)


def test_findings_endpoint_sorted_by_priority(monkeypatch, tmp_path):
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    from redcalibur_api.main import create_app

    async def exercise():
        async with _client(create_app()) as client:
            await client.get("/health")
            await client.post("/workspaces/demo-ai-coding-stack/runs", json={"kind": "vuln_scan"})
            return await client.get("/workspaces/demo-ai-coding-stack/findings")

    resp = asyncio.run(exercise())
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) >= 3
    scores = [f["priority_score"] for f in findings]
    assert scores == sorted(scores, reverse=True)
    # No invented vuln ids — all come from the feed.
    assert all(f["vuln_id"].startswith("OSV-DEMO-") for f in findings)
