import asyncio

import httpx


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def test_markdown_report_contains_findings_and_citations(monkeypatch, tmp_path):
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    from redcalibur_api.main import create_app

    async def exercise():
        async with _client(create_app()) as client:
            await client.get("/health")
            await client.post("/workspaces/demo-ai-coding-stack/runs", json={"kind": "baseline"})
            return await client.get("/workspaces/demo-ai-coding-stack/report?format=md")

    resp = asyncio.run(exercise())
    assert resp.status_code == 200
    assert "text/markdown" in resp.headers["content-type"]
    text = resp.text
    assert "# RedCalibur Assessment Report" in text
    assert "## Findings" in text
    assert "OSV-DEMO-2025-0001" in text
    assert "Prioritized Recommendations" in text
    assert "Evidence Index" in text


def test_html_report_renders(monkeypatch, tmp_path):
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    from redcalibur_api.main import create_app

    async def exercise():
        async with _client(create_app()) as client:
            await client.get("/health")
            await client.post("/workspaces/demo-ai-coding-stack/runs", json={"kind": "baseline"})
            return await client.get("/workspaces/demo-ai-coding-stack/report?format=html")

    resp = asyncio.run(exercise())
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "<table>" in resp.text
    assert "RedCalibur Assessment Report" in resp.text


def test_report_bad_format_rejected(monkeypatch, tmp_path):
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    from redcalibur_api.main import create_app

    async def exercise():
        async with _client(create_app()) as client:
            await client.get("/health")
            return await client.get("/workspaces/demo-ai-coding-stack/report?format=pdf")

    resp = asyncio.run(exercise())
    assert resp.status_code == 400
