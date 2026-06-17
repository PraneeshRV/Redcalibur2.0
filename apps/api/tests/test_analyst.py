import asyncio

import httpx

from redcalibur_api.ai import gateway
from redcalibur_api.models import AnalystClaim, AnalystQuestionKind, EvidenceItem


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


def _evidence(eid: str) -> EvidenceItem:
    return EvidenceItem(
        id=eid,
        workspace_id="w",
        run_id="r",
        source_tool="redcalibur.vuln_intel.vuln_scan",
        evidence_type="vulnerability_match",
        title="t",
        summary="s",
        normalized={
            "package": "demo-vulnerable-package",
            "ecosystem": "npm",
            "version_spec": "1.0.0",
            "vulnerabilities": [
                {
                    "id": "OSV-DEMO-2025-0001",
                    "summary": "prototype pollution",
                    "severity_label": "critical",
                    "kev": True,
                    "priority_score": 94,
                    "fix_available": True,
                    "fixed_version": "1.2.0",
                }
            ],
        },
        collected_at="2026-06-17T00:00:00+00:00",
    )


def test_prioritize_cites_evidence():
    ev = [_evidence("ev-1")]
    resp = gateway.analyze(AnalystQuestionKind.prioritize, ev)
    assert resp.claims
    # Every claim cites a real evidence id.
    assert all(c.evidence_ids for c in resp.claims)
    assert all(eid in {"ev-1"} for c in resp.claims for eid in c.evidence_ids)
    assert "ev-1" in resp.citations
    assert resp.unsupported_rejected == 0


def test_no_evidence_yields_no_claims():
    resp = gateway.analyze(AnalystQuestionKind.prioritize, [])
    assert resp.claims == []
    assert resp.citations == []


class _BadProvider:
    name = "bad"

    def generate(self, kind, evidence):
        # An ungrounded claim citing an evidence id that does not exist.
        return ("bad", [AnalystClaim(text="trust me", evidence_ids=["does-not-exist"])])


def test_gateway_rejects_ungrounded_claims():
    ev = [_evidence("ev-1")]
    resp = gateway.analyze(AnalystQuestionKind.prioritize, ev, provider=_BadProvider())
    assert resp.claims == []
    assert resp.unsupported_rejected == 1


class _LeakyProvider:
    name = "leaky"

    def generate(self, kind, evidence):
        secret = "sk-ABCDEFGHIJKLMNOPQRSTUVWX1234567890"
        return (
            f"key {secret}",
            [AnalystClaim(text=f"found {secret}", evidence_ids=[evidence[0].id])],
        )


def test_gateway_redacts_secret_shaped_text():
    ev = [_evidence("ev-1")]
    resp = gateway.analyze(AnalystQuestionKind.explain_findings, ev, provider=_LeakyProvider())
    assert "sk-ABCDEF" not in resp.headline
    assert "[REDACTED]" in resp.headline
    assert all("sk-ABCDEF" not in c.text for c in resp.claims)


def test_analyst_endpoint_after_baseline(monkeypatch, tmp_path):
    monkeypatch.setenv("REDCALIBUR_DATA_DIR", str(tmp_path))
    from redcalibur_api.main import create_app

    async def exercise():
        async with _client(create_app()) as client:
            await client.get("/health")
            await client.post("/workspaces/demo-ai-coding-stack/runs", json={"kind": "baseline"})
            return await client.post(
                "/workspaces/demo-ai-coding-stack/analyst",
                json={"kind": "prioritize"},
            )

    resp = asyncio.run(exercise())
    assert resp.status_code == 200
    body = resp.json()
    assert body["provider"] == "mock"
    assert len(body["claims"]) >= 1
    assert len(body["citations"]) >= 1
