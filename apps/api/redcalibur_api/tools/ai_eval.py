"""AI security evaluation adapter.

Runs the prompt-injection, RAG-leakage, and unsafe-tool-use suites against the
local mock AI target. Risk tier 0 — fully offline, in-process, no network and no
external model calls. Each failing probe becomes an ``ai_eval_result`` evidence
record (and therefore a finding); passing probes are summarized but not raised as
findings.
"""

from __future__ import annotations

from redcalibur_api.lab import suites
from redcalibur_api.lab.mock_app import MockAIApp
from redcalibur_api.models import RiskTier
from redcalibur_api.tools.registry import (
    EvidenceRecord,
    ToolInput,
    ToolMeta,
    ToolResult,
    register,
)

TOOL_ID = "redcalibur.ai_lab.ai_eval"
TARGET_ID = "lab-mock-app"
TARGET_NAME = "Lab Mock AI App"

_meta = ToolMeta(
    id=TOOL_ID,
    name="AI Security Eval",
    version="0.1.0",
    risk_tier=RiskTier.offline_demo,
    description="Runs offline prompt-injection, RAG-leakage, and unsafe-tool-use suites against the lab mock app.",
)


class AIEvalAdapter:
    meta = _meta

    def run(self, tool_input: ToolInput) -> ToolResult:
        # Always exercises the (unhardened) mock target so the planted issues are
        # found deterministically. Fix verification uses a hardened target via the
        # dedicated verify endpoint.
        app = MockAIApp(hardened=False)
        results = suites.evaluate(app)

        evidence: list[EvidenceRecord] = []
        vulnerable = [r for r in results if r.vulnerable]
        for r in vulnerable:
            evidence.append(
                EvidenceRecord(
                    evidence_type="ai_eval_result",
                    title=f"{r.category}: {r.title} ({r.probe_id})",
                    summary=f"Target '{TARGET_NAME}' is vulnerable to {r.category} probe {r.probe_id}.",
                    normalized={
                        "target_id": TARGET_ID,
                        "target_name": TARGET_NAME,
                        "category": r.category,
                        "probe_id": r.probe_id,
                        "title": r.title,
                        "vulnerable": True,
                        "detail": r.detail,
                    },
                )
            )

        by_category: dict[str, int] = {}
        for r in vulnerable:
            by_category[r.category] = by_category.get(r.category, 0) + 1

        return ToolResult(
            tool_id=TOOL_ID,
            success=True,
            evidence=evidence,
            output_summary={
                "target_id": TARGET_ID,
                "total_probes": len(results),
                "vulnerable_count": len(vulnerable),
                "by_category": by_category,
            },
        )


ai_eval = AIEvalAdapter()
register(ai_eval)
