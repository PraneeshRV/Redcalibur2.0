"""Findings derivation + lifecycle overlay.

A finding is a triage-ready view over evidence:

- dependency findings: one per (package, vulnerability) from vulnerability_match
  evidence, sorted by the explainable priority score;
- ai_eval findings: one per failing probe from ai_eval_result evidence.

Finding ids are STABLE across runs (derived from intrinsic attributes, not the
evidence row's uuid) so a persisted lifecycle status (open / accepted /
false_positive / fixed / verified) survives re-running a scan. Each finding still
links to the most recent evidence row it came from.
"""

from __future__ import annotations

from redcalibur_api.models import (
    EvidenceItem,
    Finding,
    FindingKind,
    FindingState,
    FindingStatus,
)

# ai_eval probes carry their own severity; map category to a coarse priority.
_AI_EVAL_PRIORITY = {
    "prompt_injection": 80,
    "rag_leakage": 75,
    "unsafe_tool_use": 90,
}
_AI_EVAL_SEVERITY = {
    "prompt_injection": "high",
    "rag_leakage": "high",
    "unsafe_tool_use": "critical",
}


def _dependency_findings(workspace_id: str, item: EvidenceItem) -> list[Finding]:
    pkg = item.normalized.get("package", "unknown")
    ecosystem = item.normalized.get("ecosystem", "unknown")
    out: list[Finding] = []
    for v in item.normalized.get("vulnerabilities", []):
        vuln_id = v.get("id", "unknown")
        out.append(
            Finding(
                id=f"dep:{ecosystem}:{pkg}:{vuln_id}",
                workspace_id=workspace_id,
                finding_kind=FindingKind.dependency,
                package=pkg,
                ecosystem=ecosystem,
                vuln_id=vuln_id,
                aliases=list(v.get("aliases", [])),
                severity_cvss=float(v.get("severity_cvss", 0.0)),
                severity_label=v.get("severity_label", "unknown"),
                kev=bool(v.get("kev", False)),
                epss=float(v.get("epss", 0.0)),
                priority_score=int(v.get("priority_score", 0)),
                fixed_version=v.get("fixed_version"),
                fix_available=bool(v.get("fix_available", False)),
                evidence_id=item.id,
            )
        )
    return out


def _ai_eval_findings(workspace_id: str, item: EvidenceItem) -> list[Finding]:
    category = item.normalized.get("category", "unknown")
    probe_id = item.normalized.get("probe_id", "unknown")
    target = item.normalized.get("target_id", "lab-mock-app")
    return [
        Finding(
            id=f"aieval:{target}:{category}:{probe_id}",
            workspace_id=workspace_id,
            finding_kind=FindingKind.ai_eval,
            package=target,
            ecosystem="ai_app",
            vuln_id=probe_id,
            severity_label=_AI_EVAL_SEVERITY.get(category, "high"),
            priority_score=_AI_EVAL_PRIORITY.get(category, 70),
            evidence_id=item.id,
        )
    ]


def derive_findings(
    workspace_id: str,
    evidence: list[EvidenceItem],
    states: dict[str, FindingState] | None = None,
) -> list[Finding]:
    states = states or {}
    by_id: dict[str, Finding] = {}
    for item in evidence:
        if item.evidence_type == "vulnerability_match":
            derived = _dependency_findings(workspace_id, item)
        elif item.evidence_type == "ai_eval_result":
            derived = _ai_eval_findings(workspace_id, item)
        else:
            continue
        for finding in derived:
            # Keep the latest evidence row for a stable finding id.
            by_id[finding.id] = finding

    findings = list(by_id.values())
    for finding in findings:
        state = states.get(finding.id)
        if state is not None:
            finding.status = state.status
            finding.note = state.note
    findings.sort(key=lambda f: f.priority_score, reverse=True)
    return findings
