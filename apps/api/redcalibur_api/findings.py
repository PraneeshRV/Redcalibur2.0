"""Findings derivation.

A finding is a triage-ready view over vulnerability evidence: one row per
(package, vulnerability) pair, sorted by the explainable priority score. Each
finding links back to the evidence item it came from, so nothing is asserted
without a citation. Findings are derived on read rather than persisted; lifecycle
state (accepted / false-positive / fixed / verified) is a post-MVP concern, so
the status defaults to ``open``.
"""

from __future__ import annotations

from redcalibur_api.models import EvidenceItem, Finding


def derive_findings(workspace_id: str, evidence: list[EvidenceItem]) -> list[Finding]:
    findings: list[Finding] = []
    for item in evidence:
        if item.evidence_type != "vulnerability_match":
            continue
        pkg = item.normalized.get("package", "unknown")
        ecosystem = item.normalized.get("ecosystem", "unknown")
        for v in item.normalized.get("vulnerabilities", []):
            findings.append(
                Finding(
                    id=f"{item.id}:{v.get('id')}",
                    workspace_id=workspace_id,
                    package=pkg,
                    ecosystem=ecosystem,
                    vuln_id=v.get("id", "unknown"),
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
    findings.sort(key=lambda f: f.priority_score, reverse=True)
    return findings
