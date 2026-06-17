"""Analyst providers.

A provider turns a question kind plus a set of evidence items into raw claims.
The only provider shipped today is the deterministic ``MockProvider`` — it
performs NO network calls and invents nothing: every claim it emits is built
directly from a specific evidence item and cites that item's id. This keeps
tests deterministic and guarantees the analyst is grounded in evidence.

A live provider (OpenAI/Anthropic) would implement the same ``generate``
signature; the gateway validates whatever any provider returns against the real
evidence set, so an ungrounded claim from any provider is rejected downstream.
"""

from __future__ import annotations

from typing import Protocol

from redcalibur_api.models import AnalystClaim, AnalystQuestionKind, EvidenceItem


class AnalystProvider(Protocol):
    name: str

    def generate(self, kind: AnalystQuestionKind, evidence: list[EvidenceItem]) -> tuple[str, list[AnalystClaim]]:
        """Return (headline, claims). Each claim must cite evidence ids."""
        ...


def _vuln_items(evidence: list[EvidenceItem]) -> list[EvidenceItem]:
    items = [e for e in evidence if e.evidence_type == "vulnerability_match"]
    # Highest top-priority first so "what should I fix first" is meaningful.
    def top_priority(item: EvidenceItem) -> int:
        vulns = item.normalized.get("vulnerabilities", [])
        return max((int(v.get("priority_score", 0)) for v in vulns), default=0)

    return sorted(items, key=top_priority, reverse=True)


class MockProvider:
    """Deterministic, offline analyst. Grounded entirely in evidence."""

    name = "mock"

    def generate(self, kind: AnalystQuestionKind, evidence: list[EvidenceItem]) -> tuple[str, list[AnalystClaim]]:
        if kind == AnalystQuestionKind.prioritize:
            return self._prioritize(evidence)
        if kind == AnalystQuestionKind.explain_findings:
            return self._explain(evidence)
        if kind == AnalystQuestionKind.remediate:
            return self._remediate(evidence)
        if kind == AnalystQuestionKind.report_section:
            return self._report_section(evidence)
        return ("No analysis available for this question kind.", [])

    def _prioritize(self, evidence: list[EvidenceItem]) -> tuple[str, list[AnalystClaim]]:
        vulns = _vuln_items(evidence)
        if not vulns:
            return ("No vulnerability evidence is available, so there is nothing to prioritize.", [])
        claims: list[AnalystClaim] = []
        for rank, item in enumerate(vulns, start=1):
            records = item.normalized.get("vulnerabilities", [])
            if not records:
                continue
            top = max(records, key=lambda v: int(v.get("priority_score", 0)))
            pkg = item.normalized.get("package", "unknown")
            kev = " (known-exploited)" if top.get("kev") else ""
            claims.append(
                AnalystClaim(
                    text=(
                        f"#{rank}: Address {pkg} — {top.get('id')} has priority "
                        f"{top.get('priority_score')} ({top.get('severity_label')}){kev}."
                    ),
                    evidence_ids=[item.id],
                )
            )
        headline = f"Fix {vulns[0].normalized.get('package', 'the top package')} first based on priority score."
        return (headline, claims)

    def _explain(self, evidence: list[EvidenceItem]) -> tuple[str, list[AnalystClaim]]:
        vulns = _vuln_items(evidence)
        if not vulns:
            return ("No findings to explain.", [])
        claims: list[AnalystClaim] = []
        for item in vulns:
            for v in item.normalized.get("vulnerabilities", []):
                claims.append(
                    AnalystClaim(
                        text=f"{v.get('id')} in {item.normalized.get('package')}: {v.get('summary')}",
                        evidence_ids=[item.id],
                    )
                )
        return (f"{len(claims)} finding(s) explained from collected evidence.", claims)

    def _remediate(self, evidence: list[EvidenceItem]) -> tuple[str, list[AnalystClaim]]:
        vulns = _vuln_items(evidence)
        claims: list[AnalystClaim] = []
        for item in vulns:
            pkg = item.normalized.get("package")
            for v in item.normalized.get("vulnerabilities", []):
                if v.get("fix_available") and v.get("fixed_version"):
                    claims.append(
                        AnalystClaim(
                            text=f"Upgrade {pkg} to {v.get('fixed_version')} to resolve {v.get('id')}.",
                            evidence_ids=[item.id],
                        )
                    )
        if not claims:
            return ("No fixed versions are available in the evidence for the matched vulnerabilities.", [])
        return (f"{len(claims)} remediation step(s) drafted from evidence.", claims)

    def _report_section(self, evidence: list[EvidenceItem]) -> tuple[str, list[AnalystClaim]]:
        claims: list[AnalystClaim] = []
        for item in _vuln_items(evidence):
            records = item.normalized.get("vulnerabilities", [])
            ids = ", ".join(v.get("id", "") for v in records)
            claims.append(
                AnalystClaim(
                    text=f"{item.normalized.get('package')} ({item.normalized.get('version_spec')}): {ids}",
                    evidence_ids=[item.id],
                )
            )
        if not claims:
            return ("No vulnerability findings recorded for this workspace.", [])
        return ("Vulnerability summary assembled from evidence.", claims)
