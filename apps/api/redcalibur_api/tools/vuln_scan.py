"""Vulnerability enrichment scan.

Inventories package manifests in declared scope roots (reusing the manifest
scan parsers) and matches them against the bundled offline vulnerability feed.
Risk tier 1 — passive read-only, no network calls. All enrichment data comes
from a local, version-pinned feed shipped with the package.
"""

from __future__ import annotations

from pathlib import Path

from redcalibur_api import vuln_intel
from redcalibur_api.models import RiskTier
from redcalibur_api.tools.manifest_scan import _PARSERS, _find_manifests
from redcalibur_api.tools.registry import (
    EvidenceRecord,
    ToolInput,
    ToolMeta,
    ToolResult,
    register,
)

TOOL_ID = "redcalibur.vuln_intel.vuln_scan"

_meta = ToolMeta(
    id=TOOL_ID,
    name="Vulnerability Scan",
    version="0.1.0",
    risk_tier=RiskTier.passive_read_only,
    description="Matches declared packages against the offline vulnerability feed and scores priority.",
)


class VulnScanAdapter:
    meta = _meta

    def run(self, tool_input: ToolInput) -> ToolResult:
        scope = tool_input.scope
        project_root: Path = tool_input.project_root

        excluded_paths = [(project_root / e).resolve() for e in scope.excluded_roots]

        def _is_excluded(path: Path) -> bool:
            return any(path == ex or ex in path.parents for ex in excluded_paths)

        all_packages: list[dict] = []
        for allowed_root in scope.allowed_roots:
            root_path = (project_root / allowed_root).resolve()
            if not root_path.exists():
                continue
            for manifest_path in _find_manifests(root_path):
                if _is_excluded(manifest_path):
                    continue
                parser = _PARSERS.get(manifest_path.name)
                if parser is None:
                    continue
                all_packages.extend(parser(manifest_path))

        matches = vuln_intel.match_packages(all_packages)
        meta = vuln_intel.feed_meta()

        evidence: list[EvidenceRecord] = []
        total_vulns = 0
        highest_priority = 0
        kev_count = 0
        for match in matches:
            vulns = [vuln_intel.vuln_to_dict(v) for v in match.vulns]
            total_vulns += len(vulns)
            highest_priority = max(highest_priority, *(v["priority_score"] for v in vulns))
            kev_count += sum(1 for v in vulns if v["kev"])
            top = vulns[0]
            evidence.append(
                EvidenceRecord(
                    evidence_type="vulnerability_match",
                    title=f"{match.ecosystem}:{match.name} — {len(vulns)} known vulnerability(ies)",
                    summary=(
                        f"{match.name} ({match.version_spec}) matches {len(vulns)} feed record(s); "
                        f"top priority {top['priority_score']} ({top['severity_label']}"
                        f"{', KEV' if top['kev'] else ''})."
                    ),
                    normalized={
                        "ecosystem": match.ecosystem,
                        "package": match.name,
                        "version_spec": match.version_spec,
                        "observed_version": match.observed_version,
                        "manifest_path": match.manifest_path,
                        "vulnerabilities": vulns,
                        "feed": {
                            "feed_id": meta.feed_id,
                            "generated_at": meta.generated_at,
                            "stale": meta.stale,
                            "days_old": meta.days_old,
                        },
                    },
                )
            )

        return ToolResult(
            tool_id=TOOL_ID,
            success=True,
            evidence=evidence,
            output_summary={
                "packages_scanned": len(all_packages),
                "vulnerable_packages": len(matches),
                "total_vulnerabilities": total_vulns,
                "highest_priority": highest_priority,
                "kev_count": kev_count,
                "feed_stale": meta.stale,
                "feed_generated_at": meta.generated_at,
            },
        )


vuln_scan = VulnScanAdapter()
register(vuln_scan)
