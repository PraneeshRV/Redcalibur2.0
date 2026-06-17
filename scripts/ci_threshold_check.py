#!/usr/bin/env python3
"""CI threshold gate.

Runs the offline vulnerability and AI-eval adapters in-process against the seeded
demo workspace, derives findings, and exits non-zero if the number of critical
or known-exploited (KEV) findings exceeds the configured thresholds. No network,
no running server — it imports the adapters directly.

Usage:
    python scripts/ci_threshold_check.py --max-critical 0 --max-kev 0
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

# Use a throwaway data dir so the gate never touches the project database.
os.environ.setdefault("REDCALIBUR_DATA_DIR", tempfile.mkdtemp(prefix="redcalibur-ci-"))

# Ensure the package is importable when run from the repo root.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps" / "api"))

from redcalibur_api import db  # noqa: E402
from redcalibur_api.findings import derive_findings  # noqa: E402
from redcalibur_api.models import EvidenceItem  # noqa: E402
from redcalibur_api.tools import ai_eval as _ai_eval  # noqa: E402,F401 — registers
from redcalibur_api.tools import vuln_scan as _vuln_scan  # noqa: E402,F401 — registers
from redcalibur_api.tools.registry import ToolInput, get as get_tool  # noqa: E402

_TOOLS = ["redcalibur.vuln_intel.vuln_scan", "redcalibur.ai_lab.ai_eval"]


def collect_findings():
    db.initialize_database()
    scope = db.get_scope(db.DEMO_WORKSPACE_ID)
    evidence: list[EvidenceItem] = []
    for tool_id in _TOOLS:
        adapter = get_tool(tool_id)
        if adapter is None:
            continue
        result = adapter.run(
            ToolInput(workspace_id=db.DEMO_WORKSPACE_ID, scope=scope, project_root=ROOT, params={})
        )
        for rec in result.evidence:
            evidence.append(
                EvidenceItem(
                    id=db.new_id(),
                    workspace_id=db.DEMO_WORKSPACE_ID,
                    run_id="ci",
                    source_tool=tool_id,
                    evidence_type=rec.evidence_type,
                    title=rec.title,
                    summary=rec.summary,
                    normalized=rec.normalized,
                    collected_at=db.utc_now(),
                )
            )
    return derive_findings(db.DEMO_WORKSPACE_ID, evidence)


def main() -> int:
    parser = argparse.ArgumentParser(description="RedCalibur CI threshold gate")
    parser.add_argument("--max-critical", type=int, default=0)
    parser.add_argument("--max-kev", type=int, default=0)
    args = parser.parse_args()

    findings = collect_findings()
    critical = sum(1 for f in findings if f.severity_label == "critical")
    kev = sum(1 for f in findings if f.kev)

    print(f"Findings: {len(findings)} total | critical={critical} | kev={kev}")
    print(f"Thresholds: max_critical={args.max_critical} max_kev={args.max_kev}")

    failed = False
    if critical > args.max_critical:
        print(f"FAIL: {critical} critical finding(s) exceeds threshold {args.max_critical}")
        failed = True
    if kev > args.max_kev:
        print(f"FAIL: {kev} KEV finding(s) exceeds threshold {args.max_kev}")
        failed = True

    if failed:
        return 1
    print("PASS: thresholds satisfied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
