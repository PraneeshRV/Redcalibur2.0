from datetime import UTC, datetime

from redcalibur_api import vuln_intel


def test_feed_loads_and_only_known_ids():
    records = vuln_intel.load_records()
    assert len(records) >= 3
    ids = {r.id for r in records}
    assert "OSV-DEMO-2025-0001" in ids
    # Every record id is a feed id (no invented ids).
    assert all(r.id.startswith("OSV-DEMO-") for r in records)


def test_match_demo_packages_produces_expected_hits():
    packages = [
        {"ecosystem": "npm", "name": "demo-vulnerable-package", "version_spec": "1.0.0", "manifest_path": "x"},
        {"ecosystem": "pypi", "name": "requests", "version_spec": "requests>=2.28.0", "manifest_path": "y"},
        {"ecosystem": "pypi", "name": "anthropic", "version_spec": "anthropic>=0.25.0", "manifest_path": "z"},
    ]
    matches = vuln_intel.match_packages(packages)
    by_name = {m.name: m for m in matches}
    # npm demo package is vulnerable (1.0.0 < fixed 1.2.0).
    assert "demo-vulnerable-package" in by_name
    # requests matches two feed records.
    assert len(by_name["requests"].vulns) == 2
    # anthropic has no feed records => no match.
    assert "anthropic" not in by_name


def test_version_above_fixed_is_not_affected():
    packages = [
        {"ecosystem": "npm", "name": "demo-vulnerable-package", "version_spec": "1.5.0", "manifest_path": "x"},
    ]
    matches = vuln_intel.match_packages(packages)
    # 1.5.0 >= fixed 1.2.0 => not affected.
    assert matches == []


def test_priority_score_is_explainable_and_kev_boosted():
    records = {r.id: r for r in vuln_intel.load_records()}
    critical = records["OSV-DEMO-2025-0001"]  # cvss 9.8, kev true, epss 0.74
    score, breakdown = vuln_intel.priority_score(critical)
    assert breakdown["known_exploited"] == 30
    assert breakdown["severity"] == 49  # round(9.8/10*50)
    assert breakdown["exploit_probability"] == 15  # round(0.74*20)
    assert score == min(100, 49 + 30 + 15)
    assert score == 94


def test_stale_feed_flag():
    # Feed generated 2026-06-01; from far in the future it is stale.
    future = datetime(2027, 1, 1, tzinfo=UTC)
    meta = vuln_intel.feed_meta(now=future)
    assert meta.stale is True
    assert meta.days_old > 90
    # Right after generation it is fresh.
    fresh = vuln_intel.feed_meta(now=datetime(2026, 6, 2, tzinfo=UTC))
    assert fresh.stale is False
