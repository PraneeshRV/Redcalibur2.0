"""Prove the hunts find the planted leads and stay quiet on normal traffic.

Ground truth is documented in make_sample_log.py: the beacon and exfil
hosts must be flagged, the popular hosts and the light personal blog must
not be.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "hunts"))

from beacon_hunt import hunt as beacon_hunt, read_events  # noqa: E402
from make_sample_log import (  # noqa: E402
    BEACON_HOST,
    BLOG_HOST,
    EXFIL_HOST,
    POPULAR_HOSTS,
    build_events,
)
from rare_domain_hunt import hunt as rare_hunt, registrable  # noqa: E402


def test_beacon_detected():
    findings = beacon_hunt(build_events())
    hits = [f for f in findings if f["host"] == BEACON_HOST]
    assert hits, "planted beacon not found"
    f = hits[0]
    assert 55 <= f["mean_interval_s"] <= 65  # it really is the 60 s loop
    assert f["jitter"] < 0.25


def test_normal_browsing_not_flagged():
    findings = beacon_hunt(build_events())
    hosts = {f["host"] for f in findings}
    for host in POPULAR_HOSTS:
        assert host not in hosts, f"beacon hunt fired on popular host {host}"


def test_exfil_and_rare_domain_detected():
    findings = {f["domain"]: f for f in rare_hunt(build_events())}
    exfil_dom = registrable(EXFIL_HOST)
    assert exfil_dom in findings, "planted exfil domain not found"
    reasons = " ".join(findings[exfil_dom]["reasons"])
    assert "rare" in reasons and "upload-heavy" in reasons


def test_quiet_on_tuned_benign_rare():
    """The one-person blog stays below the volume thresholds on purpose."""
    findings = {f["domain"] for f in rare_hunt(build_events())}
    assert registrable(BLOG_HOST) not in findings
    for host in POPULAR_HOSTS:
        assert registrable(host) not in findings


def test_registrable_domain():
    assert registrable("cdn-updates.checkstatus.net") == "checkstatus.net"
    assert registrable("a.b.corp.com") == "corp.com"
    assert registrable("localhost") == "localhost"


def test_read_events_roundtrip(tmp_path):
    events = build_events()
    path = tmp_path / "proxy.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    assert read_events(str(path)) == events
