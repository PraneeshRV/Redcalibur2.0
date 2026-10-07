"""Replay three shipped rules against real attack captures.

The .evtx files under tools/evtx_samples are real attack samples from
sbousseaden/EVTX-ATTACK-SAMPLES (see SOURCES.md there). Each replay must
find at least one true positive — the rule fires on real telemetry, not
only on hand-written vectors. Skipped automatically when python-evtx or
the samples are absent, so the suite stays hermetic.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

evtx = pytest.importorskip("Evtx.Evtx")  # noqa: F841  (python-evtx)

HERE = Path(__file__).resolve().parents[1]
SAMPLES = HERE / "tools" / "evtx_samples"
SIGMA = HERE / "sigma"

REPLAYS = [
    ("dcsync_ntds.yml", "CA_DCSync_4662.evtx"),
    ("lsass_credential_access.yml", "sysmon_10_lsass_mimikatz_logonpasswords.evtx"),
    ("pass_the_hash.yml", "LM_4624_mimikatz_pth_source.evtx"),
]


@pytest.mark.parametrize("rule_file,evtx_file", REPLAYS)
def test_rule_fires_on_real_attack_capture(rule_file, evtx_file):
    evtx_path = SAMPLES / evtx_file
    if not evtx_path.exists():
        pytest.skip(f"sample not present: {evtx_file}")
    from evtx_replay import replay

    total, hits, _ = replay(str(SIGMA / rule_file), str(evtx_path))
    assert total > 0, f"{evtx_file} yielded no records"
    assert hits > 0, f"{rule_file} did not fire on real capture {evtx_file}"
