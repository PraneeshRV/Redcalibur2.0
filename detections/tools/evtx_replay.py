"""Replay a Sigma rule against a real Windows event log (.evtx) file.

This is the bridge between the synthetic test vectors and real telemetry:
each EVTX record is parsed into the flat field dict the evaluator expects
(EventID from the System channel, everything else from EventData), and the
rule's own matching logic decides hit or miss. A rule that only fires on
hand-written vectors has not met a real log format yet; this closes that
gap for true positives.

Quiet-side testing stays on synthetic vectors on purpose: these samples are
attack captures, so they prove catches, not silence.

Usage:
    python evtx_replay.py --rule ../sigma/kerberoasting.yml \
        --evtx evtx_samples/CA_DCSync_4662.evtx
"""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evaluator import load_rule, matches  # noqa: E402


def evtx_records(path: str):
    """Yield one flat event dict per EVTX record."""
    from Evtx.Evtx import Evtx  # python-evtx keeps its class in a submodule

    with Evtx(path) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
            except ET.ParseError:
                continue
            # Windows event XML uses a default namespace; drop it so plain
            # find("System") / find("EventData") work.
            for el in root.iter():
                if isinstance(el.tag, str) and "}" in el.tag:
                    el.tag = el.tag.split("}", 1)[1]
            event = {}
            sys_el = root.find("System")
            if sys_el is None:
                continue
            eid = sys_el.find("EventID")
            if eid is not None and eid.text:
                event["EventID"] = int(eid.text)
            data_el = root.find("EventData")
            if data_el is not None:
                for data in data_el.findall("Data"):
                    name = data.get("Name")
                    if name and data.text:
                        event[name] = data.text
            yield event


def replay(rule_path: str, evtx_path: str) -> tuple[int, int, list[dict]]:
    """Return (total_records, matches, sample_matches)."""
    rule = load_rule(rule_path)
    total = hits = 0
    samples: list[dict] = []
    for event in evtx_records(evtx_path):
        total += 1
        if matches(rule, event):
            hits += 1
            if len(samples) < 3:
                samples.append(event)
    return total, hits, samples


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rule", required=True, help="Sigma rule .yml")
    parser.add_argument("--evtx", required=True, help="Windows event log .evtx")
    args = parser.parse_args()

    total, hits, samples = replay(args.rule, args.evtx)
    name = Path(args.rule).stem
    print(f"{name} vs {Path(args.evtx).name}: {hits}/{total} records matched")
    for s in samples:
        trimmed = {k: s[k] for k in list(s)[:6]}
        print(f"  e.g. {trimmed}")


if __name__ == "__main__":
    main()
