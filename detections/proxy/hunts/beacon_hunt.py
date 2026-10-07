"""Hunt: C2 beaconing — regular contact intervals per (source, destination).

Why a hunt and not a Sigma rule: a signature asks a question about ONE event
("is this user agent curl?"). Beaconing is a question about a TIME SERIES
("does this pair talk at regular intervals?"), which no per-event rule
language can express. That is the practical line between detection and
hunting, and this module is the hunting side of it.

Method: group proxy events by (src, host), compute the gaps between
consecutive contacts, and flag pairs whose gaps are regular (low jitter =
stdev/mean) over a long enough window. Human browsing is bursty and
irregular; callbacks to an operator's loop are not.
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict

# Tuning knobs: defensible defaults, not magic.
MIN_CONTACTS = 20        # a pair must have at least this many contacts
MIN_INTERVALS = 10       # ...yielding at least this many gaps
MAX_JITTER = 0.25        # stdev/mean of gaps; humans are way noisier
MIN_SPAN_SECONDS = 1800  # the regularity must persist at least 30 minutes


def read_events(path: str) -> list[dict]:
    events = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def hunt(events: list[dict], max_jitter: float = MAX_JITTER) -> list[dict]:
    """Return beacon findings for every (src, host) pair with regular gaps."""
    by_pair: dict[tuple, list[float]] = defaultdict(list)
    for ev in events:
        by_pair[(ev.get("src"), ev.get("cs-host"))].append(float(ev["ts"]))

    findings = []
    for (src, host), stamps in by_pair.items():
        if len(stamps) < MIN_CONTACTS:
            continue
        stamps.sort()
        gaps = [b - a for a, b in zip(stamps, stamps[1:])]
        if len(gaps) < MIN_INTERVALS:
            continue
        span = stamps[-1] - stamps[0]
        mean = statistics.mean(gaps)
        if mean <= 0 or span < MIN_SPAN_SECONDS:
            continue
        jitter = statistics.pstdev(gaps) / mean
        if jitter <= max_jitter:
            findings.append(
                {
                    "src": src,
                    "host": host,
                    "contacts": len(stamps),
                    "mean_interval_s": round(mean, 1),
                    "jitter": round(jitter, 4),
                    "span_s": round(span, 1),
                }
            )
    findings.sort(key=lambda f: f["jitter"])
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", help="proxy log as JSONL")
    parser.add_argument("--max-jitter", type=float, default=MAX_JITTER)
    args = parser.parse_args()

    findings = hunt(read_events(args.log), max_jitter=args.max_jitter)
    if not findings:
        print("no beaconing candidates")
        return
    print(f"{'SRC':<14}{'HOST':<36}{'CONTACTS':>8}{'MEAN(s)':>9}{'JITTER':>8}")
    for f in findings:
        print(
            f"{f['src']:<14}{f['host']:<36}{f['contacts']:>8}"
            f"{f['mean_interval_s']:>9}{f['jitter']:>8}"
        )


if __name__ == "__main__":
    main()
