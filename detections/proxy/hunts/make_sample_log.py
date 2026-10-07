"""Generate the sample proxy log used by the hunts and their tests.

Deterministic (fixed seed): the same corpus every run, with a planted C2
beacon, a planted exfiltration destination and a deliberately benign
one-person blog, hidden inside ordinary multi-user browsing. Field names
follow the Sigma proxy conventions so the same events exercise both the
Sigma rules and the hunts.

Planted ground truth (what a correct hunt must and must not find):
  * BEACON_HOST  — 120 contacts every ~60 s from one source, python UA:
                   beacon_hunt MUST flag it (regular gaps).
  * EXFIL_HOST   — 20 large uploads from one source, browser UA:
                   rare_domain_hunt MUST flag it (rare + upload-heavy).
  * BLOG_HOST    — one user's personal blog, light traffic:
                   MUST stay quiet at default thresholds (tuning proof).
  * popular hosts — busy and irregular: MUST stay quiet everywhere.
"""

from __future__ import annotations

import argparse
import json
import random

BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) Safari/17.5",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/129.0",
]
POPULAR_HOSTS = [
    "github.com", "google.com", "microsoft.com", "cloud.google.com",
    "zscaler.com", "stackoverflow.com", "office.com", "amazon.in",
]
PATHS = ["/", "/index.html", "/search?q=detection+rules", "/api/v1/items", "/docs"]

BEACON_HOST = "cdn-updates.checkstatus.net"     # planted C2 callback
EXFIL_HOST = "docs-sync.rarebackup.io"          # planted exfil destination
BLOG_HOST = "notes.personalblog.dev"            # planted benign-rare

T0 = 1_760_000_000  # fixed epoch so every run is byte-identical
DURATION = 2 * 60 * 60


def build_events(seed: int = 42) -> list[dict]:
    rng = random.Random(seed)
    events: list[dict] = []

    def add(ts, src, host, method, uri, status, ua, up, down):
        events.append(
            {
                "ts": round(ts, 3),
                "src": src,
                "cs-method": method,
                "cs-host": host,
                "c-uri": uri,
                "sc-status": status,
                "UserAgent": ua,
                "cs-bytes": up,
                "sc-bytes": down,
            }
        )

    # Ordinary browsing: 30 users, bursty irregular gaps, popular hosts.
    for i in range(1, 31):
        src = f"10.20.{(i // 254) % 256}.{i % 254 + 1}"
        for host in rng.sample(POPULAR_HOSTS, 6):
            ts = T0 + rng.uniform(0, DURATION)
            for _ in range(rng.randint(4, 9)):
                add(ts, src, host, "GET", rng.choice(PATHS), 200,
                    rng.choice(BROWSER_UAS), rng.randint(300, 2000),
                    rng.randint(1_000, 200_000))
                ts += rng.uniform(45, 900)  # human-irregular gaps

    # Planted beacon: every ~60 s +- 2 s for two hours, python UA.
    for k in range(120):
        add(T0 + k * 60 + rng.uniform(-2, 2), "10.20.7.66", BEACON_HOST,
            "GET", "/ping", 200, "python-requests/2.31.0", 220, 95)

    # Planted exfil: 20 uploads of ~800 KB under a browser UA.
    for k in range(20):
        add(T0 + 300 + k * 90 + rng.uniform(0, 8), "10.20.9.13", EXFIL_HOST,
            "POST", "/upload", 200, rng.choice(BROWSER_UAS), 800_000, 1_800)

    # Planted benign-rare: one user's blog, light traffic.
    for k in range(12):
        add(T0 + 600 + k * 480 + rng.uniform(0, 60), "10.20.1.7", BLOG_HOST,
            "GET", f"/post/{k + 1}", 200, rng.choice(BROWSER_UAS),
            rng.randint(300, 900), rng.randint(2_000, 40_000))

    events.sort(key=lambda e: e["ts"])
    return events


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out", help="output JSONL path")
    args = parser.parse_args()
    events = build_events()
    with open(args.out, "w", encoding="utf-8") as handle:
        for ev in events:
            handle.write(json.dumps(ev) + "\n")
    print(f"wrote {len(events)} events to {args.out}")


if __name__ == "__main__":
    main()
