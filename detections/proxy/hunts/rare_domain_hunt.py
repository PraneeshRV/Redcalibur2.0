"""Hunt: rare domains and upload-heavy destinations (exfil-shaped traffic).

Least-frequency-of-observation: count a field across the whole org and the
rare values are the leads. Popular domains are seen by many users; a domain
seen by exactly one source — especially one that source uploads a lot to —
is either someone's personal cloud or data leaving the building.

Two independent signals, reported with their reasons so an analyst can tune:
  * rare     — the registrable domain was contacted by only one source, at
               volume (many requests or many bytes uploaded)
  * upload-heavy — uploads (cs-bytes, client to server) dwarf downloads
               (sc-bytes) at real volume; browsers pull, they do not push

The registrable-domain cut is naive (last two labels): fine for a hunt lead,
not a complete public-suffix implementation. Say that out loud if asked.
"""

from __future__ import annotations

import argparse

from beacon_hunt import read_events

MIN_EVENTS_FOR_RARE = 50        # a one-user domain must also be busy to matter
MIN_UPLOAD_BYTES_FOR_RARE = 10_000_000  # ...or move real volume (10 MB)
EXFIL_MIN_UPLOAD = 5_000_000    # upload-heavy needs at least 5 MB up ...
EXFIL_RATIO = 10                # ... and 10x more up than down


def registrable(host: str) -> str:
    """Naive registrable domain: the last two labels (a.b.corp.com -> corp.com)."""
    labels = host.rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def hunt(events: list[dict]) -> list[dict]:
    per_domain: dict[str, dict] = {}
    for ev in events:
        host = ev.get("cs-host")
        if not host:
            continue
        dom = registrable(str(host))
        agg = per_domain.setdefault(
            dom, {"srcs": set(), "contacts": 0, "cs_bytes": 0, "sc_bytes": 0}
        )
        agg["srcs"].add(ev.get("src"))
        agg["contacts"] += 1
        agg["cs_bytes"] += int(ev.get("cs-bytes") or 0)
        agg["sc_bytes"] += int(ev.get("sc-bytes") or 0)

    findings = []
    for dom, agg in per_domain.items():
        reasons = []
        if len(agg["srcs"]) <= 1 and (
            agg["contacts"] >= MIN_EVENTS_FOR_RARE
            or agg["cs_bytes"] >= MIN_UPLOAD_BYTES_FOR_RARE
        ):
            reasons.append("rare: one source, high volume")
        if (
            agg["cs_bytes"] >= EXFIL_MIN_UPLOAD
            and agg["sc_bytes"] > 0
            and agg["cs_bytes"] / agg["sc_bytes"] >= EXFIL_RATIO
        ):
            reasons.append("upload-heavy: 10x more bytes up than down")
        if reasons:
            findings.append(
                {
                    "domain": dom,
                    "sources": sorted(s for s in agg["srcs"] if s),
                    "contacts": agg["contacts"],
                    "cs_bytes_up": agg["cs_bytes"],
                    "sc_bytes_down": agg["sc_bytes"],
                    "reasons": reasons,
                }
            )
    findings.sort(key=lambda f: -f["cs_bytes_up"])
    return findings


def _fmt(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", help="proxy log as JSONL")
    args = parser.parse_args()

    for f in hunt(read_events(args.log)):
        srcs = ", ".join(f["sources"])
        print(
            f"{f['domain']:<34}{srcs:<14}{f['contacts']:>6} contacts  "
            f"up={_fmt(f['cs_bytes_up']):>9}  down={_fmt(f['sc_bytes_down']):>9}  "
            f"[{'; '.join(f['reasons'])}]"
        )


if __name__ == "__main__":
    main()
