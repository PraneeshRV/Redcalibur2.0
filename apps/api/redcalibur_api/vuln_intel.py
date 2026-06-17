"""Offline vulnerability intelligence.

Matches a package inventory against a bundled, offline OSV-style feed and
produces a normalized, explainable result. There is no network access — the
feed ships with the package and is read from disk only. Vulnerability IDs are
only ever surfaced from the feed, so the analyst layer can never hallucinate an
ID that is not grounded in feed data.

The priority score is deterministic and fully explainable: every point is
attributed to a named input (severity, known-exploited, exploit-probability,
fix-availability) so a reviewer can see exactly why something ranks high.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

_FEED_PATH = Path(__file__).resolve().parent / "vuln_feed" / "osv-offline.json"

# A feed older than this is flagged stale so reviewers don't trust it blindly.
_STALE_AFTER_DAYS = 90

_VERSION_RE = re.compile(r"(\d+(?:\.\d+){0,3})")


@dataclass(frozen=True)
class FeedRecord:
    id: str
    aliases: list[str]
    ecosystem: str
    package: str
    summary: str
    details: str
    severity_cvss: float
    severity_label: str
    cwe: list[str]
    kev: bool
    epss: float
    fixed_version: str | None
    introduced: str
    references: list[str]
    published: str
    last_modified: str


@dataclass
class FeedMeta:
    feed_id: str
    generated_at: str
    stale: bool
    days_old: int


@dataclass
class MatchedVuln:
    record: FeedRecord
    priority_score: int
    priority_breakdown: dict[str, int]


@dataclass
class PackageMatch:
    ecosystem: str
    name: str
    version_spec: str
    observed_version: str | None
    manifest_path: str
    vulns: list[MatchedVuln] = field(default_factory=list)


def feed_path() -> Path:
    return _FEED_PATH


@lru_cache(maxsize=1)
def _load_raw_feed() -> dict:
    return json.loads(_FEED_PATH.read_text(encoding="utf-8"))


def load_records() -> list[FeedRecord]:
    raw = _load_raw_feed()
    records: list[FeedRecord] = []
    for item in raw.get("vulnerabilities", []):
        ranges = item.get("affected_ranges") or [{}]
        introduced = str(ranges[0].get("introduced", "0"))
        records.append(
            FeedRecord(
                id=item["id"],
                aliases=list(item.get("aliases", [])),
                ecosystem=item["ecosystem"],
                package=item["package"],
                summary=item.get("summary", ""),
                details=item.get("details", ""),
                severity_cvss=float(item.get("severity_cvss", 0.0)),
                severity_label=item.get("severity_label", "unknown"),
                cwe=list(item.get("cwe", [])),
                kev=bool(item.get("kev", False)),
                epss=float(item.get("epss", 0.0)),
                fixed_version=item.get("fixed_version"),
                introduced=introduced,
                references=list(item.get("references", [])),
                published=item.get("published", ""),
                last_modified=item.get("last_modified", ""),
            )
        )
    return records


def feed_meta(now: datetime | None = None) -> FeedMeta:
    raw = _load_raw_feed()
    generated_at = raw.get("generated_at", "")
    now = now or datetime.now(UTC)
    days_old = 0
    try:
        gen = datetime.fromisoformat(generated_at)
        days_old = max(0, (now - gen).days)
    except ValueError:
        days_old = 10**6  # unparseable timestamp => treat as very stale
    return FeedMeta(
        feed_id=raw.get("feed_id", "unknown"),
        generated_at=generated_at,
        stale=days_old > _STALE_AFTER_DAYS,
        days_old=days_old,
    )


def _parse_version(text: str | None) -> tuple[int, ...] | None:
    if not text:
        return None
    match = _VERSION_RE.search(text)
    if not match:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    length = max(len(a), len(b))
    a = a + (0,) * (length - len(a))
    b = b + (0,) * (length - len(b))
    return (a > b) - (a < b)


def _is_affected(observed: tuple[int, ...] | None, introduced: str, fixed: str | None) -> bool:
    """A version is affected when introduced <= observed < fixed.

    If we cannot parse the observed version we conservatively treat the package
    as potentially affected (a reviewer can dismiss it) rather than hiding it.
    """
    if observed is None:
        return True
    intro = _parse_version(introduced) or (0,)
    if _cmp(observed, intro) < 0:
        return False
    fixed_v = _parse_version(fixed)
    if fixed_v is not None and _cmp(observed, fixed_v) >= 0:
        return False
    return True


def priority_score(record: FeedRecord) -> tuple[int, dict[str, int]]:
    """Deterministic, explainable 0-100 priority.

    severity: up to 50 (cvss/10 * 50)
    known-exploited (KEV): +30
    exploit probability (EPSS): up to 20 (epss * 20)
    fix available: +0 (informational; absence does not lower urgency)
    """
    severity = round(record.severity_cvss / 10.0 * 50)
    kev = 30 if record.kev else 0
    epss = round(record.epss * 20)
    breakdown = {
        "severity": severity,
        "known_exploited": kev,
        "exploit_probability": epss,
    }
    total = min(100, severity + kev + epss)
    return total, breakdown


def match_packages(packages: list[dict]) -> list[PackageMatch]:
    """Match a list of manifest package dicts against the offline feed.

    ``packages`` is the shape produced by the manifest scan adapter
    (ecosystem, name, version_spec, manifest_path, ...).
    """
    records = load_records()
    by_key: dict[tuple[str, str], list[FeedRecord]] = {}
    for rec in records:
        by_key.setdefault((rec.ecosystem, rec.package.lower()), []).append(rec)

    matches: list[PackageMatch] = []
    for pkg in packages:
        ecosystem = pkg.get("ecosystem", "")
        name = pkg.get("name", "")
        version_spec = pkg.get("version_spec", "")
        observed = _parse_version(version_spec)
        candidates = by_key.get((ecosystem, name.lower()), [])
        matched: list[MatchedVuln] = []
        for rec in candidates:
            if _is_affected(observed, rec.introduced, rec.fixed_version):
                score, breakdown = priority_score(rec)
                matched.append(MatchedVuln(record=rec, priority_score=score, priority_breakdown=breakdown))
        if matched:
            matched.sort(key=lambda m: m.priority_score, reverse=True)
            matches.append(
                PackageMatch(
                    ecosystem=ecosystem,
                    name=name,
                    version_spec=version_spec,
                    observed_version=".".join(str(p) for p in observed) if observed else None,
                    manifest_path=pkg.get("manifest_path", ""),
                    vulns=matched,
                )
            )
    matches.sort(key=lambda m: max((v.priority_score for v in m.vulns), default=0), reverse=True)
    return matches


def vuln_to_dict(matched: MatchedVuln) -> dict:
    rec = matched.record
    return {
        "id": rec.id,
        "aliases": rec.aliases,
        "summary": rec.summary,
        "details": rec.details,
        "severity_cvss": rec.severity_cvss,
        "severity_label": rec.severity_label,
        "cwe": rec.cwe,
        "kev": rec.kev,
        "epss": rec.epss,
        "fixed_version": rec.fixed_version,
        "fix_available": rec.fixed_version is not None,
        "references": rec.references,
        "priority_score": matched.priority_score,
        "priority_breakdown": matched.priority_breakdown,
    }
