"""Analyst gateway.

Sits between the API and a provider. Its job is to keep the analyst honest and
safe regardless of which provider produced the claims:

- citation validation: every claim must cite at least one evidence id that
  actually exists in the considered evidence set; claims that cite unknown ids
  (i.e. ungrounded / hallucinated) are dropped and counted;
- redaction: claim text is scrubbed of anything resembling a secret before it
  leaves the system, as a defense in depth (evidence itself never carries
  secret values, but the analyst must never reintroduce one).

The gateway never executes tools, expands scope, or disables limits — per the
safety policy's AI boundaries.
"""

from __future__ import annotations

import re

from redcalibur_api.ai.providers import AnalystProvider, MockProvider
from redcalibur_api.models import (
    AnalystClaim,
    AnalystQuestionKind,
    AnalystResponse,
    EvidenceItem,
)

# Defensive redaction patterns for secret-shaped tokens.
_REDACTION_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}\b"),
    re.compile(r"\b[A-Fa-f0-9]{40,}\b"),
]


def redact(text: str) -> str:
    for pattern in _REDACTION_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def analyze(
    kind: AnalystQuestionKind,
    evidence: list[EvidenceItem],
    provider: AnalystProvider | None = None,
) -> AnalystResponse:
    provider = provider or MockProvider()
    valid_ids = {item.id for item in evidence}

    headline, raw_claims = provider.generate(kind, evidence)

    accepted: list[AnalystClaim] = []
    unsupported = 0
    for claim in raw_claims:
        cited = [eid for eid in claim.evidence_ids if eid in valid_ids]
        if not cited:
            # No grounding => reject (ungrounded/hallucinated claim).
            unsupported += 1
            continue
        accepted.append(AnalystClaim(text=redact(claim.text), evidence_ids=cited))

    citations = sorted({eid for claim in accepted for eid in claim.evidence_ids})
    return AnalystResponse(
        kind=kind,
        headline=redact(headline),
        claims=accepted,
        citations=citations,
        provider=provider.name,
        evidence_considered=len(evidence),
        unsupported_rejected=unsupported,
    )
