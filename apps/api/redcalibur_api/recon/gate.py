"""v2 recon gate.

v2 (recon-to-report) introduces scoped domain/URL recon and active network
checks. The safety policy explicitly defers all Tier-2+ network execution until
the target-resolution gate, external-target gate, rate limits, and dry-run UX
exist. None of those are built yet, so network recon is hard-disabled here. This
module is the single chokepoint: when the prerequisites land, flipping this flag
(plus implementing the gated checks) is the only enabling step.
"""

from __future__ import annotations

# Hard-off. Do not flip until the Tier-2 prerequisites in the safety policy are
# implemented and reviewed.
NETWORK_RECON_ENABLED = False

_DEFERRED_REASON = (
    "Network recon (Tier 2+) is deferred by the RedCalibur safety policy until the "
    "target-resolution gate, external-target gate, rate limits, and dry-run preview "
    "exist. Only local, offline asset-graph construction is available today."
)


def network_recon_enabled() -> bool:
    return NETWORK_RECON_ENABLED


def deferred_reason() -> str:
    return _DEFERRED_REASON
