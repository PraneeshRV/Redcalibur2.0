# RedCalibur 2.0 Planning Index

This folder contains the first planning package for the RedCalibur revamp.

## Read In This Order

1. [Design Spec](superpowers/specs/2026-05-30-redcalibur-2-design.md)
2. [Research Digest](research/redcalibur-2-research-digest.md)
3. [Architecture Blueprint](architecture/redcalibur-2-blueprint.md)
4. [Roadmap](planning/redcalibur-2-roadmap.md)
5. [Safety Policy](planning/redcalibur-2-safety-policy.md)
6. [Demo Script](planning/redcalibur-2-demo-script.md)

## Current Decision

The project should start as an AI Security + Developer Exposure Workbench and later grow into a Recon-to-Report Security Platform.

## Implementation Boundary

The next planning step should cover the Product Spine Preview only. Do not start scanners, AI analyst features, reports, network checks, or open-data integrations until the app foundation, workspace model, scope policy, blocked-preview UX, and audit spine exist.

## Product Spine Preview

Locked first slice:

- Next.js plus FastAPI
- project-local SQLite in `data/`
- seed workspace: `RedCalibur Demo - AI Coding Stack`
- local fixture scope only
- deterministic policy preview
- blocked preview audit events
- minimal Command Center and Scopes UI
- no scanner execution
- no live AI calls
- no network target checks
