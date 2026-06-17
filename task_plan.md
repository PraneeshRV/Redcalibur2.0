# RedCalibur 2.0 Task Plan

Status: MVP complete (Phases 0-7) — implemented and verified.

## Goal

Revamp RedCalibur into an A-first AI Security + Developer Exposure Workbench that later grows into a B-style Recon-to-Report platform.

## Phases

| Phase | Status | Output |
| --- | --- | --- |
| Explore old RedCalibur and modern market | complete | research digest |
| Brainstorm product directions | complete | visual companion and design spec |
| Define architecture and safety spine | complete | architecture blueprint and safety policy |
| Define roadmap and first implementation slice | complete | roadmap and Product Spine Preview plan |
| User review and approval | complete | user said to proceed |
| Implementation | complete | Product Spine Preview |

## Current Decision

Build A first:

```txt
AI Security + Developer Exposure Workbench
```

Grow into B later:

```txt
Recon-to-Report Security Platform
```

## First Slice

Product Spine Preview:

- Next.js plus FastAPI
- project-local SQLite
- seed demo workspace
- local fixture scope only
- deterministic policy preview
- blocked-preview UX
- audit persistence
- no scanners
- no live AI
- no reports
- no network target checks

## Next Step

MVP shipped. Future work is v1 (AI security lab: prompt-injection / RAG-leakage / unsafe-tool-use suites, finding lifecycle, CI, Docker) and v2 (recon-to-report). Any live network or AI source must sit behind a Tier-2 policy gate per the safety policy.
