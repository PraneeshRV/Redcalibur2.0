# RedCalibur 2.0 Progress

## 2026-05-30

- Explored local workspace; it started empty and not a git repository.
- Inspected old `PraneeshRV/RedCalibur` repository remotely.
- Researched modern AI security, developer exposure, open vulnerability data, and frontier security tooling.
- Spawned research/planning agents for architecture, roadmap, safety, UX, innovation, and reviews.
- Created visual companion screen at `http://localhost:63390`.
- Created planning package:
  - `PROJECT.md`
  - `docs/README.md`
  - `docs/superpowers/specs/2026-05-30-redcalibur-2-design.md`
  - `docs/research/redcalibur-2-research-digest.md`
  - `docs/architecture/redcalibur-2-blueprint.md`
  - `docs/planning/redcalibur-2-roadmap.md`
  - `docs/planning/redcalibur-2-safety-policy.md`
  - `docs/planning/redcalibur-2-demo-script.md`
  - `docs/planning/product-spine-preview-plan.md`
  - `docs/superpowers/plans/2026-05-30-product-spine-preview.md`
- Tightened plan after review:
  - named Product Spine Preview as first slice
  - locked Next.js + FastAPI + SQLite
  - deferred scanners, live AI, reports, open data, and network checks
  - added safety gates and acceptance fixtures

## Current State

Implementation approved on 2026-05-31.

## 2026-05-31

- Initialized Git repository and switched to `product-spine-preview`.
- Committed planning package as baseline commit `2ce401b`.
- Started Product Spine Preview implementation.
- Implemented FastAPI API, SQLite persistence, policy preview, audit events, and Next.js operator console.
- Added `POST /workspaces`, durable scope updates, Demo-mode network target blocks, redacted audit display targets, and README setup instructions after review findings.
- Installed npm dependencies, Python API virtualenv dependencies, and Playwright Chromium runtime.
- Verified with `npm run test`: API 13 passed, production web build passed, Playwright 2 passed.
- Stop-line search found only frontend calls to the local RedCalibur API.

## Current State

Product Spine Preview is implemented and verified.

## 2026-06-13

- Started Phase 3 (Tool Registry and Developer Surface Scan) on top of the Product Spine.
- Added Run/Job/EvidenceItem models, SQLite tables, and CRUD.
- Added a tool registry + adapter contract and the read-only Manifest Scan adapter
  (package.json, pyproject.toml, requirements.txt, Cargo.toml, go.mod; pure-Python, no subprocess, no network).
- Added run endpoints: `POST /workspaces/{id}/runs`, `GET /workspaces/{id}/runs`, `GET /runs/{id}`.
- Added a Developer Surface web page with multi-page nav (Command Center + Developer Surface).
- Verification against the safety policy found and fixed three gaps before declaring done:
  - run endpoint now passes through a deterministic policy gate (tool risk tier vs scope max) and writes a `run` audit event;
  - manifest scan now honors `excluded_roots` (will not read manifests under excluded paths such as `secrets/`);
  - adapter faults are captured as failed job/run results instead of surfacing a 500.
- Verified: API 26 passed, web production build passed, Playwright 2 passed.

## Phase 3 Remaining (not yet built)

Still required to fully close Phase 3:

- MCP config inventory adapter
- AI config inventory adapter
- redacted secrets baseline check
- per-adapter timeout/output caps + cancellation
- "no unsafe command execution" test for the adapter execution contract
