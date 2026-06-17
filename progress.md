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

## 2026-06-17

Phase 3 complete. Remaining items built and verified:

- `tools/mcp_config_scan.py` — inventories `.mcp.json`, `mcp.json`, `claude_desktop_config.json`, `.claude/settings.json`; reads `mcpServers` and `servers` keys; captures env key names only (not values)
- `tools/ai_config_scan.py` — inventories Claude, Cursor, Copilot, Aider, Continue, Codex config artifacts
- `tools/secrets_baseline.py` — regex scan for 13 high-confidence secret patterns; captures pattern+line only, never the secret value; 512 KB file cap, 20 findings/file cap, 200 total cap
- Per-adapter timeout: `ThreadPoolExecutor` with `_ADAPTER_TIMEOUT_SECONDS = 30` wraps every adapter execution; timeout surfaces as a failed job, not a 500
- `RunKind` extended with `mcp_config_scan`, `ai_config_scan`, `secrets_baseline`
- No-unsafe-exec tests: AST-based import audit for all 4 adapters (no `subprocess` allowed)
- 26 new tests; all 52 API + 2 Playwright pass

## Current State

Phase 3 is complete. All developer surface scan adapters are built and verified.

## 2026-06-17 (Phase 4)

Phase 4 (Run Orchestration and Evidence Store) built on top of Phase 3.

- Background worker (`orchestrator.py`): a single daemon thread drains a run queue and executes a run's jobs sequentially. Every job still passes the deterministic policy gate (tool risk tier vs scope max), writes a per-job `run` audit event, and runs its adapter in a thread with a 30s wall-clock cap; adapter faults/timeouts are captured as failed jobs, never 500s.
- Multi-job runs: new `baseline` RunKind fans out across all four developer-surface adapters as four jobs under one run. Single-kind runs keep one-job behavior.
- Async + sync contract: `POST /workspaces/{id}/runs` enqueues a run; `wait` (default true) blocks until terminal and returns the full result (preserves the prior synchronous contract and all existing tests), `wait:false` returns a queued snapshot for live UI.
- Cancellation: `POST /runs/{id}/cancel` sets a persisted `cancelling` status + signals the in-process worker; the worker checks before each job and resolves the run to `cancelled`. New `cancelling`/`cancelled` run statuses and `cancelled` job status.
- Live event stream: `run_events` table (atomic monotonic per-run seq, UNIQUE(run_id, seq)) plus `GET /runs/{id}/events` SSE endpoint with client-disconnect and 5-minute ceiling guards.
- Artifact persistence: each terminal run writes a durable JSON snapshot to `data/artifacts/{run_id}.json` (0o600).
- UI: new `/runs` page — start baseline, live progress polling, run history, per-job states, policy-blocked badge, cancel button, evidence drawer joined to jobs by source tool. Nav extended to three pages.
- Reviewed against the safety policy (no new network/subprocess paths, all writes under `data/`, gate intact) and fixed four concurrency issues found in review: two-writer seq race (atomic INSERT...SELECT + UNIQUE), `_done` event-dict leak (pop on finalize), non-deterministic job order (`ORDER BY rowid`), unbounded SSE loop (disconnect + ceiling), and made the adapter timeout non-blocking for the worker.
- Verified: API 59 passed (7 new), web production build passed, Playwright 3 passed (1 new).

## Current State

Phase 4 is complete and verified. Run orchestration, cancellation, live events, artifact persistence, and the Runs/evidence browser are in place.

## 2026-06-17 (Phases 5-7 — MVP)

Built Phases 5, 6, and 7 to reach the portfolio MVP. Everything stays offline and deterministic within the safety envelope (no network, no subprocess, mock AI only).

Phase 5 — Open-data vulnerability intelligence (offline):
- Bundled OSV-style feed at `redcalibur_api/vuln_feed/osv-offline.json` (local file, never network). Vulnerability IDs are only ever emitted from the feed.
- `vuln_intel.py`: feed loader, version matching (introduced <= observed < fixed), explainable 0-100 priority score (severity + known-exploited + exploit-probability, each attributed), and a stale-feed indicator (>90 days).
- `tools/vuln_scan.py`: Tier-1 read-only adapter, reuses manifest parsers, honors `excluded_roots`, emits `vulnerability_match` evidence. New `vuln_scan` RunKind; also added to the `baseline` fan-out (now 5 jobs).

Phase 6 — Evidence-backed AI analyst (mock only, no live calls):
- `ai/providers.py` deterministic `MockProvider`; `ai/gateway.py` validates every claim's citations against real evidence ids (drops + counts ungrounded claims) and redacts secret-shaped text.
- `POST /workspaces/{id}/analyst` with kinds explain_findings / prioritize / remediate / report_section. Enum-only input, so no free-text instruction path to the provider.

Phase 7 — Findings, report export, UI polish:
- `findings.py` derives prioritized findings from evidence (each linked to its evidence id). `GET /workspaces/{id}/findings`.
- `reporting.py` builds deterministic Markdown + HTML assessment reports (summary, prioritized recs with citations, findings table, evidence index, feed-staleness line, Demo/Learning watermark, HTML-escaped). `GET /workspaces/{id}/report?format=md|html`.
- New `/findings` web page: triage table with severity/KEV badges and evidence drawer, AI Analyst panel (cited answers), and report export buttons. Nav now four pages.
- README rewritten with capabilities, demo flow, and safety boundaries.
- Reviewed against the safety policy (no network, mock AI, read-only scans with exclusions honored, citation-grounded analyst, redaction, escaped HTML) — no blockers; applied the two flagged policy-alignment fixes (feed-staleness surfaced in the report, Demo/Learning watermark).
- Verified: API 75 passed (16 new), web production build passed (5 routes), Playwright 4 passed (incl. a workspace→baseline→findings→analyst golden path).

## Current State

MVP complete (Phases 0-7). Workspace/scope/safety spine, developer-surface scans, run orchestration, offline vulnerability intelligence, evidence-backed mock AI analyst, findings triage, and Markdown/HTML report export are all built and verified. Remaining roadmap items (v1 AI security lab, v2 recon-to-report) are future work; any live network/AI source must go behind a Tier-2 policy gate.
