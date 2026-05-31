# RedCalibur 2.0 Roadmap

Status: Draft  
Date: 2026-05-30

## North Star

RedCalibur 2.0 is a safe, local-first AI security workbench that helps builders discover, understand, fix, verify, and report security exposure across code, dependencies, AI tools, agents, and scoped targets.

## MVP Definition

MVP is complete when RedCalibur can:

- create a workspace
- declare a safety mode and scope
- run a read-only baseline assessment
- collect structured evidence
- enrich at least one dependency/config finding with open data
- explain findings through an evidence-backed AI analyst
- export a professional Markdown or HTML report
- support a safe offline demo workflow

## First Shippable Slice: Product Spine Preview

This comes before the full MVP.

Goal:

Create the smallest visible RedCalibur that proves the product spine:

- local app startup
- workspace model
- safety modes
- scope declaration
- deterministic policy decisions
- blocked run preview
- audit persistence
- minimal Command Center and Scopes UI

Locked slice choices:

- stack: Next.js plus FastAPI
- DB: project-local SQLite
- storage: project-local `data/`
- demo: `RedCalibur Demo - AI Coding Stack`
- scope: local fixtures only
- AI: mock provider only, no live calls
- reports: deferred
- scanners: deferred
- network target checks: deferred

Slice acceptance criteria:

- one command starts web and API
- health endpoint returns OK
- migrations are idempotent
- seed workspace appears in UI and API
- allowed local fixture preview returns `allowed`
- external URL in Demo mode returns `blocked`
- excessive risk tier returns `blocked`
- blocked previews create audit events
- audit events are visible in Command Center
- no scanner, live AI, report, or network execution path exists

Stop line:

End this slice once the blocked-target demo works. Do not continue into scanners, AI, open data, reports, or live workers during the same implementation plan.

## Phase 0: Product Spine

Goal: Freeze the product shape before code.

Deliverables:

- design spec
- architecture blueprint
- safety policy
- roadmap
- visual direction
- demo script

Acceptance criteria:

- A-first direction is explicit.
- B-later expansion path is explicit.
- MVP workflow is one coherent golden path.
- non-goals and safety boundaries are documented.

Demo checkpoint:

- Walk through docs and visual companion without code.

## Phase 1: App Foundation

Goal: Create the empty product shell.

Deliverables:

- monorepo scaffold
- Next.js operator console
- FastAPI backend
- SQLite database and migrations
- local artifact directories
- API health route
- seed demo workspace

Acceptance criteria:

- one command starts local dev
- UI loads Command Center
- API health check passes
- migrations run cleanly
- demo workspace appears

Tests:

- frontend boot smoke test
- API health test
- migration test
- basic Playwright route test

Defer:

- scanners
- AI provider calls
- report export
- multi-user auth

## Phase 2: Scope, Safety, And Audit Spine

Goal: Make authorization central from day one.

Deliverables:

- mode selector: Demo, Learning, Authorized Assessment
- workspace purpose and authorization text
- allowed roots/targets and exclusions
- risk tier model
- policy engine
- audit event table
- run preview and blocked-target UI

Acceptance criteria:

- Demo mode cannot touch arbitrary internet targets.
- Out-of-scope targets are blocked.
- Every run request creates an audit event.
- Tool metadata includes risk tier before any tool is executable.

Tests:

- scope matching unit tests
- policy decision tests
- API rejection tests
- audit persistence tests

Demo checkpoint:

- Try to scan an out-of-scope target and show RedCalibur refusing it clearly.

## Phase 3: Tool Registry And Developer Surface Scan

Goal: Replace old one-off tools with a safe adapter system.

Deliverables:

- tool registry
- adapter contract
- local worker loop
- repo manifest scan
- dependency inventory
- MCP config inventory
- AI config inventory
- redacted secrets baseline check
- structured evidence output

Acceptance criteria:

- tools run only through registry and policy
- every tool emits typed JSON evidence
- failures are captured as job results
- raw strings are not the product contract

Tests:

- adapter contract tests
- fixture parser tests
- timeout/cancellation tests
- no unsafe command execution tests

Demo checkpoint:

- Run baseline against a demo repo and watch package/config evidence appear.

## Phase 4: Run Orchestration And Evidence Store

Goal: Make RedCalibur feel alive and reliable.

Deliverables:

- run queue
- job states
- live event stream
- cancellation
- artifact persistence
- evidence browser
- run history

Acceptance criteria:

- one assessment can run multiple jobs
- UI shows live progress
- cancellation works
- every finding links to evidence

Tests:

- worker integration tests
- state transition tests
- artifact persistence tests
- Playwright live-run test

Demo checkpoint:

- Start, cancel, restart, and complete a baseline run.

## Phase 5: Open-Data Vulnerability Intelligence

Goal: Turn inventory into useful security context.

Deliverables:

- OSV integration
- CVE/cvelistV5 ingestion or lookup
- NVD enrichment where available
- CISA KEV enrichment
- FIRST EPSS enrichment
- normalized vulnerability model
- explainable priority score
- stale-source indicators

Acceptance criteria:

- package evidence maps to known vulnerabilities
- priority score shows its inputs
- stale and missing data are visible
- no hallucinated vulnerability IDs

Tests:

- source fixture tests
- conflicting data tests
- scoring tests
- offline cache tests

Demo checkpoint:

- Scan a deliberately vulnerable dependency and show enriched priority.

## Phase 6: Evidence-Backed AI Analyst

Goal: Add AI where it helps without becoming the source of truth.

Deliverables:

- AI gateway
- mock provider
- OpenAI and/or Anthropic provider
- evidence citation format
- finding explanation
- remediation drafting
- prioritized "what should I fix first" answer
- report section generation

Acceptance criteria:

- AI output cites evidence IDs
- unsupported claims are rejected or marked as hypotheses
- unsafe requests are refused
- tests run deterministically with mock provider

Tests:

- golden prompt tests
- citation coverage checks
- unsupported-claim tests
- redaction tests

Demo checkpoint:

- Ask "What should I fix first?" and get a cited, prioritized answer.

## Phase 7: Portfolio MVP Polish

Goal: Make the first public version impressive.

Deliverables:

- Command Center polish
- Developer Surface page
- Runs page
- Findings triage
- Evidence drawer
- AI Analyst panel
- Markdown/HTML report export
- demo data
- README
- demo video script

Acceptance criteria:

- reviewer understands product in five minutes
- full demo works offline or against fixtures
- report export looks professional
- UI feels like an operator console

Tests:

- full Playwright golden path
- report snapshot tests
- visual smoke tests
- accessibility pass for primary flows

Demo checkpoint:

- Create workspace -> run assessment -> review finding -> ask AI -> export report -> show verification.

## v1: AI Security Lab And Professional Workflow

Deliverables:

- AI app target model
- prompt injection suites
- RAG leakage suites
- unsafe tool-use suites
- regression tests from findings
- fix verification
- CI integration
- Dockerized release
- finding lifecycle: open, accepted, false positive, fixed, verified

Acceptance criteria:

- user can test a demo AI app
- eval results become evidence-backed findings
- fixes can be retested
- CI can fail on configured thresholds

## v2: Recon-To-Report Platform

Deliverables:

- scoped domain and URL recon
- safe active checks
- asset graph
- attack-path view
- scheduled monitoring
- collaboration and roles
- integrations with GitHub, Jira, Slack, DefectDojo-style exports
- plugin SDK
- report templates
- optional hosted mode

Acceptance criteria:

- repeated assessments show before/after posture
- teams can assign and track findings
- plugins can be added without changing orchestration
- graph explains assets, evidence, vulnerabilities, and fixes

## Explicit Deferrals

Do not build before MVP:

- exploit execution
- credential attacks
- phishing delivery
- stealth/evasion tooling
- autonomous internet-scale scanning
- SaaS billing
- distributed scanning
- plugin marketplace
- automated patch PRs
- browser exploitation chains

## Recommended First Implementation Plan

Plan only the Product Spine Preview first.

Reason:

The project needs a strong spine before scanners, AI, and open-data intelligence. App foundation, workspace model, scope enforcement, safety modes, blocked-preview UX, and audit logs make everything later safer and cleaner.

## Product Spine Preview Execution Matrix

| Area | Must-have artifact | Exit criteria |
| --- | --- | --- |
| App startup | root dev command | web and API reachable |
| Persistence | SQLite DB and migrations | fresh and repeated migration pass |
| Seed data | demo workspace and local fixture scope | visible in UI and API |
| Policy | scope decision engine | allowed local, blocked external, blocked high-risk tests pass |
| Audit | append-only audit table/API | preview requests persist visible events |
| UI | Command Center, Scopes, Run Preview | reviewer can see blocked run reason |
| Stop line | no scanner/AI/report execution | code search confirms no execution path |
