# Product Spine Preview Plan

Status: Draft for approval  
Date: 2026-05-30

## Goal

Create the smallest working RedCalibur 2.0 spine that proves local startup, workspace creation, scope declaration, policy decisions, blocked-run UX, and audit persistence.

This is not the full MVP. It is the safety and product foundation that makes the MVP buildable.

## Locked Architecture

- Web: Next.js in `apps/web`
- API: FastAPI in `apps/api`
- Database: SQLite at `data/redcalibur.db`
- Artifacts: project-local `data/` tree
- Seed workspace: `RedCalibur Demo - AI Coding Stack`
- Scope: local fixtures only
- AI: mock provider only, no live model calls
- Reports: deferred
- Scanners: deferred
- Network target checks: deferred

## Stop Line

Stop when the blocked-target demo works.

Do not add:

- scanner execution
- live AI provider calls
- OSV/CVE/KEV/EPSS integrations
- report export
- live run workers
- external network target checks

## Implementation Tasks

### 1. Scaffold Repo Foundation

Create:

- root workspace config
- `apps/web`
- `apps/api`
- one root dev command
- basic README instructions

Acceptance:

- one command starts web and API
- API health endpoint returns OK
- web app loads Command Center route

### 2. Add Backend Persistence

Create SQLite persistence for:

- `Workspace`
- `ScopeDeclaration`
- `AuditEvent`

Acceptance:

- migrations run on a fresh DB
- migrations run safely on an already-migrated DB
- seed data appears after setup

### 3. Define Domain Contracts

Define backend models and API schemas for:

- mode: Demo, Learning, Authorized Assessment
- risk tier: 0, 1, 2, 3, 4
- target type: local path, URL, domain, IP, repo/package placeholder
- policy decision: allowed, blocked, requires_approval, demo_only
- workspace
- scope declaration
- audit event
- run preview request/response

Acceptance:

- OpenAPI schema exposes the contracts
- frontend uses typed responses or generated/synchronized types

### 4. Seed Demo Workspace

Seed:

```txt
Workspace: RedCalibur Demo - AI Coding Stack
Mode: Demo
Allowed root: fixtures/demo-ai-stack/
Excluded root: fixtures/demo-ai-stack/secrets/
Authorization: Demo-only local fixture workspace for RedCalibur planning and UI validation.
Max risk tier: 1
```

Acceptance:

- seed workspace appears in API
- seed workspace appears in UI
- scope status reads as configured

### 5. Implement Policy Engine

Support:

- local-root allow matching
- exclusions overriding allowed roots
- missing scope rejection
- Demo-mode arbitrary network rejection
- max risk tier enforcement
- clear decision reasons
- policy version in every response

Acceptance tests:

- allowed local fixture returns `allowed`
- excluded local path returns `blocked`
- missing scope returns `blocked`
- external URL in Demo mode returns `blocked`
- private IP target returns `blocked`
- localhost target not explicitly scoped returns `blocked`
- excessive risk tier returns `blocked`

### 6. Add Workspace And Scope APIs

Endpoints:

- `GET /health`
- `GET /workspaces`
- `GET /workspaces/{id}`
- `POST /workspaces`
- `GET /workspaces/{id}/scope`
- `PUT /workspaces/{id}/scope`
- `POST /workspaces/{id}/run-preview`
- `GET /workspaces/{id}/audit-events`

Acceptance:

- invalid scope is rejected with a useful error
- valid scope is persisted
- run preview returns decision, reasons, and policy version

### 7. Add Audit Event Persistence

Every run preview request writes an audit event.

Event includes:

- workspace ID
- mode
- action
- target
- risk tier
- decision
- policy version
- input summary
- redacted input hash
- timestamp

Acceptance:

- allowed previews create audit events
- blocked previews create audit events
- audit history is visible through API
- app API has no delete route for audit events

### 8. Build Minimal Operator UI

Screens:

- Command Center
- Scopes

Command Center shows:

- workspace name
- mode
- scope status
- max risk tier
- latest policy preview
- latest audit events

Scopes page shows:

- mode
- allowed roots
- exclusions
- authorization text
- run preview form

Run Preview form:

- target input
- risk tier selector
- preview button
- decision badge
- reason list

Acceptance:

- reviewer can see the seed workspace
- reviewer can preview an allowed local path
- reviewer can preview an external URL and see a blocked reason
- latest audit event appears after preview

### 9. Verification Suite

Backend:

- health test
- migration idempotency test
- policy unit tests
- scope API tests
- audit persistence tests

Frontend:

- route smoke test
- Playwright test for seed workspace
- Playwright test for blocked external URL preview

Static checks:

- no scanner adapter execution exists
- no live AI provider call exists
- no report generation path exists
- no network target check path exists

Acceptance:

- all tests pass locally
- Product Spine Preview demo is repeatable from a clean checkout

## Definition Of Done

The Product Spine Preview is done when:

- local dev startup works
- seeded demo workspace appears
- scope policy returns correct decisions
- blocked previews persist audit events
- UI clearly explains blocked targets
- tests verify the above
- no scanner, AI, report, or network execution has slipped in

