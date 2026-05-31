# RedCalibur 2.0 Design Spec

Status: Draft for user review  
Date: 2026-05-30  
Decision: Build A first, then grow into B.

## One-Line Direction

RedCalibur 2.0 should become a local-first AI security and developer exposure workbench: it scans the modern builder surface, creates evidence-backed findings, helps verify and fix issues, and exports professional reports.

## Product Thesis

The original RedCalibur was an AI-assisted red-team and OSINT toolkit. RedCalibur 2.0 should keep the ambition and name, but rebuild the center of gravity around safety, evidence, and verification.

The moat is not "more scanners." The moat is a defensible evidence engine:

- explicit authorization and scope before every run
- read-only local and project exposure checks by default
- AI app and agent security labs
- open vulnerability intelligence with provenance
- findings that cite artifacts instead of vibes
- fix recommendations with repeatable verification
- polished reports that a reviewer, recruiter, or security lead can trust

Project Glasswing and Claude Mythos suggest frontier models will make vulnerability discovery faster. The bottleneck becomes triage, verification, disclosure, remediation, and proof. RedCalibur should own that bottleneck for solo builders, students, open-source maintainers, and small teams.

## Strategic Shape

### A First: AI Security + Developer Exposure Workbench

This is the first build.

It focuses on the security surfaces modern AI builders actually carry:

- code repositories and lockfiles
- dependencies and package metadata
- IDE and editor extensions
- browser extensions used in developer workflows
- MCP servers and local AI tool configs
- prompts, agent tools, RAG surfaces, and model endpoints
- demo AI apps and intentionally vulnerable labs
- evidence, findings, remediation, regression tests, and reports

Why this first:

- It is more distinctive than another recon dashboard.
- It is safer and more portfolio-friendly than exploit tooling.
- It fits the 2026 AI security wave.
- It gives RedCalibur a unique identity before growing wider.

### B Later: Recon-to-Report Security Console

This is the platform expansion.

It grows RedCalibur into a broader professional assessment console:

- authorized target scopes
- passive recon
- safe low-impact active checks
- asset inventory
- vulnerability enrichment
- finding lifecycle
- team workflow
- repeat assessments
- report templates
- integrations

The first product should be built so B can emerge naturally, but B should not steal focus from the A-first MVP.

## Lessons From Old RedCalibur

Keep:

- the RedCalibur identity
- the security workbench ambition
- AI-assisted analysis
- report generation
- a broad tool catalog
- a learner-friendly feel

Replace:

- one-off subprocess route handlers
- raw string outputs
- wildcard CORS
- no authorization model
- duplicated frontend stacks
- exploit/payload/phishing framing
- AI claims that are not tied to evidence

Reframe old features:

| Old idea | RedCalibur 2.0 version |
| --- | --- |
| Exploits | Exploit intelligence, impact summaries, safe validation |
| Payload generator | Safe test inputs for local labs and non-destructive checks |
| Phishing | Offline awareness simulator only, no credential capture |
| Password tools | Credential hygiene and policy checks |
| Vulnerability scan | Evidence-based findings with confidence and remediation |

## Primary Users

1. Builder securing their own AI project  
   Wants to know what is risky in their repo, local AI tooling, dependencies, and agent design.

2. Student or portfolio builder  
   Wants an impressive, safe, demoable project that shows security maturity.

3. Open-source maintainer  
   Wants dependency and configuration exposure, reportable findings, and remediation guidance.

4. Small team operator  
   Wants a lightweight alternative to heavy enterprise tooling for scoped assessments and report generation.

## MVP Workflow

The MVP should make one golden path excellent:

1. Open RedCalibur locally.
2. Choose mode: Demo, Learning, or Authorized Assessment.
3. Create a workspace.
4. Define scope: local repo, demo app, AI target, allowed data sources.
5. Preview what RedCalibur will read and what it will not do.
6. Run a baseline read-only assessment.
7. Watch live run events as evidence appears.
8. Review assets, evidence, and candidate findings.
9. Ask the AI analyst what matters first, with citations.
10. Accept or reject findings.
11. Generate a Markdown or HTML report.
12. Re-run after a fix and show before/after verification.

## Product Pillars

### 1. Scope Before Scan

Every assessment starts with a scope declaration. RedCalibur should know the mode, purpose, allowed targets, exclusions, risk tier, and authorization text before tools run.

### 2. Read-Only By Default

The default product reads metadata and evidence. It should not execute untrusted package code, exploit targets, collect credentials, or perform stealth behavior.

### 3. Evidence Is The Source Of Truth

Every finding links to evidence. AI commentary is useful, but it is not evidence.

### 4. AI As Analyst, Not Autopilot

AI can summarize, prioritize, explain, draft remediation, and generate reports. Deterministic policy decides what can run.

### 5. Fix Then Prove

The product should not stop at "you have a problem." It should help produce a fix plan, verification step, regression check, and reportable proof.

### 6. Demo Mode Is A First-Class Product

A safe, offline demo workspace should always exist. It is how the project can be shown without touching real targets.

## MVP Feature Set

### Command Center

First screen after app launch. Shows current workspace, mode, scope status, active runs, latest findings, stale data warnings, and next actions.

### Scope And Safety

- mode selection
- workspace purpose
- allowed local roots and demo targets
- target exclusions
- risk tier labels
- run approval preview
- audit events

### Developer Surface Scan

Read-only inventory and exposure checks:

- package manifests and lockfiles
- npm, pnpm, Yarn, Bun, PyPI, Go, RubyGems, Composer
- MCP JSON host configs
- AI CLI and local agent configs where feasible
- editor extension manifests
- browser extension manifests if explicitly enabled
- secrets baseline check with redacted evidence

### AI App Lab

Controlled tests for demo or user-owned AI systems:

- prompt injection checks
- data leakage checks
- unsafe tool-use checks
- excessive agency checks
- RAG retrieval boundary tests
- regression tests from accepted findings

### Open Data Intelligence

MVP sources:

- OSV.dev for package vulnerability matching
- CVE/cvelistV5 for canonical vulnerability records
- NVD for enriched vulnerability metadata where available
- CISA KEV for known-exploited signal
- FIRST EPSS for exploit probability
- CWE/CVSS for classification and severity context

The UI must expose source, fetched time, staleness, and conflicts.

### Findings

Findings should have:

- title
- category
- severity
- confidence
- affected assets
- evidence links
- source tools
- open data links
- remediation
- safe validation
- status: candidate, accepted, false positive, fixed, verified

### AI Analyst

The AI analyst should:

- answer only from stored evidence unless clearly marked as a hypothesis
- cite evidence IDs
- explain priority
- draft remediation
- summarize runs
- generate report sections
- refuse unsupported or unsafe requests

### Reports

MVP report exports:

- Markdown first
- HTML second
- PDF later if the stack makes it simple

Report sections:

- scope and authorization
- methodology
- executive summary
- confirmed findings
- rejected or unresolved candidates
- evidence appendix
- remediation plan
- verification results
- audit appendix

## Safety Policy

### Modes

| Mode | Purpose | Network | Allowed risk |
| --- | --- | --- | --- |
| Demo | portfolio demos and screenshots | local fixtures only | Tier 0 |
| Learning | intentionally vulnerable labs | allowlisted lab targets | Tier 0-2 |
| Authorized Assessment | user-owned systems | scoped external network | Tier 1-3 later |

### Risk Tiers

| Tier | Name | Examples | MVP status |
| --- | --- | --- | --- |
| 0 | Offline/demo | fixtures, saved scans, toy apps | enabled |
| 1 | Passive read-only | manifest scan, OSV lookup, DNS, CVE enrichment | enabled |
| 2 | Low-impact active | HTTP headers, TLS check, robots/sitemap | defer until target-resolution gate passes |
| 3 | Intrusive active | crawling, fuzzing, authenticated checks | defer |
| 4 | Prohibited | exploit execution, credential attacks, stealth, phishing delivery | never |

### Hard Boundaries

RedCalibur 2.0 should not ship:

- phishing kits
- credential collection
- password cracking against real accounts
- malware, droppers, persistence, or evasion
- stealth scanning
- exploit weaponization
- autonomous unscoped internet scanning
- bypasses for access controls or rate limits

## Architecture Summary

Start as a modular monolith:

```txt
apps/
  web/                 Next.js operator console
  api/                 FastAPI backend
packages/
  core/                domain models, scope policy, risk scoring
  tools/               scanner and adapter registry
  ai/                  provider abstraction and analyst logic
  intel/               OSV, CVE, KEV, EPSS, advisory ingestion
  reports/             Markdown/HTML report generation
  plugins/             extension manifests and SDK contracts
data/
  redcalibur.db        local SQLite database
  artifacts/           evidence, logs, reports, screenshots
```

SQLite and local filesystem storage are enough for MVP. Keep internal boundaries clean so Postgres, remote workers, object storage, collaboration, and hosted deployment can arrive later.

## UX Direction

RedCalibur should feel like an operator console, not a marketing site.

Use:

- dense tables
- split panes
- drawers
- filters
- status chips
- live event timelines
- evidence viewers
- restrained colors
- readable mono text for logs, versions, hashes, and paths

Avoid:

- cyberpunk theatrics
- giant hero sections
- fake terminals as decoration
- purple gradient AI magic
- tool button grids without workflow
- unsupported claims

Primary navigation:

- Command Center
- Scopes
- Developer Surface
- AI App Lab
- Findings
- Evidence
- Reports
- Knowledge Base
- Settings and Safety

## MVP Success Criteria

RedCalibur 2.0 MVP is successful when a reviewer can see this in under five minutes:

- create a workspace
- declare scope
- run a read-only baseline scan
- watch evidence appear
- review a dependency/config/AI-lab finding
- ask AI for cited prioritization
- export a professional report
- re-run after a simulated fix

## First Shippable Slice: Product Spine Preview

Before the full MVP, build a smaller Product Spine Preview.

Goal:

Prove that RedCalibur can start locally, create a workspace, declare scope, evaluate a run request through deterministic policy, block unsafe or out-of-scope work, and persist an audit trail.

Locked choices for this slice:

- stack: Next.js web app plus FastAPI backend
- database: project-local SQLite at `data/redcalibur.db`
- storage: project-local `data/artifacts/`, `data/reports/`, `data/cache/`
- first demo workspace: `RedCalibur Demo - AI Coding Stack`
- first demo scope: local fixture roots only
- first AI provider: mock provider only, no live model calls
- first report target: no reports yet; Markdown-only when reports begin
- first safety posture: no scanner execution, no network checks, no AI App Lab execution

Preview acceptance criteria:

- one command starts web and API
- API health endpoint returns OK
- migrations run cleanly on fresh and already-migrated databases
- seed demo workspace is visible in UI and API
- scope declaration can be viewed and edited
- run preview for an allowed local fixture returns `allowed`
- run preview for an external URL in Demo mode returns `blocked`
- run preview above workspace max risk tier returns `blocked`
- every preview persists an audit event
- Command Center shows current mode, scope status, and latest audit events
- there is no code path that executes scanners, calls live AI providers, or performs network target checks

This slice is not the full MVP. It is the foundation that makes the MVP credible.

## Non-Goals For MVP

- multi-user SaaS
- billing
- remote scanning agents
- exploit execution
- credential attacks
- phishing automation
- distributed workers
- plugin marketplace
- autonomous pentesting
- internet-scale recon
- advanced graph database

## Locked First-Slice Decisions

1. Frontend/backend split: Next.js plus FastAPI.
2. First demo target: `Secure My AI Coding Stack`, using local fixtures.
3. AI providers: provider abstraction later, mock provider first.
4. Local storage path: project-local `data/` during development.
5. Report export: Markdown-only when report work starts; no reports in the Product Spine Preview.
6. Network checks: none in the Product Spine Preview.

## Later Decisions

These remain open for post-preview planning:

1. Whether to add Anthropic, OpenAI, local, or OpenAI-compatible providers first after mock AI.
2. Whether HTML export arrives before or after the AI Analyst.
3. Which package ecosystems follow the first npm fixture.
4. When to introduce `~/.redcalibur/` user-home storage.
5. Whether Tier 2 checks belong in MVP or v1.

## Approval Checkpoint

Recommended approval:

Build the first implementation plan around the Product Spine Preview:

- app foundation
- local database
- workspace model
- safety modes
- scope declaration
- empty operator console
- audit log spine
- blocked run preview

Do not add scanners or AI until the product spine exists.
