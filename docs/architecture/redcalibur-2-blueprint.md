# RedCalibur 2.0 Architecture Blueprint

Status: Draft  
Date: 2026-05-30

## Architecture Principle

RedCalibur should be a local evidence machine. Tools collect defensible facts, AI helps interpret them, and the user gets a clean path from exposure discovery to remediation and reportable proof.

## MVP Shape

Use a modular monolith first:

```txt
apps/
  web/                 Next.js operator console
  api/                 FastAPI backend
packages/
  core/                domain models, policy, scoring
  tools/               tool registry and adapters
  ai/                  providers, analyst, eval helpers
  intel/               vulnerability data ingestion
  reports/             report rendering
  plugins/             manifest schema and extension SDK
data/
  redcalibur.db        SQLite database
  artifacts/           raw evidence, logs, exports
```

Why:

- easy to run locally
- strong portfolio demo
- clear service boundaries without distributed complexity
- can grow into Postgres and worker services later

## Bounded Contexts

### Workspace And Scope

Owns:

- workspaces
- modes
- authorization declarations
- allowed targets
- exclusions
- risk tiers
- policy snapshots

Primary rule:

No tool runs without a scope decision.

### Developer Exposure

Owns read-only inventory of:

- repos
- lockfiles
- installed package metadata
- editor extensions
- browser extensions
- MCP configs
- AI tool configs
- secrets-adjacent configuration

### AI Security Lab

Owns:

- AI app targets
- prompt injection tests
- tool-use tests
- RAG leakage tests
- guardrail regression tests
- probe/detector result normalization

### Asset Inventory

Normalizes:

- repositories
- packages
- configs
- endpoints
- domains
- prompts
- models
- tools
- MCP servers
- evidence-linked components

### Job Execution

Owns:

- runs
- jobs
- queue
- cancellations
- retries
- timeouts
- live events

### Evidence

Owns:

- raw artifacts
- normalized records
- hashes
- provenance
- timestamps
- source tool version
- evidence-to-finding links

### Findings

Owns:

- deduplication
- severity
- confidence
- status
- affected assets
- remediation
- safe validation
- lifecycle history

### AI Analyst

Owns:

- provider routing
- redaction
- prompt templates
- citation enforcement
- evidence-grounded answers
- report section drafts

### Reports

Owns:

- Markdown reports
- HTML reports
- evidence appendices
- audit appendices
- future PDF rendering

### Extensions

Owns:

- scanner plugin contracts
- intel connector contracts
- AI eval pack contracts
- report template contracts
- permission declarations

## Core Data Model

MVP tables:

```txt
Workspace(
  id, name, mode, purpose, created_at, updated_at
)

ScopeDeclaration(
  id, workspace_id, mode, allowed_roots_json, allowed_targets_json,
  excluded_targets_json, max_risk_tier, authorization_text,
  policy_version, created_at
)

Asset(
  id, workspace_id, type, name, uri, fingerprint,
  metadata_json, first_seen_at, last_seen_at
)

Run(
  id, workspace_id, kind, status, requested_by,
  policy_snapshot_json, started_at, finished_at
)

Job(
  id, run_id, tool_id, status, input_json, output_summary_json,
  error, started_at, finished_at
)

RunEvent(
  id, run_id, job_id, level, message, payload_json, created_at
)

EvidenceItem(
  id, workspace_id, run_id, asset_id, source_tool,
  evidence_type, title, summary, raw_artifact_uri,
  normalized_json, hash, confidence, collected_at
)

Finding(
  id, workspace_id, title, category, severity, confidence,
  status, affected_asset_ids_json, evidence_ids_json,
  remediation, safe_validation, ai_summary,
  created_at, updated_at
)

VulnerabilityIntel(
  id, source, external_id, aliases_json, severity_json,
  affected_json, references_json, exploit_signal_json,
  fetched_at, provenance_json
)

Report(
  id, workspace_id, title, format, artifact_uri,
  included_findings_json, generated_at
)

AuditEvent(
  id, workspace_id, user_id, mode, action, target,
  risk_tier, scope_decision, policy_version,
  input_summary, redacted_inputs_hash,
  artifacts_created_json, created_at
)
```

Use SQLite JSON columns for MVP. Migrate to Postgres when team features, hosted mode, or heavier search become necessary.

## Run Flow

```txt
User starts run
-> API validates workspace and scope
-> policy engine returns scope decision
-> Run record is created
-> Jobs are created from selected playbook
-> local worker executes adapters
-> adapters emit events, artifacts, evidence
-> normalizers update assets and findings
-> intel layer enriches with OSV/CVE/KEV/EPSS
-> AI analyst optionally drafts cited summaries
-> UI streams progress and updates views
```

## Tool Registry

Each tool adapter should declare:

```yaml
id: redcalibur.developer_surface.manifest_scan
name: Manifest Scan
version: 0.1.0
risk_tier: 1
inputs:
  - local_root
outputs:
  - evidence.package_inventory
  - asset.package
permissions:
  filesystem:
    - read_scoped_roots
  network: []
timeouts:
  default_seconds: 30
```

Adapter contract:

```txt
validate(input, scope) -> ValidationResult
run(input, context) -> ToolResult
normalize(result) -> Assets + Evidence + CandidateFindings
```

MVP first-party adapters:

- repo manifest scan
- dependency inventory
- OSV dependency lookup
- MCP config inventory
- AI config inventory
- secrets baseline scanner with redaction
- prompt injection demo test
- unsafe tool-use demo test

## Policy Engine

Policy checks:

- normalize target
- match against allowed scope
- apply mode restrictions
- apply risk tier restrictions
- block private/internal ranges unless explicitly declared
- block third-party redirects and discovered targets unless approved
- enforce rate and request limits
- attach policy snapshot to run

Decisions:

```txt
allowed
blocked
requires_approval
demo_only
```

## AI Gateway

All model calls go through one gateway.

Responsibilities:

- provider selection
- redaction
- prompt template selection
- system safety policy injection
- evidence packaging
- citation requirements
- response validation
- prompt and response hashes in audit logs

MVP providers:

- mock provider for tests
- OpenAI provider
- Anthropic provider
- local/OpenAI-compatible provider later or optional

AI tasks:

- summarize run
- explain finding
- prioritize remediation
- draft report sections
- suggest safe validation
- generate AI-lab test cases for demo targets

AI cannot:

- approve its own actions
- expand scope
- disable limits
- execute tools directly
- generate weaponized exploit steps
- create phishing or credential theft flows

## Evidence Model

Evidence must separate raw artifacts from normalized summaries.

Rules:

- raw artifact is stored on disk
- normalized record is stored in DB
- each artifact has a hash
- each item records source tool and version
- each finding links to one or more evidence items
- AI commentary is stored separately from evidence
- stale or missing data is visible

Example:

```json
{
  "evidence_type": "dependency_vulnerability",
  "source_tool": "osv_dependency_lookup",
  "asset": "npm:example-package@1.2.3",
  "normalized": {
    "package": "example-package",
    "version": "1.2.3",
    "vulnerability_ids": ["GHSA-example", "CVE-2026-0000"],
    "fixed_versions": ["1.2.4"]
  }
}
```

## Local Storage

Development default:

```txt
data/
  redcalibur.db
  artifacts/
  reports/
  cache/
  logs/
```

User install default later:

```txt
~/.redcalibur/
  redcalibur.db
  artifacts/
  reports/
  cache/
  plugins/
  logs/
```

Workspace export:

```txt
workspace-export.zip
  workspace.json
  db-snapshot.sqlite
  artifacts/
  reports/
```

## UI Architecture

Frontend pages:

- Command Center
- Scopes
- Developer Surface
- AI App Lab
- Assets
- Runs
- Findings
- Evidence
- Reports
- Knowledge Base
- Settings and Safety

Frontend primitives:

- compact tables
- split panes
- status chips
- risk badges
- timeline/event stream
- evidence drawer
- finding detail panels
- report preview

## MVP Testing Strategy

Unit:

- scope matcher
- policy engine
- risk scoring
- adapter contracts
- evidence normalization
- report rendering

Integration:

- create workspace
- declare scope
- start run
- emit events
- persist artifacts
- create finding
- generate report

AI:

- mock provider golden outputs
- citation coverage checks
- unsupported-claim rejection
- redaction tests

Frontend:

- golden path Playwright test
- empty/loading/error states
- visual smoke checks

## Later Platform Upgrades

When growing into B:

- Postgres
- remote workers
- Redis/RQ, Celery, or Temporal
- scheduled scans
- collaboration and RBAC
- asset graph
- attack-path view
- GitHub/Jira/Slack/DefectDojo integrations
- signed evidence bundles
- plugin sandboxing
- hosted deployment

