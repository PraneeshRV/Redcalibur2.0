# RedCalibur 2.0 Safety Policy

Status: Draft  
Date: 2026-05-30

## Purpose

RedCalibur 2.0 is a defensive security workbench. It is designed for user-owned projects, local developer environments, intentionally vulnerable labs, and explicitly authorized assessments.

The product should make safe behavior the shortest path.

## Core Principles

1. Scope is required before execution.
2. Read-only collection is the default.
3. Risky actions are gated by deterministic policy, not AI judgment.
4. Evidence is separated from AI interpretation.
5. Reports use defender-first language.
6. Demo mode never touches arbitrary external targets.
7. Prohibited capabilities are absent from the product, not merely hidden.

## Modes

| Mode | Purpose | Network access | Allowed risk |
| --- | --- | --- | --- |
| Demo | portfolio demos, screenshots, local walkthroughs | local fixtures only | Tier 0 |
| Learning | intentionally vulnerable local/lab targets | allowlisted labs only | Tier 0-2 |
| Authorized Assessment | user-owned systems with explicit scope | scoped targets only | Tier 1-3 later |

Mode must be visible in:

- Command Center
- run button
- run preview
- active run banner
- findings
- reports
- audit log

## Risk Tiers

| Tier | Name | Examples | Policy |
| --- | --- | --- | --- |
| 0 | Offline/demo | fixtures, saved scans, toy targets | always allowed in Demo |
| 1 | Passive read-only | local manifest scan, OSV lookup, CVE enrichment, DNS lookup | scope required |
| 2 | Low-impact active | HTTP headers, TLS check, robots/sitemap fetch | explicit consent |
| 3 | Intrusive active | crawling, fuzzing, authenticated checks | defer until post-MVP |
| 4 | Prohibited | exploit execution, credential attacks, stealth, phishing delivery | unavailable |

MVP should ship with Tier 0-1 first. Tier 2 must wait until the target-resolution gate, external target gate, rate limits, and dry-run UX exist.

## Scope Enforcement

Every tool run must pass through the policy engine.

Required checks:

- canonicalize target
- match against allowed roots, domains, URLs, repos, or lab targets
- apply mode restrictions
- apply risk tier restrictions
- apply exclusions
- reject unexpected redirects or discovered third-party targets
- reject private/internal ranges unless explicitly declared
- enforce scan window and request budget
- record the policy version

Policy decision values:

```txt
allowed
blocked
requires_approval
demo_only
```

Each decision should be persisted with the run or audit event.

## External Target Gate

External targets are not allowed in the Product Spine Preview.

Before any post-preview external target checks are implemented, scope declarations for external targets must include:

- scope owner
- assessment purpose
- exact scheme, host, port, and path boundaries where applicable
- assessment window with expiry
- explicit exclusions
- abuse or security contact
- proof-of-control or approval artifact where feasible
- max risk tier
- request budget and rate limit

Expired external scopes must fail closed.

## Target Resolution Requirements

Before any Tier 2 network check exists, target resolution must handle and test:

- DNS rebinding attempts
- CNAMEs resolving to private or loopback addresses
- IPv4 and IPv6 private ranges
- localhost aliases
- encoded IP addresses
- IDNA and punycode domains
- wildcard domain boundaries
- scheme and port mismatches
- redirects to out-of-scope hosts
- cloud metadata endpoints
- proxy environment variables

If resolution cannot be made safely, the decision must be `blocked`.

## Safety Acceptance Fixtures

The Product Spine Preview must include policy tests for:

- allowed local fixture root
- excluded local path
- missing scope
- external URL in Demo mode
- private IP target
- localhost target when not explicitly scoped
- excessive risk tier
- blocked preview creates audit event
- no network execution occurs during preview

## AI Boundaries

AI can:

- summarize evidence
- explain findings
- suggest safe checks
- draft remediation
- generate report sections
- help create regression tests for safe demo/lab targets
- classify findings against OWASP, CWE, CVE, or MITRE ATLAS when evidence exists

AI cannot:

- approve tool execution
- expand scope
- disable limits
- change risk tier
- execute tools directly
- produce weaponized exploit chains
- produce phishing kits
- help collect credentials
- provide stealth, persistence, evasion, or malware instructions

All AI answers must either cite evidence or label the answer as a hypothesis.

## AI App Lab Safety Requirements

AI App Lab execution is deferred until after the Product Spine Preview.

Before any AI App Lab probes run:

- probes must come from an approved static catalog
- demo probes must be inert and local/lab-only
- external egress must be blocked by default
- tool calls must be intercepted and simulated unless explicitly scoped
- live third-party endpoints must be disallowed in Demo mode
- AI must not generate attack payloads for real targets
- transcripts must be treated as untrusted evidence
- tests must prove probes cannot trigger real external actions

## AI Analyst Prompt-Injection Requirements

Before live AI analyst calls:

- all evidence is marked as untrusted data
- evidence cannot modify system or developer instructions
- prompts use strict context separation
- model output cannot expand scope, alter risk tier, or approve actions
- exploit, phishing, credential, stealth, and malware requests are refusal-tested
- adversarial evidence fixtures are included in tests

## Prohibited Product Capabilities

Do not build:

- phishing delivery
- credential capture
- password cracking against real accounts
- exploit execution against real targets
- malware generation
- persistence or evasion tooling
- stealth scanning
- access-control bypass guidance
- rate-limit bypass guidance
- autonomous scanning outside declared scope

## Abuse-Resistant UX

Required UX patterns:

- scope setup before tools
- risk badge on every tool and playbook
- dry-run preview for any networked run
- clear "why blocked" explanations
- safe alternatives when a run is blocked
- report watermarks for Demo and Learning modes
- typed confirmation only for future Tier 3 actions
- no sensational labels or "hack this" language

Preferred language:

- assess
- validate
- evidence
- exposure
- remediation
- verification
- authorized scope
- observed evidence

Avoid:

- weaponize
- compromise
- exploit this
- bypass
- stealth
- own
- exfiltrate

## Audit Events

Minimum fields:

```txt
event_id
workspace_id
user_id
mode
timestamp
policy_version
tool_version
action
target
risk_tier
scope_decision
approval_id
input_summary
redacted_inputs_hash
artifacts_created
findings_created
ai_model
ai_prompt_hash
ai_response_hash
```

Audit logs should be append-only from the app's perspective.

## Report Policy

Reports should include:

- authorization scope
- methodology
- observed evidence
- affected assets
- confidence
- potential impact
- recommended remediation
- safe validation
- limitations
- audit appendix

Reports should not include:

- step-by-step exploitation
- weaponized payloads
- credential capture steps
- stealth instructions
- unsupported severity claims

## Secrets, Artifacts, And Export Handling

Implementation requirements:

- never persist raw secrets when a redacted representation is enough
- redact secrets before AI, reports, and exports
- store raw artifacts under `data/`, which must be gitignored
- use restrictive file permissions for local data where supported
- sanitize workspace exports
- provide retention and delete controls before broader artifact capture
- cap artifact and model-output sizes to avoid accidental data hoarding

## Tool Execution Contract

Before any scanner adapter exists, the runner must enforce:

- no shell interpolation
- fixed argument arrays for subprocesses
- scoped working directory
- stripped or explicit environment variables
- no package-manager script execution
- timeout caps
- output size caps
- declared filesystem permissions
- declared network permissions
- no network access unless the tool permission and policy decision both allow it

## MVP Safety Gate

Before adding scanners:

- policy engine exists
- modes exist
- tool risk tiers exist
- audit event persistence exists
- blocked-target UX exists
- adapter execution contract exists
- safety acceptance fixtures pass

Before adding AI:

- evidence model exists
- citation format exists
- AI gateway exists
- redaction tests exist
- unsupported-claim behavior is defined

Before adding Tier 2 network checks:

- scope matching tests pass
- redirect handling is scoped
- rate limits exist
- dry-run preview exists
- target resolution requirements pass
- external target gate exists

Tier 3 stays behind a post-MVP feature flag.
