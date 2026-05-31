# RedCalibur 2.0 Demo Script

Status: Draft  
Date: 2026-05-30

## Demo Goal

Show RedCalibur as a serious, safe, AI-era security workbench in five minutes.

The demo should prove:

- it is scoped and authorized
- it is read-only by default
- it finds modern developer and AI-app exposure
- every finding has evidence
- AI helps without inventing facts
- the workflow ends in remediation and reportable proof

## Demo Narrative 1: Secure My AI Coding Stack

Best first public demo.

### Setup

Workspace:

```txt
RedCalibur Demo - AI Coding Stack
```

Mode:

```txt
Demo
```

Scope:

```txt
fixtures/demo-ai-stack/
fixtures/demo-dev-configs/
```

### Story

1. Open Command Center.
2. Show Demo mode and local-only scope.
3. Click Run Baseline.
4. Live events appear:
   - reading manifests
   - inventorying packages
   - checking MCP configs
   - checking AI tool configs
   - enriching package vulnerabilities
   - generating candidate findings
5. Developer Surface fills with packages, configs, and extensions.
6. Open a finding:
   - vulnerable package with OSV/CVE evidence
   - over-permissive MCP config
   - risky AI tool environment variable pattern
7. Ask AI Analyst: "What should I fix first?"
8. AI returns a cited priority answer.
9. Accept one finding.
10. Export a Markdown report.

### Reviewer Takeaway

RedCalibur understands the modern developer machine and turns messy local state into security decisions.

## Demo Narrative 2: Break And Harden An AI Agent

Best v1 demo after AI App Lab exists.

### Setup

Workspace:

```txt
RedCalibur Demo - Support Agent Lab
```

Mode:

```txt
Learning
```

Target:

```txt
local demo chatbot with tools and memory
```

### Story

1. Open AI App Lab.
2. Show target adapter and allowed local endpoint.
3. Run prompt injection and unsafe tool-use suite.
4. Results show:
   - prompt injection transcript
   - unsafe tool call attempt
   - data boundary failure
5. RedCalibur maps results to OWASP GenAI categories.
6. AI Analyst drafts remediation:
   - tool allowlist
   - untrusted content boundaries
   - confirmation before external actions
7. Toggle demo app to patched mode.
8. Re-run tests.
9. Show before/after risk drop.
10. Export report with transcripts and verification.

### Reviewer Takeaway

RedCalibur does not just find AI risks. It converts them into repeatable regression tests and proof of improvement.

## Demo Narrative 3: From Repo To Report

Best later B-direction demo.

### Setup

Workspace:

```txt
RedCalibur Demo - Repo Assessment
```

Mode:

```txt
Authorized Assessment
```

Scope:

```txt
local vulnerable repo
localhost demo web app
```

### Story

1. Create workspace.
2. Declare scope and authorization.
3. Run passive assessment.
4. Assets appear:
   - packages
   - local service
   - HTTP headers
   - TLS or local transport state
5. Findings appear with evidence and open-data enrichment.
6. Triage false positive vs accepted finding.
7. Show remediation checklist.
8. Re-run verification.
9. Export professional assessment report.

### Reviewer Takeaway

RedCalibur can grow from the A-first workbench into a professional recon-to-report platform.

## Visual Tone For Demo

Use:

- active workspace immediately visible
- compact dashboard
- evidence panels
- live event timeline
- risk and confidence chips
- report preview

Avoid:

- marketing landing page
- exaggerated hacking language
- empty dashboard
- fake terminal theatrics

## Five-Minute Timing

```txt
0:00 - 0:30   Open Command Center and explain mode/scope
0:30 - 1:20   Run baseline and show live evidence
1:20 - 2:20   Review Developer Surface and one finding
2:20 - 3:20   Ask AI Analyst for cited priority
3:20 - 4:20   Show remediation and verification path
4:20 - 5:00   Export report and summarize roadmap
```

## First Demo Data To Build

Fixtures:

- `demo-ai-stack/package.json`
- `demo-ai-stack/package-lock.json`
- `demo-ai-stack/mcp.json`
- `demo-ai-stack/ai-config.json`
- `demo-ai-stack/prompts/support-agent.md`
- `demo-ai-stack/reports/expected-report.md`

Seed findings:

- vulnerable dependency
- over-permissive MCP server config
- prompt injection susceptibility
- missing tool confirmation boundary

Seed evidence:

- package manifest record
- OSV vulnerability match
- MCP config record with redacted env
- AI lab transcript
- verification pass/fail result
