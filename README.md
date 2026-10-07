# RedCalibur 2.0

RedCalibur 2.0 is a local-first AI security and developer exposure workbench. It is safe by construction: every tool runs through a deterministic policy gate, nothing touches the network in Demo mode, and every finding is grounded in collected evidence.

## What it does

- **Workspaces, scope, and safety modes** — declare allowed roots, exclusions, and a maximum risk tier. A deterministic run preview shows allowed/blocked decisions, and every preview and run writes an append-only audit event.
- **Developer surface scan** — read-only adapters inventory package manifests, MCP configs, AI tool configs, and a redacted secrets baseline across declared scope roots.
- **Run orchestration** — a baseline assessment fans out into multiple jobs through a background worker queue with live progress, cancellation, an event stream, and durable run artifacts.
- **Offline vulnerability intelligence** — matched packages are enriched against a bundled, offline OSV-style feed with an explainable priority score (severity + known-exploited + exploit probability) and stale-feed indicators. Vulnerability IDs only ever come from the feed.
- **Evidence-backed AI analyst** — a mock provider answers "what should I fix first?", explains findings, and drafts remediation. Every claim cites the evidence it came from; ungrounded claims are rejected and secret-shaped text is redacted. No live AI calls.
- **Findings triage and report export** — a prioritized findings view plus Markdown and HTML assessment reports assembled deterministically from evidence.
- **AD attack detections (Sigma)** — detection-as-code rules for common Active Directory attacks (Kerberoasting, DCSync, LSASS access, pass-the-hash, LLMNR/NBT-NS poisoning), each validated as spec-compliant Sigma and proven by tests that show it catches the attack and stays quiet on normal activity — three rules are also replayed against real EVTX attack captures. See [detections/](detections/).
- **Proxy hunts** — Sigma rules for web-telemetry signals (non-browser tools on trusted sites, reverse tunnels, risky downloads) plus Python hunts for what per-event rules cannot express: C2 beaconing and rare/upload-heavy domains, demonstrated on a planted sample log. See [detections/proxy/](detections/proxy/).

The console has four pages: Command Center, Developer Surface, Runs, and Findings.

## Requirements

- Node.js 26+
- Python 3.14+

## Setup

Install JavaScript dependencies:

```bash
npm install
```

Create the API virtual environment and install Python dependencies:

```bash
python3 -m venv apps/api/.venv
apps/api/.venv/bin/python -m pip install -e 'apps/api[test]'
```

Install the Playwright browser runtime:

```bash
npx playwright install chromium
```

## Run

Start API and web app:

```bash
npm run dev
```

Open:

```txt
http://localhost:3000
```

## Test

Run all verification:

```bash
npm run test
```

## Demo flow

1. Open the console — the seeded `RedCalibur Demo - AI Coding Stack` workspace loads in Demo mode.
2. Go to **Findings** and click **Run Baseline**. The worker runs all developer-surface scans plus vulnerability enrichment against the local demo fixture.
3. Review the prioritized findings (the demo npm package surfaces as a critical, known-exploited match).
4. Ask the **AI Analyst** what to fix first — the answer cites evidence ids.
5. Export the assessment as **Markdown** or **HTML**.

## Detections

`detections/` holds the Sigma rule pack for common Active Directory attack
techniques. Every rule is validated with pySigma and ships with attack and
benign sample events, so the test suite proves each rule fires on the attack
and stays silent on normal activity:

```bash
pip install -r detections/requirements.txt
cd detections && python -m pytest -q
```

Details, signals and tuning notes: [detections/README.md](detections/README.md).

## Safety boundaries

All scanning is local and read-only. Demo mode blocks arbitrary network targets, no tool executes above the workspace's declared risk tier, AI runs against a mock provider only (no live calls), and the vulnerability feed is bundled offline. There is no exploit execution, credential attack, or external active scanning path.

