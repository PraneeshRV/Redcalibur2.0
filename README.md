# RedCalibur 2.0

RedCalibur 2.0 starts as a local-first AI security and developer exposure workbench. This repository currently implements the Product Spine Preview: workspace, scope, deterministic run preview, blocked-target UX, and audit persistence.

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

The Product Spine Preview intentionally does not include scanner execution, live AI provider calls, open-data integrations, report generation, or external network target checks.

