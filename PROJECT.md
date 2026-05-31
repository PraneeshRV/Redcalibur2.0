# RedCalibur 2.0

Status: Planning draft  
Date: 2026-05-30

## Direction

Build A first, then grow into B.

A first:

```txt
AI Security + Developer Exposure Workbench
```

B later:

```txt
Recon-to-Report Security Platform
```

## Product Thesis

RedCalibur 2.0 is a local-first security workbench for builders. It scans modern developer and AI surfaces, collects evidence, enriches findings with open data, uses AI as a cited analyst, supports remediation and verification, and exports professional reports.

## Current Planning Artifacts

- Design spec: [docs/superpowers/specs/2026-05-30-redcalibur-2-design.md](docs/superpowers/specs/2026-05-30-redcalibur-2-design.md)
- Research digest: [docs/research/redcalibur-2-research-digest.md](docs/research/redcalibur-2-research-digest.md)
- Architecture blueprint: [docs/architecture/redcalibur-2-blueprint.md](docs/architecture/redcalibur-2-blueprint.md)
- Roadmap: [docs/planning/redcalibur-2-roadmap.md](docs/planning/redcalibur-2-roadmap.md)
- Safety policy: [docs/planning/redcalibur-2-safety-policy.md](docs/planning/redcalibur-2-safety-policy.md)
- Demo script: [docs/planning/redcalibur-2-demo-script.md](docs/planning/redcalibur-2-demo-script.md)

## Recommended Next Step

Approve the product spine, then write the first implementation plan for the Product Spine Preview:

- app foundation
- workspace model
- safety modes
- scope declaration
- policy engine
- audit spine
- blocked run preview
- minimal Command Center and Scopes UI

Scanners, AI, and open-data intelligence should follow only after that spine exists.

## Locked First Slice

- Next.js web app
- FastAPI backend
- project-local SQLite in `data/`
- seed workspace: `RedCalibur Demo - AI Coding Stack`
- local fixture scope only
- no scanner execution
- no live AI provider calls
- no network target checks
- audit every run preview, including blocked previews
