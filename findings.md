# RedCalibur 2.0 Findings

## Old Repo Findings

- Original RedCalibur was a Python/FastAPI and frontend security toolkit with AI-assisted red-team and OSINT features.
- Useful legacy concepts: RedCalibur identity, tool catalog, AI assistance, report generation.
- Major issues to replace: one-off subprocess routes, duplicated frontends, raw string outputs, wildcard CORS, no authorization model, unsafe exploit/payload/phishing framing.

## Research Findings

- The strongest modern direction is not another scanner. It is a local-first evidence, verification, remediation, and reporting workbench for AI builders.
- Anthropic Project Glasswing and Claude Mythos point toward AI-assisted defensive vulnerability work; the operational bottleneck is verification and remediation.
- Perplexity Bumblebee validates read-only developer endpoint scanning as a safe modern pattern.
- PyRIT, RAMPART, garak, Promptfoo, Giskard, AI-Infra-Guard, OWASP GenAI, MITRE ATLAS, OSV, CVE, NVD, CISA KEV, and FIRST EPSS provide patterns and data sources to borrow from.

## Product Findings

- A-first direction is more distinctive than rebuilding classic recon first.
- B-later platform path remains valuable once the safety/evidence spine exists.
- First shippable slice must be much smaller than full MVP.
- Product Spine Preview is the correct first implementation boundary.

## Safety Findings

- External target authorization cannot be self-attested in later phases; it needs owner, scope, expiry, approval artifact, and contact.
- Tier 2 network checks must wait for target-resolution gates and abuse-case tests.
- AI App Lab must be local/lab-only at first, with static probe catalogs and intercepted tool calls.
- Evidence must be treated as untrusted input to the AI analyst.
- Secrets and artifacts need redaction, gitignore, file-permission, export-sanitization, and retention controls.

