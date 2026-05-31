# RedCalibur 2.0 Research Digest

Status: Draft  
Date: 2026-05-30

## Research Goal

Find the strongest modern ideas to revive RedCalibur as a serious AI-era security project, without turning it into an unsafe exploit toy or a thin wrapper around existing scanners.

## Key Conclusion

The strongest direction is a local-first AI security and developer exposure workbench. It should borrow patterns from frontier AI security programs, read-only developer endpoint scanners, LLM red-team frameworks, and open vulnerability intelligence, then combine them into one evidence-backed workflow.

## Frontier AI Security Signals

### Anthropic Project Glasswing and Claude Mythos

Sources:

- Project Glasswing: https://www.anthropic.com/glasswing
- Claude Mythos Preview: https://red.anthropic.com/2026/mythos-preview/
- Initial Glasswing update: https://www.anthropic.com/research/glasswing-initial-update

Relevant signals:

- Anthropic positioned Mythos Preview for defensive security work through Project Glasswing.
- The public materials emphasize local vulnerability detection, black-box testing, endpoint security, penetration testing of systems, and critical software hardening.
- The May 2026 update says the hard part is no longer only finding vulnerabilities. Verification, disclosure, patching, and safe operational handling become the bottleneck.

RedCalibur implication:

Do not imitate unrestricted exploit autonomy. Instead, build the workflow around verification, evidence, triage, remediation, and proof.

### Perplexity Bumblebee

Sources:

- GitHub repository: https://github.com/perplexityai/bumblebee
- Perplexity announcement: https://www.perplexity.ai/hub/blog/perplexity-is-open-sourcing-bumblebee

Relevant signals:

- Bumblebee is a read-only developer endpoint scanner for package, extension, and developer-tool metadata.
- It reads lockfiles, package manager metadata, extension manifests, and supported MCP JSON configs.
- It avoids package-manager execution and source-file reads.
- It outputs structured component records for supply-chain exposure response.

RedCalibur implication:

The read-only metadata scanner pattern is perfect for a safe, portfolio-grade MVP. RedCalibur should scan local developer and AI tooling surfaces, but integrate results into workspaces, evidence, findings, AI analysis, remediation, and reports.

### Google Big Sleep and CodeMender

Sources:

- Big Sleep public project materials: https://googleprojectzero.blogspot.com/
- Google DeepMind security research: https://deepmind.google/discover/blog/

Relevant signals:

- AI vulnerability research is moving from toy demonstrations into real security research workflows.
- Public access and exact capabilities vary, so these should be treated as inspiration, not dependencies.

RedCalibur implication:

Use the idea of AI-assisted vulnerability research, but keep MVP grounded in safe local assessments and evidence workflows.

## AI Security Tools To Borrow From

### Microsoft PyRIT

Source: https://github.com/microsoft/PyRIT

Pattern to borrow:

- adapter-based risk identification
- reusable prompt and target abstractions
- structured AI red-team experiments

What to avoid:

- becoming only a red-team script harness

### Microsoft RAMPART

Source: https://microsoft.github.io/RAMPART/

Pattern to borrow:

- pytest-native safety testing
- statistical trials
- regression-friendly agent testing

RedCalibur use:

Accepted AI-lab findings should become repeatable regression tests.

### NVIDIA garak

Sources:

- https://garak.ai/
- https://github.com/NVIDIA/garak

Pattern to borrow:

- generator, probe, detector mental model
- broad vulnerability categories
- reproducible scan records

RedCalibur use:

Adapt the probe/detector pattern to AI applications, agents, RAG systems, tools, and MCP surfaces.

### Promptfoo

Source: https://www.promptfoo.dev/docs/red-team/quickstart/

Pattern to borrow:

- config-as-artifact evals
- CI-friendly red-team runs
- target adapters
- reportable evaluation outputs

RedCalibur use:

Let users store eval suites as project artifacts and eventually run them in CI.

### Giskard

Source: https://docs.giskard.ai/hub/sdk/scan/index.html

Pattern to borrow:

- OWASP LLM Top 10 alignment
- business-risk framing
- scan review workflow

RedCalibur use:

Map AI findings to OWASP GenAI categories and show why they matter to a builder.

### Tencent AI-Infra-Guard

Source: https://github.com/Tencent/AI-Infra-Guard

Pattern to borrow:

- AI infrastructure security breadth
- MCP scan awareness
- agent, skill, and model infrastructure surfaces

RedCalibur use:

Treat AI infrastructure as a first-class asset graph, not just prompt text.

## Standards And Frameworks

### OWASP GenAI Security Project

Sources:

- https://genai.owasp.org/
- https://owasp.org/www-project-top-10-for-large-language-model-applications

Use:

- classification for AI app risks
- report mapping
- educational context
- test suite organization

### MITRE ATLAS

Source: https://atlas.mitre.org/

Use:

- adversarial AI tactics and techniques
- threat context for AI findings
- optional knowledge-base mapping

### NIST AI RMF

Source: https://www.nist.gov/itl/ai-risk-management-framework

Use:

- governance vocabulary
- risk management framing
- useful for reports and future compliance views

## Open Data Sources

### CVE / cvelistV5

Source: https://github.com/CVEProject/cvelistV5

Use:

- canonical vulnerability identifiers
- aliases
- public record metadata

### NVD

Source: https://nvd.nist.gov/developers/vulnerabilities

Use:

- CVSS, CPE, references, enriched metadata where available

Risk:

- enrichment availability and freshness can vary. RedCalibur should show source freshness and avoid assuming NVD is complete.

### CISA KEV

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

Use:

- known-exploited signal
- prioritization boost
- defender-friendly remediation urgency

### FIRST EPSS

Source: https://api.first.org/epss/

Use:

- exploit probability signal
- historical score support
- prioritization input

### OSV.dev

Source: https://osv.dev/

Use:

- open-source package vulnerability matching
- version-aware affected ranges
- package ecosystem normalization

### GitHub Advisory Database

Source: https://docs.github.com/github/managing-security-vulnerabilities/browsing-security-vulnerabilities-in-the-github-advisory-database

Use:

- GHSA records
- package advisories
- ecosystem-specific security metadata

### OpenSSF Scorecard

Source: https://openssf.org/scorecard/

Use:

- open-source project security health signal
- later supply-chain trust scoring

## Product Patterns To Copy

Copy these patterns:

- scope and authorization gates
- read-only local metadata scanning
- adapter-based tools
- evidence records with hashes and provenance
- run event timelines
- finding lifecycle
- report-grade language
- eval suites as reusable artifacts
- AI answers with citations
- stale-data and uncertainty indicators

Avoid these patterns:

- exploit-autopilot demos
- unscoped internet scanning
- false-positive firehose
- tool grids with no workflow
- AI-generated claims without evidence
- hidden destructive behavior
- "cyberpunk" aesthetics over operator clarity

## RedCalibur Innovation Thesis

Most tools are either:

- classic scanners
- AI red-team libraries
- vulnerability data feeds
- report generators
- local supply-chain inventory tools

RedCalibur can combine them into one builder-focused loop:

```txt
scope -> collect evidence -> enrich -> find -> explain -> fix -> verify -> report
```

That loop is the product.

