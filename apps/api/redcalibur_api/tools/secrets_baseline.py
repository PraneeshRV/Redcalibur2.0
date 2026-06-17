"""
Scans text files in scope roots for high-confidence secret patterns
(API keys, tokens, private keys, connection strings).
Captures file:line:column positions and pattern type — never the secret value.
Risk tier 1 — passive read-only, no network calls.
"""
import re
from pathlib import Path

from redcalibur_api.models import RiskTier
from redcalibur_api.tools.registry import EvidenceRecord, ToolInput, ToolMeta, ToolResult, register

TOOL_ID = "redcalibur.developer_surface.secrets_baseline"

_meta = ToolMeta(
    id=TOOL_ID,
    name="Secrets Baseline",
    version="0.1.0",
    risk_tier=RiskTier.passive_read_only,
    description="Detects high-confidence secret patterns in declared scope roots. Never records secret values.",
)

_EXCLUDE_DIRS = {"node_modules", ".venv", "venv", ".git", "__pycache__", "dist", "build", ".next"}

# Files whose extensions are typically binary or not useful to scan
_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz", ".lock", ".pyc",
    ".map", ".min.js", ".min.css",
}

# Max file size to scan (512 KB)
_MAX_FILE_BYTES = 512 * 1024

# Max findings per file (avoid noisy files)
_MAX_FINDINGS_PER_FILE = 20

# Max total findings across all files
_MAX_TOTAL_FINDINGS = 200


# Each pattern: (label, compiled regex)
# Groups must capture only the non-secret portion; secret value is never stored.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("private_key_header", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"(?<![A-Z0-9])(AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}(?![A-Z0-9])")),
    ("aws_secret_key", re.compile(r'(?i)(aws.{0,20}secret.{0,20}[=:"\s])([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])')),
    ("github_token", re.compile(r'(?i)(ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36}')),
    ("github_classic_token", re.compile(r'\bghp_[A-Za-z0-9]{36}\b')),
    ("openai_api_key", re.compile(r'(?i)(sk-[A-Za-z0-9]{48}|sk-proj-[A-Za-z0-9_-]{48,})')),
    ("anthropic_api_key", re.compile(r'\bsk-ant-[A-Za-z0-9\-_]{40,}\b')),
    ("slack_token", re.compile(r'\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b')),
    ("stripe_key", re.compile(r'\b(sk_live_|pk_live_|sk_test_|rk_live_)[A-Za-z0-9]{20,}\b')),
    ("google_api_key", re.compile(r'\bAIza[A-Za-z0-9\-_]{35}\b')),
    ("jwt_token", re.compile(r'\beyJ[A-Za-z0-9\-_=]{20,}\.[A-Za-z0-9\-_=]{20,}\.[A-Za-z0-9\-_=]{20,}\b')),
    ("database_url_with_password", re.compile(
        r'(?i)(postgres|postgresql|mysql|mongodb|redis)://[^:@\s]+:[^@\s]{8,}@'
    )),
    ("generic_secret_assignment", re.compile(
        r'(?i)\b(password|passwd|secret|api_key|apikey|auth_token|access_token|private_key)\s*[=:]\s*["\'](?!\{)[^\s"\'){]{8,}["\']'
    )),
]


def _should_skip(path: Path) -> bool:
    suffixes = "".join(path.suffixes).lower()
    for ext in _SKIP_EXTENSIONS:
        if suffixes.endswith(ext):
            return True
    return False


def _scan_file(path: Path) -> list[dict]:
    if _should_skip(path):
        return []
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings: list[dict] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(findings) >= _MAX_FINDINGS_PER_FILE:
            break
        for label, pattern in _PATTERNS:
            if pattern.search(line):
                findings.append({
                    "pattern": label,
                    "file": path.as_posix(),
                    "line": lineno,
                })
                # One finding per line per pattern is enough
    return findings


class SecretsBaselineAdapter:
    meta = _meta

    def run(self, tool_input: ToolInput) -> ToolResult:
        scope = tool_input.scope
        project_root = tool_input.project_root
        evidence: list[EvidenceRecord] = []
        scanned_roots: list[str] = []
        total_files_scanned = 0
        total_findings = 0
        skipped_excluded = 0

        excluded_paths = [
            (project_root / excl).resolve()
            for excl in scope.excluded_roots
        ]

        def _is_excluded(path: Path) -> bool:
            return any(path == ex or ex in path.parents for ex in excluded_paths)

        for allowed_root in scope.allowed_roots:
            root_path = (project_root / allowed_root).resolve()
            if not root_path.exists():
                continue
            scanned_roots.append(root_path.as_posix())

            for file_path in sorted(root_path.rglob("*")):
                if not file_path.is_file():
                    continue
                if any(part in _EXCLUDE_DIRS for part in file_path.parts):
                    continue
                if _is_excluded(file_path):
                    skipped_excluded += 1
                    continue
                if total_findings >= _MAX_TOTAL_FINDINGS:
                    break

                findings = _scan_file(file_path)
                if not findings:
                    continue

                total_files_scanned += 1
                total_findings += len(findings)
                rel = file_path.relative_to(project_root)

                evidence.append(
                    EvidenceRecord(
                        evidence_type="secret_finding",
                        title=f"Potential secrets: {rel}",
                        summary=f"{len(findings)} potential secret(s) in {file_path.name}",
                        normalized={
                            "file": rel.as_posix(),
                            # findings carry pattern+line only — never the secret value
                            "findings": findings,
                        },
                    )
                )

        return ToolResult(
            tool_id=TOOL_ID,
            success=True,
            evidence=evidence,
            output_summary={
                "scanned_roots": scanned_roots,
                "files_with_findings": total_files_scanned,
                "total_findings": total_findings,
                "skipped_excluded": skipped_excluded,
                "capped": total_findings >= _MAX_TOTAL_FINDINGS,
            },
        )


secrets_baseline = SecretsBaselineAdapter()
register(secrets_baseline)
