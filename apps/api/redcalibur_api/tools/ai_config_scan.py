"""
Inventories AI tool configuration artifacts in project scope roots.
Covers Claude (.claude/), Cursor (.cursor/), GitHub Copilot (.github/copilot*),
Aider (.aider*), Continue (.continue/), Codex (.codex/), and OpenAI config.
Risk tier 1 — passive read-only, no network calls.
"""
import json
from pathlib import Path

from redcalibur_api.models import RiskTier
from redcalibur_api.tools.registry import EvidenceRecord, ToolInput, ToolMeta, ToolResult, register

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore[no-redef]

TOOL_ID = "redcalibur.developer_surface.ai_config_scan"

_meta = ToolMeta(
    id=TOOL_ID,
    name="AI Config Scan",
    version="0.1.0",
    risk_tier=RiskTier.passive_read_only,
    description="Inventories AI tool configurations in declared scope roots.",
)

_EXCLUDE_DIRS = {"node_modules", ".venv", "venv", ".git", "__pycache__", "dist", "build", ".next"}


def _rel(path: Path, project_root: Path) -> str:
    try:
        return path.relative_to(project_root).as_posix()
    except ValueError:
        return path.as_posix()


def _safe_read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _collect_dir_summary(directory: Path, project_root: Path) -> dict:
    files = []
    for p in sorted(directory.rglob("*")):
        if p.is_file() and not any(part in _EXCLUDE_DIRS for part in p.parts):
            files.append(_rel(p, project_root))
    return {"directory": _rel(directory, project_root), "files": files}


def _scan_claude(root: Path, project_root: Path) -> list[EvidenceRecord]:
    records = []
    claude_dir = root / ".claude"
    if claude_dir.is_dir():
        summary = _collect_dir_summary(claude_dir, project_root)
        records.append(EvidenceRecord(
            evidence_type="ai_config",
            title=f"Claude config: {_rel(claude_dir, project_root)}",
            summary=f"{len(summary['files'])} file(s) in .claude/",
            normalized={"tool": "claude", **summary},
        ))
    claude_md = root / "CLAUDE.md"
    if claude_md.is_file():
        text = _safe_read_text(claude_md) or ""
        records.append(EvidenceRecord(
            evidence_type="ai_config",
            title=f"Claude instructions: {_rel(claude_md, project_root)}",
            summary=f"CLAUDE.md present ({len(text.splitlines())} lines)",
            normalized={"tool": "claude", "file": _rel(claude_md, project_root), "line_count": len(text.splitlines())},
        ))
    return records


def _scan_cursor(root: Path, project_root: Path) -> list[EvidenceRecord]:
    records = []
    cursor_dir = root / ".cursor"
    if cursor_dir.is_dir():
        summary = _collect_dir_summary(cursor_dir, project_root)
        records.append(EvidenceRecord(
            evidence_type="ai_config",
            title=f"Cursor config: {_rel(cursor_dir, project_root)}",
            summary=f"{len(summary['files'])} file(s) in .cursor/",
            normalized={"tool": "cursor", **summary},
        ))
    cursor_rules = root / ".cursorrules"
    if cursor_rules.is_file():
        text = _safe_read_text(cursor_rules) or ""
        records.append(EvidenceRecord(
            evidence_type="ai_config",
            title=f"Cursor rules: {_rel(cursor_rules, project_root)}",
            summary=f".cursorrules present ({len(text.splitlines())} lines)",
            normalized={"tool": "cursor", "file": _rel(cursor_rules, project_root), "line_count": len(text.splitlines())},
        ))
    return records


def _scan_copilot(root: Path, project_root: Path) -> list[EvidenceRecord]:
    records = []
    github_dir = root / ".github"
    if not github_dir.is_dir():
        return records
    for p in sorted(github_dir.iterdir()):
        if p.is_file() and "copilot" in p.name.lower():
            records.append(EvidenceRecord(
                evidence_type="ai_config",
                title=f"GitHub Copilot config: {_rel(p, project_root)}",
                summary=f"Copilot config file: {p.name}",
                normalized={"tool": "copilot", "file": _rel(p, project_root)},
            ))
    return records


def _scan_aider(root: Path, project_root: Path) -> list[EvidenceRecord]:
    records = []
    for name in (".aider.conf.yml", ".aider.model.settings.yml", ".aider.model.metadata.json"):
        p = root / name
        if p.is_file():
            records.append(EvidenceRecord(
                evidence_type="ai_config",
                title=f"Aider config: {_rel(p, project_root)}",
                summary=f"Aider config file: {p.name}",
                normalized={"tool": "aider", "file": _rel(p, project_root)},
            ))
    return records


def _scan_continue(root: Path, project_root: Path) -> list[EvidenceRecord]:
    records = []
    continue_dir = root / ".continue"
    if continue_dir.is_dir():
        summary = _collect_dir_summary(continue_dir, project_root)
        records.append(EvidenceRecord(
            evidence_type="ai_config",
            title=f"Continue config: {_rel(continue_dir, project_root)}",
            summary=f"{len(summary['files'])} file(s) in .continue/",
            normalized={"tool": "continue", **summary},
        ))
    return records


def _scan_codex(root: Path, project_root: Path) -> list[EvidenceRecord]:
    records = []
    codex_dir = root / ".codex"
    if codex_dir.is_dir():
        summary = _collect_dir_summary(codex_dir, project_root)
        records.append(EvidenceRecord(
            evidence_type="ai_config",
            title=f"Codex config: {_rel(codex_dir, project_root)}",
            summary=f"{len(summary['files'])} file(s) in .codex/",
            normalized={"tool": "codex", **summary},
        ))
    return records


_SCANNERS = [_scan_claude, _scan_cursor, _scan_copilot, _scan_aider, _scan_continue, _scan_codex]


class AiConfigScanAdapter:
    meta = _meta

    def run(self, tool_input: ToolInput) -> ToolResult:
        scope = tool_input.scope
        project_root = tool_input.project_root
        evidence: list[EvidenceRecord] = []
        scanned_roots: list[str] = []
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

            for scanner in _SCANNERS:
                for record in scanner(root_path, project_root):
                    # Check if any file in the record is excluded
                    file_str = record.normalized.get("file", "")
                    if file_str:
                        fpath = (project_root / file_str).resolve()
                        if _is_excluded(fpath):
                            skipped_excluded += 1
                            continue
                    dir_str = record.normalized.get("directory", "")
                    if dir_str:
                        dpath = (project_root / dir_str).resolve()
                        if _is_excluded(dpath):
                            skipped_excluded += 1
                            continue
                    evidence.append(record)

        tools_found = sorted({r.normalized.get("tool", "unknown") for r in evidence})

        return ToolResult(
            tool_id=TOOL_ID,
            success=True,
            evidence=evidence,
            output_summary={
                "scanned_roots": scanned_roots,
                "artifacts_found": len(evidence),
                "tools_detected": tools_found,
                "skipped_excluded": skipped_excluded,
            },
        )


ai_config_scan = AiConfigScanAdapter()
register(ai_config_scan)
