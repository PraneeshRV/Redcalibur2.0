"""
Inventories MCP server configurations found in project scope roots.
Reads .mcp.json, claude_desktop_config.json, and .claude/settings.json.
Risk tier 1 — passive read-only, no network calls.
"""
import json
from pathlib import Path

from redcalibur_api.models import RiskTier
from redcalibur_api.tools.registry import EvidenceRecord, ToolInput, ToolMeta, ToolResult, register

TOOL_ID = "redcalibur.developer_surface.mcp_config_scan"

_meta = ToolMeta(
    id=TOOL_ID,
    name="MCP Config Scan",
    version="0.1.0",
    risk_tier=RiskTier.passive_read_only,
    description="Inventories MCP server configurations in declared scope roots.",
)

_EXCLUDE_DIRS = {"node_modules", ".venv", "venv", ".git", "__pycache__", "dist", "build", ".next"}

# File names that may contain MCP server config
_MCP_FILENAMES = {".mcp.json", "mcp.json", "claude_desktop_config.json"}


def _find_mcp_files(root: Path) -> list[Path]:
    results: list[Path] = []
    for path in root.rglob("*"):
        if any(part in _EXCLUDE_DIRS for part in path.parts):
            continue
        if path.name in _MCP_FILENAMES and path.is_file():
            results.append(path)
    # Also check .claude/settings.json at root level
    settings = root / ".claude" / "settings.json"
    if settings.is_file() and settings not in results:
        results.append(settings)
    return sorted(results)


def _extract_servers_from_mcp_json(data: dict) -> list[dict]:
    # Support both "mcpServers" (Claude Code canonical) and "servers" (older/alternate)
    raw = data.get("mcpServers") or data.get("servers") or {}
    servers = []
    for name, cfg in raw.items():
        servers.append({
            "name": name,
            "command": cfg.get("command"),
            "args": cfg.get("args", []),
            "env_keys": list((cfg.get("env") or {}).keys()),
            "transport": cfg.get("transport", "stdio"),
        })
    return servers


def _extract_servers_from_claude_settings(data: dict) -> list[dict]:
    servers = []
    raw = (data.get("mcpServers") or {})
    for name, cfg in raw.items():
        servers.append({
            "name": name,
            "command": cfg.get("command"),
            "args": cfg.get("args", []),
            "env_keys": list((cfg.get("env") or {}).keys()),
            "transport": cfg.get("transport", "stdio"),
        })
    return servers


def _parse_file(path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    if path.name in (".mcp.json", "mcp.json", "claude_desktop_config.json"):
        return _extract_servers_from_mcp_json(data)
    if path.name == "settings.json":
        return _extract_servers_from_claude_settings(data)
    return []


class McpConfigScanAdapter:
    meta = _meta

    def run(self, tool_input: ToolInput) -> ToolResult:
        scope = tool_input.scope
        project_root = tool_input.project_root
        evidence: list[EvidenceRecord] = []
        total_servers = 0
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

            for cfg_path in _find_mcp_files(root_path):
                if _is_excluded(cfg_path):
                    skipped_excluded += 1
                    continue
                servers = _parse_file(cfg_path)
                if not servers:
                    continue
                total_servers += len(servers)
                rel = cfg_path.relative_to(project_root)
                evidence.append(
                    EvidenceRecord(
                        evidence_type="mcp_server_inventory",
                        title=f"MCP config: {rel}",
                        summary=f"{len(servers)} MCP server(s) declared in {cfg_path.name}",
                        normalized={
                            "config_file": cfg_path.as_posix(),
                            "servers": servers,
                        },
                    )
                )

        return ToolResult(
            tool_id=TOOL_ID,
            success=True,
            evidence=evidence,
            output_summary={
                "scanned_roots": scanned_roots,
                "config_files_found": len(evidence),
                "total_servers": total_servers,
                "skipped_excluded": skipped_excluded,
            },
        )


mcp_config_scan = McpConfigScanAdapter()
register(mcp_config_scan)
