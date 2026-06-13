from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from redcalibur_api.models import RiskTier, ScopeDeclaration


@dataclass(frozen=True)
class ToolMeta:
    id: str
    name: str
    version: str
    risk_tier: RiskTier
    description: str


@dataclass
class ToolInput:
    workspace_id: str
    scope: ScopeDeclaration
    project_root: Path
    params: dict[str, Any]


@dataclass
class EvidenceRecord:
    evidence_type: str
    title: str
    summary: str
    normalized: dict[str, Any]


@dataclass
class ToolResult:
    tool_id: str
    success: bool
    evidence: list[EvidenceRecord]
    output_summary: dict[str, Any]
    error: str | None = None


class ToolAdapter(Protocol):
    meta: ToolMeta

    def run(self, tool_input: ToolInput) -> ToolResult: ...


_registry: dict[str, "ToolAdapter"] = {}


def register(adapter: "ToolAdapter") -> None:
    _registry[adapter.meta.id] = adapter


def get(tool_id: str) -> "ToolAdapter | None":
    return _registry.get(tool_id)


def all_tools() -> list[ToolMeta]:
    return [adapter.meta for adapter in _registry.values()]
