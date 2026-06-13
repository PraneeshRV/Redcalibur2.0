"""
Reads package manifest files (package.json, pyproject.toml, requirements.txt,
Cargo.toml, go.mod) from declared allowed scope roots.
Risk tier 1 — passive read-only, no network calls.
"""
import json
import re
from pathlib import Path

from redcalibur_api.models import RiskTier
from redcalibur_api.tools.registry import EvidenceRecord, ToolAdapter, ToolInput, ToolMeta, ToolResult, register

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore[no-redef]


TOOL_ID = "redcalibur.developer_surface.manifest_scan"

_meta = ToolMeta(
    id=TOOL_ID,
    name="Manifest Scan",
    version="0.1.0",
    risk_tier=RiskTier.passive_read_only,
    description="Inventories package manifests in declared scope roots.",
)

_MANIFEST_GLOBS = [
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "Cargo.toml",
    "go.mod",
]

_EXCLUDE_DIRS = {"node_modules", ".venv", "venv", ".git", "__pycache__", "dist", "build", ".next"}


def _find_manifests(root: Path) -> list[Path]:
    results: list[Path] = []
    for path in root.rglob("*"):
        if any(part in _EXCLUDE_DIRS for part in path.parts):
            continue
        if path.name in _MANIFEST_GLOBS and path.is_file():
            results.append(path)
    return sorted(results)


def _parse_package_json(path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    records = []
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        for name, version_spec in (data.get(section) or {}).items():
            records.append({
                "ecosystem": "npm",
                "name": name,
                "version_spec": version_spec,
                "section": section,
                "manifest": path.name,
                "manifest_path": path.as_posix(),
            })
    return records


def _parse_pyproject_toml(path: Path) -> list[dict]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    records = []
    deps = (data.get("project") or {}).get("dependencies") or []
    for dep in deps:
        match = re.match(r"^([A-Za-z0-9_.\-]+)", dep)
        name = match.group(1) if match else dep
        records.append({
            "ecosystem": "pypi",
            "name": name,
            "version_spec": dep,
            "section": "dependencies",
            "manifest": path.name,
            "manifest_path": path.as_posix(),
        })
    for extra, extra_deps in ((data.get("project") or {}).get("optional-dependencies") or {}).items():
        for dep in extra_deps:
            match = re.match(r"^([A-Za-z0-9_.\-]+)", dep)
            name = match.group(1) if match else dep
            records.append({
                "ecosystem": "pypi",
                "name": name,
                "version_spec": dep,
                "section": f"optional:{extra}",
                "manifest": path.name,
                "manifest_path": path.as_posix(),
            })
    return records


def _parse_requirements_txt(path: Path) -> list[dict]:
    records = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            match = re.match(r"^([A-Za-z0-9_.\-]+)", line)
            name = match.group(1) if match else line
            records.append({
                "ecosystem": "pypi",
                "name": name,
                "version_spec": line,
                "section": "requirements",
                "manifest": path.name,
                "manifest_path": path.as_posix(),
            })
    except OSError:
        pass
    return records


def _parse_cargo_toml(path: Path) -> list[dict]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    records = []
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, spec in (data.get(section) or {}).items():
            version_spec = spec if isinstance(spec, str) else (spec.get("version") or "")
            records.append({
                "ecosystem": "cargo",
                "name": name,
                "version_spec": version_spec,
                "section": section,
                "manifest": path.name,
                "manifest_path": path.as_posix(),
            })
    return records


def _parse_go_mod(path: Path) -> list[dict]:
    records = []
    try:
        in_require = False
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line == "require (":
                in_require = True
                continue
            if in_require and line == ")":
                in_require = False
                continue
            if in_require or line.startswith("require "):
                dep_line = line.removeprefix("require ").strip()
                parts = dep_line.split()
                if len(parts) >= 2:
                    records.append({
                        "ecosystem": "go",
                        "name": parts[0],
                        "version_spec": parts[1],
                        "section": "require",
                        "manifest": path.name,
                        "manifest_path": path.as_posix(),
                    })
    except OSError:
        pass
    return records


_PARSERS = {
    "package.json": _parse_package_json,
    "pyproject.toml": _parse_pyproject_toml,
    "requirements.txt": _parse_requirements_txt,
    "Cargo.toml": _parse_cargo_toml,
    "go.mod": _parse_go_mod,
}


class ManifestScanAdapter:
    meta = _meta

    def run(self, tool_input: ToolInput) -> ToolResult:
        scope = tool_input.scope
        project_root = tool_input.project_root
        evidence: list[EvidenceRecord] = []
        total_packages = 0
        scanned_roots: list[str] = []
        skipped_excluded = 0

        excluded_paths = [
            (project_root / excluded).resolve()
            for excluded in scope.excluded_roots
        ]

        def _is_excluded(path: Path) -> bool:
            return any(path == ex or ex in path.parents for ex in excluded_paths)

        for allowed_root in scope.allowed_roots:
            root_path = (project_root / allowed_root).resolve()
            if not root_path.exists():
                continue
            scanned_roots.append(root_path.as_posix())

            for manifest_path in _find_manifests(root_path):
                if _is_excluded(manifest_path):
                    skipped_excluded += 1
                    continue
                parser = _PARSERS.get(manifest_path.name)
                if parser is None:
                    continue
                packages = parser(manifest_path)
                if not packages:
                    continue
                total_packages += len(packages)
                rel = manifest_path.relative_to(project_root)
                evidence.append(
                    EvidenceRecord(
                        evidence_type="package_inventory",
                        title=f"Package manifest: {rel}",
                        summary=f"{len(packages)} package(s) declared in {manifest_path.name}",
                        normalized={
                            "manifest": manifest_path.name,
                            "manifest_path": manifest_path.as_posix(),
                            "packages": packages,
                        },
                    )
                )

        return ToolResult(
            tool_id=TOOL_ID,
            success=True,
            evidence=evidence,
            output_summary={
                "scanned_roots": scanned_roots,
                "manifests_found": len(evidence),
                "total_packages": total_packages,
                "skipped_excluded": skipped_excluded,
            },
        )


manifest_scan = ManifestScanAdapter()
register(manifest_scan)
