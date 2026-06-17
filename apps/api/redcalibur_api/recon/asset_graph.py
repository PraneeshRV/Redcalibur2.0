"""Offline asset graph.

Builds a v2-style asset graph purely from evidence already collected locally —
no network, no recon. Nodes are the workspace, manifests, packages, matched
vulnerabilities, and AI targets; edges capture declares / depends_on /
affected_by / exposes relationships. This gives the v2 "asset graph" view a
real, safe foundation that live recon can later extend (once gated).
"""

from __future__ import annotations

from redcalibur_api.models import AssetEdge, AssetGraph, AssetNode, EvidenceItem, Workspace


def build_asset_graph(workspace: Workspace, evidence: list[EvidenceItem]) -> AssetGraph:
    nodes: dict[str, AssetNode] = {}
    edges: list[AssetEdge] = []

    ws_node_id = f"workspace:{workspace.id}"
    nodes[ws_node_id] = AssetNode(id=ws_node_id, kind="workspace", label=workspace.name)

    def add_node(node: AssetNode) -> str:
        nodes.setdefault(node.id, node)
        return node.id

    for item in evidence:
        if item.evidence_type == "package_inventory":
            manifest_path = item.normalized.get("manifest_path", item.title)
            m_id = f"manifest:{manifest_path}"
            add_node(AssetNode(id=m_id, kind="manifest", label=item.normalized.get("manifest", manifest_path)))
            edges.append(AssetEdge(source=ws_node_id, target=m_id, relation="declares"))
            for pkg in item.normalized.get("packages", []):
                p_id = f"package:{pkg.get('ecosystem')}:{pkg.get('name')}"
                add_node(AssetNode(id=p_id, kind="package", label=f"{pkg.get('ecosystem')}:{pkg.get('name')}"))
                edges.append(AssetEdge(source=m_id, target=p_id, relation="depends_on"))

        elif item.evidence_type == "vulnerability_match":
            p_id = f"package:{item.normalized.get('ecosystem')}:{item.normalized.get('package')}"
            add_node(AssetNode(id=p_id, kind="package", label=f"{item.normalized.get('ecosystem')}:{item.normalized.get('package')}"))
            edges.append(AssetEdge(source=ws_node_id, target=p_id, relation="declares"))
            for v in item.normalized.get("vulnerabilities", []):
                v_id = f"vuln:{v.get('id')}"
                add_node(AssetNode(
                    id=v_id, kind="vulnerability", label=v.get("id", "unknown"),
                    meta={"severity": v.get("severity_label"), "kev": v.get("kev"), "priority": v.get("priority_score")},
                ))
                edges.append(AssetEdge(source=p_id, target=v_id, relation="affected_by"))

        elif item.evidence_type == "ai_eval_result":
            t_id = f"ai_target:{item.normalized.get('target_id')}"
            add_node(AssetNode(id=t_id, kind="ai_target", label=item.normalized.get("target_name", "AI target")))
            edges.append(AssetEdge(source=ws_node_id, target=t_id, relation="declares"))
            v_id = f"vuln:{item.normalized.get('category')}:{item.normalized.get('probe_id')}"
            add_node(AssetNode(
                id=v_id, kind="vulnerability", label=f"{item.normalized.get('category')}:{item.normalized.get('probe_id')}",
                meta={"category": item.normalized.get("category")},
            ))
            edges.append(AssetEdge(source=t_id, target=v_id, relation="exposes"))

    return AssetGraph(
        workspace_id=workspace.id,
        nodes=list(nodes.values()),
        edges=edges,
        note="Built from local evidence only. Live network recon (v2) is gated and not executed.",
    )
