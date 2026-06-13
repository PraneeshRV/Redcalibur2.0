"use client";

import { Box, FileText, Search } from "lucide-react";
import { useEffect, useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000";

type Package = {
  ecosystem: string;
  name: string;
  version_spec: string;
  section: string;
  manifest_path: string;
};

type EvidenceItem = {
  id: string;
  evidence_type: string;
  title: string;
  summary: string;
  normalized: {
    manifest: string;
    manifest_path: string;
    packages: Package[];
  };
  collected_at: string;
};

type Job = {
  id: string;
  tool_id: string;
  status: string;
  output_summary: {
    scanned_roots: string[];
    manifests_found: number;
    total_packages: number;
  } | null;
  error: string | null;
  started_at: string;
  finished_at: string | null;
};

type RunResponse = {
  run: { id: string; kind: string; status: string; started_at: string; finished_at: string | null };
  jobs: Job[];
  evidence: EvidenceItem[];
};

type WorkspaceSummary = { id: string; name: string };

export default function DeveloperSurface() {
  const [workspace, setWorkspace] = useState<WorkspaceSummary | null>(null);
  const [runData, setRunData] = useState<RunResponse | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  async function loadWorkspace() {
    try {
      const workspaces = (await fetch(`${API_BASE}/workspaces`).then((r) => r.json())) as WorkspaceSummary[];
      return workspaces[0] ?? null;
    } catch {
      return null;
    }
  }

  async function loadLatestRun(workspaceId: string) {
    try {
      const runs = (await fetch(`${API_BASE}/workspaces/${workspaceId}/runs`).then((r) => r.json())) as { id: string }[];
      if (runs.length === 0) return null;
      return (await fetch(`${API_BASE}/runs/${runs[0].id}`).then((r) => r.json())) as RunResponse;
    } catch {
      return null;
    }
  }

  useEffect(() => {
    (async () => {
      setError(null);
      try {
        const ws = await loadWorkspace();
        if (!ws) { setError("API not reachable."); return; }
        setWorkspace(ws);
        const latest = await loadLatestRun(ws.id);
        setRunData(latest);
      } catch {
        setError("Failed to load Developer Surface data.");
      }
    })();
  }, []);

  async function startScan() {
    if (!workspace) return;
    setScanning(true);
    setError(null);
    try {
      const result = await fetch(`${API_BASE}/workspaces/${workspace.id}/runs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind: "manifest_scan" }),
      });
      if (!result.ok) {
        const body = await result.json().catch(() => ({}));
        setError((body as { detail?: string }).detail ?? "Scan failed.");
        return;
      }
      setRunData(await result.json());
    } catch {
      setError("Scan failed — API not reachable.");
    } finally {
      setScanning(false);
    }
  }

  function toggleExpand(id: string) {
    setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));
  }

  const job = runData?.jobs[0] ?? null;
  const allPackages = (runData?.evidence ?? []).flatMap((e) => e.normalized.packages);
  const ecosystemCounts = allPackages.reduce<Record<string, number>>((acc, pkg) => {
    acc[pkg.ecosystem] = (acc[pkg.ecosystem] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 18 }}>
        <h1 style={{ margin: 0 }}>Developer Surface</h1>
        <button className="button" type="button" onClick={startScan} disabled={scanning || !workspace}>
          <Search size={14} style={{ marginRight: 6, verticalAlign: "middle" }} />
          {scanning ? "Scanning…" : "Run Manifest Scan"}
        </button>
      </div>

      {error ? <p className="blocked">{error}</p> : null}

      {job ? (
        <div className="meta" style={{ marginBottom: 16 }}>
          <span className="chip">Status: {runData?.run.status}</span>
          <span className="chip">Manifests: {job.output_summary?.manifests_found ?? "-"}</span>
          <span className="chip">Packages: {job.output_summary?.total_packages ?? "-"}</span>
          <span className="chip">Ran: {runData?.run.finished_at?.slice(0, 19).replace("T", " ") ?? "-"}</span>
        </div>
      ) : (
        !error && <p style={{ color: "var(--muted)" }}>No scan results yet. Click <strong>Run Manifest Scan</strong> to inventory packages in declared scope roots.</p>
      )}

      {Object.keys(ecosystemCounts).length > 0 && (
        <div className="meta" style={{ marginBottom: 16 }}>
          {Object.entries(ecosystemCounts).map(([eco, count]) => (
            <span key={eco} className="chip">{eco}: {count}</span>
          ))}
        </div>
      )}

      {(runData?.evidence ?? []).map((item) => (
        <section key={item.id} className="panel" style={{ marginBottom: 12 }}>
          <h2 style={{ cursor: "pointer" }} onClick={() => toggleExpand(item.id)}>
            <FileText size={16} />
            {item.title}
            <span style={{ marginLeft: "auto", color: "var(--muted)", fontSize: 12 }}>
              {item.normalized.packages.length} packages
              {expanded[item.id] ? " ▲" : " ▼"}
            </span>
          </h2>
          <p style={{ marginBottom: expanded[item.id] ? 12 : 0 }}>{item.summary}</p>
          {expanded[item.id] && (
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
              <thead>
                <tr style={{ color: "var(--muted)", textAlign: "left" }}>
                  <th style={{ padding: "4px 8px" }}>
                    <Box size={12} style={{ marginRight: 4, verticalAlign: "middle" }} />
                    Name
                  </th>
                  <th style={{ padding: "4px 8px" }}>Version spec</th>
                  <th style={{ padding: "4px 8px" }}>Section</th>
                  <th style={{ padding: "4px 8px" }}>Ecosystem</th>
                </tr>
              </thead>
              <tbody>
                {item.normalized.packages.map((pkg, i) => (
                  <tr key={i} style={{ borderTop: "1px solid var(--border)" }}>
                    <td style={{ padding: "6px 8px", fontFamily: "ui-monospace, monospace" }}>{pkg.name}</td>
                    <td style={{ padding: "6px 8px", color: "var(--muted)", fontFamily: "ui-monospace, monospace" }}>{pkg.version_spec}</td>
                    <td style={{ padding: "6px 8px", color: "var(--muted)" }}>{pkg.section}</td>
                    <td style={{ padding: "6px 8px" }}>
                      <span className="chip" style={{ fontSize: 11 }}>{pkg.ecosystem}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      ))}
    </>
  );
}
