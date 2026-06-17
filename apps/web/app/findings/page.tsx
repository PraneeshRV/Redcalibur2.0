"use client";

import { Bot, ChevronDown, ChevronRight, Download, Play, ShieldAlert } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000";

type Finding = {
  id: string;
  finding_kind: string;
  package: string;
  ecosystem: string;
  vuln_id: string;
  aliases: string[];
  severity_cvss: number;
  severity_label: string;
  kev: boolean;
  epss: number;
  priority_score: number;
  fixed_version: string | null;
  fix_available: boolean;
  evidence_id: string;
  status: string;
};

const STATUSES = ["open", "accepted", "false_positive", "fixed", "verified"];

type Claim = { text: string; evidence_ids: string[] };
type AnalystResponse = {
  kind: string;
  headline: string;
  claims: Claim[];
  citations: string[];
  provider: string;
  evidence_considered: number;
  unsupported_rejected: number;
};

type WorkspaceSummary = { id: string; name: string };

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#c0392b",
  high: "#e67e22",
  medium: "#d4a017",
  low: "#7f8c8d",
};

export default function FindingsPage() {
  const [workspace, setWorkspace] = useState<WorkspaceSummary | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [analyst, setAnalyst] = useState<AnalystResponse | null>(null);
  const [analystLoading, setAnalystLoading] = useState(false);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadFindings = useCallback(async (workspaceId: string) => {
    try {
      const list = (await fetch(`${API_BASE}/workspaces/${workspaceId}/findings`).then((r) => r.json())) as Finding[];
      setFindings(Array.isArray(list) ? list : []);
    } catch {
      setError("Failed to load findings.");
    }
  }, []);

  useEffect(() => {
    (async () => {
      setError(null);
      try {
        const workspaces = (await fetch(`${API_BASE}/workspaces`).then((r) => r.json())) as WorkspaceSummary[];
        const ws = workspaces[0] ?? null;
        if (!ws) { setError("API not reachable."); return; }
        setWorkspace(ws);
        await loadFindings(ws.id);
      } catch {
        setError("Failed to load findings.");
      }
    })();
  }, [loadFindings]);

  async function runBaseline() {
    if (!workspace) return;
    setRunning(true);
    setError(null);
    try {
      await fetch(`${API_BASE}/workspaces/${workspace.id}/runs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind: "baseline", wait: true }),
      });
      await loadFindings(workspace.id);
    } catch {
      setError("Baseline run failed — API not reachable.");
    } finally {
      setRunning(false);
    }
  }

  async function ask(kind: string) {
    if (!workspace) return;
    setAnalystLoading(true);
    try {
      const res = await fetch(`${API_BASE}/workspaces/${workspace.id}/analyst`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind }),
      });
      setAnalyst((await res.json()) as AnalystResponse);
    } catch {
      setError("Analyst request failed — API not reachable.");
    } finally {
      setAnalystLoading(false);
    }
  }

  function toggle(id: string) {
    setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));
  }

  async function setStatus(findingId: string, status: string) {
    if (!workspace) return;
    try {
      await fetch(`${API_BASE}/workspaces/${workspace.id}/findings/${findingId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status }),
      });
      await loadFindings(workspace.id);
    } catch {
      setError("Failed to update status — API not reachable.");
    }
  }

  function openReport(format: "md" | "html") {
    if (!workspace) return;
    window.open(`${API_BASE}/workspaces/${workspace.id}/report?format=${format}`, "_blank");
  }

  return (
    <>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 18 }}>
        <h1 style={{ margin: 0 }}>Findings</h1>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="button" type="button" onClick={runBaseline} disabled={running || !workspace}>
            <Play size={14} style={{ marginRight: 6, verticalAlign: "middle" }} />
            {running ? "Running…" : "Run Baseline"}
          </button>
          <button className="button" type="button" onClick={() => openReport("md")} disabled={!workspace}>
            <Download size={14} style={{ marginRight: 6, verticalAlign: "middle" }} />
            Report .md
          </button>
          <button className="button" type="button" onClick={() => openReport("html")} disabled={!workspace}>
            <Download size={14} style={{ marginRight: 6, verticalAlign: "middle" }} />
            Report .html
          </button>
        </div>
      </div>

      {error ? <p className="blocked">{error}</p> : null}

      <div className="grid">
        <section className="panel">
          <h2><ShieldAlert size={16} /> Triage ({findings.length})</h2>
          {findings.length === 0 ? (
            <p style={{ color: "var(--muted)" }}>No findings yet. Run a baseline assessment to enrich packages against the offline vulnerability feed.</p>
          ) : null}
          {findings.map((f) => (
            <div key={f.id} style={{ borderTop: "1px solid var(--border)", padding: "8px 0" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }} onClick={() => toggle(f.id)}>
                {expanded[f.id] ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                <span className="chip" style={{ background: SEVERITY_COLOR[f.severity_label] ?? "#555", color: "#fff" }}>
                  {f.priority_score}
                </span>
                <strong style={{ fontFamily: "ui-monospace, monospace" }}>{f.ecosystem}:{f.package}</strong>
                <span style={{ color: "var(--muted)" }}>{f.vuln_id}</span>
                {f.kev ? <span className="blocked" style={{ fontSize: 11 }}>KEV</span> : null}
                <span className="chip" style={{ fontSize: 11 }}>{f.status}</span>
                <span style={{ marginLeft: "auto", color: "var(--muted)", fontSize: 12 }}>{f.severity_label}</span>
              </div>
              {expanded[f.id] && (
                <div style={{ margin: "8px 0 0 22px", fontSize: 13 }}>
                  <p style={{ margin: "2px 0" }}>CVSS {f.severity_cvss} · EPSS {f.epss} · {f.aliases.join(", ") || "no aliases"}</p>
                  <p style={{ margin: "2px 0" }}>
                    {f.fix_available ? <>Fix available: upgrade to <strong>{f.fixed_version}</strong></> : "No fixed version in feed"}
                  </p>
                  <p style={{ margin: "2px 0", color: "var(--muted)" }}>Evidence: <code>{f.evidence_id}</code></p>
                  <label style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 6 }}>
                    Status:
                    <select value={f.status} onChange={(e) => setStatus(f.id, e.target.value)}>
                      {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </label>
                </div>
              )}
            </div>
          ))}
        </section>

        <section className="panel">
          <h2><Bot size={16} /> AI Analyst</h2>
          <p style={{ color: "var(--muted)", fontSize: 13, marginTop: 0 }}>
            Evidence-backed (mock provider). Every claim cites the evidence it came from; ungrounded claims are rejected.
          </p>
          <div className="meta" style={{ marginBottom: 12 }}>
            <button className="button" type="button" onClick={() => ask("prioritize")} disabled={analystLoading || !workspace}>What should I fix first?</button>
            <button className="button" type="button" onClick={() => ask("explain_findings")} disabled={analystLoading || !workspace}>Explain findings</button>
            <button className="button" type="button" onClick={() => ask("remediate")} disabled={analystLoading || !workspace}>Draft remediation</button>
          </div>
          {analystLoading ? <p style={{ color: "var(--muted)" }}>Analyzing…</p> : null}
          {analyst ? (
            <div>
              <h3 style={{ marginBottom: 6 }}>{analyst.headline}</h3>
              <ul>
                {analyst.claims.map((claim, i) => (
                  <li key={i} style={{ marginBottom: 6 }}>
                    {claim.text}
                    <span style={{ color: "var(--muted)", fontSize: 11 }}> — cites {claim.evidence_ids.length} evidence item(s)</span>
                  </li>
                ))}
              </ul>
              <p style={{ color: "var(--muted)", fontSize: 12 }}>
                Provider: {analyst.provider} · considered {analyst.evidence_considered} evidence item(s) · rejected {analyst.unsupported_rejected} unsupported claim(s)
              </p>
            </div>
          ) : null}
        </section>
      </div>
    </>
  );
}
