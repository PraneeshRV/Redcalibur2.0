"use client";

import { CheckCircle2, FlaskConical, Play, ShieldAlert } from "lucide-react";
import { useCallback, useEffect, useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000";

type Finding = {
  id: string;
  finding_kind: string;
  package: string;
  vuln_id: string;
  severity_label: string;
  priority_score: number;
  status: string;
};

type WorkspaceSummary = { id: string; name: string };

const CATEGORY_LABEL: Record<string, string> = {
  "prompt_injection": "Prompt Injection",
  "rag_leakage": "RAG Leakage",
  "unsafe_tool_use": "Unsafe Tool Use",
};

export default function LabPage() {
  const [workspace, setWorkspace] = useState<WorkspaceSummary | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [running, setRunning] = useState(false);
  const [verifying, setVerifying] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadFindings = useCallback(async (workspaceId: string) => {
    try {
      const list = (await fetch(`${API_BASE}/workspaces/${workspaceId}/findings`).then((r) => r.json())) as Finding[];
      setFindings((Array.isArray(list) ? list : []).filter((f) => f.finding_kind === "ai_eval"));
    } catch {
      setError("Failed to load eval findings.");
    }
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const workspaces = (await fetch(`${API_BASE}/workspaces`).then((r) => r.json())) as WorkspaceSummary[];
        const ws = workspaces[0] ?? null;
        if (!ws) { setError("API not reachable."); return; }
        setWorkspace(ws);
        await loadFindings(ws.id);
      } catch {
        setError("API not reachable.");
      }
    })();
  }, [loadFindings]);

  async function runEval() {
    if (!workspace) return;
    setRunning(true);
    setError(null);
    try {
      await fetch(`${API_BASE}/workspaces/${workspace.id}/runs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind: "ai_eval", wait: true }),
      });
      await loadFindings(workspace.id);
    } catch {
      setError("Eval run failed — API not reachable.");
    } finally {
      setRunning(false);
    }
  }

  async function verify(findingId: string) {
    if (!workspace) return;
    setVerifying(findingId);
    try {
      await fetch(`${API_BASE}/workspaces/${workspace.id}/findings/${findingId}/verify`, { method: "POST" });
      await loadFindings(workspace.id);
    } catch {
      setError("Verify failed — API not reachable.");
    } finally {
      setVerifying(null);
    }
  }

  const byCategory = findings.reduce<Record<string, Finding[]>>((acc, f) => {
    const cat = f.vuln_id.startsWith("pi") ? "prompt_injection" : f.vuln_id.startsWith("rag") ? "rag_leakage" : "unsafe_tool_use";
    (acc[cat] = acc[cat] ?? []).push(f);
    return acc;
  }, {});

  return (
    <>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 18 }}>
        <h1 style={{ margin: 0 }}>AI Security Lab</h1>
        <button className="button" type="button" onClick={runEval} disabled={running || !workspace}>
          <Play size={14} style={{ marginRight: 6, verticalAlign: "middle" }} />
          {running ? "Running…" : "Run Eval Suites"}
        </button>
      </div>

      <p style={{ color: "var(--muted)", marginTop: 0 }}>
        Offline prompt-injection, RAG-leakage, and unsafe-tool-use suites against a local mock AI app. No network, no live model calls.
        Click <strong>Verify</strong> on a finding to re-run its probe against a hardened target.
      </p>

      {error ? <p className="blocked">{error}</p> : null}

      {findings.length === 0 ? (
        <p style={{ color: "var(--muted)" }}>No eval findings yet. Run the suites to probe the mock target.</p>
      ) : null}

      <div className="grid">
        {Object.entries(byCategory).map(([cat, items]) => (
          <section key={cat} className="panel">
            <h2><ShieldAlert size={16} /> {CATEGORY_LABEL[cat] ?? cat} ({items.length})</h2>
            {items.map((f) => (
              <div key={f.id} style={{ borderTop: "1px solid var(--border)", padding: "8px 0", display: "flex", alignItems: "center", gap: 8 }}>
                <FlaskConical size={14} />
                <span style={{ fontFamily: "ui-monospace, monospace" }}>{f.vuln_id}</span>
                <span className={f.status === "verified" ? "allowed" : "blocked"} style={{ fontSize: 11 }}>
                  {f.status}
                </span>
                <button
                  className="button"
                  type="button"
                  style={{ marginLeft: "auto", padding: "2px 10px" }}
                  onClick={() => verify(f.id)}
                  disabled={verifying === f.id || f.status === "verified"}
                >
                  {f.status === "verified" ? <><CheckCircle2 size={12} style={{ verticalAlign: "middle", marginRight: 4 }} />Verified</> : verifying === f.id ? "Verifying…" : "Verify"}
                </button>
              </div>
            ))}
          </section>
        ))}
      </div>
    </>
  );
}
