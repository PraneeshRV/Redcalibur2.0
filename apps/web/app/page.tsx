"use client";

import { ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000";

type Workspace = {
  id: string;
  name: string;
  mode: string;
  purpose: string;
};

type Scope = {
  allowed_roots: string[];
  excluded_roots: string[];
  max_risk_tier: number;
  authorization_text: string;
  policy_version: string;
};

type AuditEvent = {
  id: string;
  target: string;
  risk_tier: number;
  decision: string;
  created_at: string;
};

type Preview = {
  decision: string;
  reasons: string[];
  policy_version: string;
  normalized_target: string;
};

export default function CommandCenter() {
  const [workspace, setWorkspace] = useState<Workspace | null>(null);
  const [scope, setScope] = useState<Scope | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [target, setTarget] = useState("https://example.com");
  const [targetType, setTargetType] = useState("url");
  const [riskTier, setRiskTier] = useState(1);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function refresh() {
    setError(null);
    try {
      const workspaces = (await fetch(`${API_BASE}/workspaces`).then((res) => res.json())) as Workspace[];
      const active = workspaces[0];
      if (!active) {
        setError("No workspace returned from API.");
        return;
      }
      setWorkspace(active);
      setScope(await fetch(`${API_BASE}/workspaces/${active.id}/scope`).then((res) => res.json()));
      setEvents(await fetch(`${API_BASE}/workspaces/${active.id}/audit-events`).then((res) => res.json()));
    } catch {
      setError("RedCalibur API is not reachable.");
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function runPreview() {
    if (!workspace) return;
    setError(null);
    try {
      const response = await fetch(`${API_BASE}/workspaces/${workspace.id}/run-preview`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, target_type: targetType, risk_tier: riskTier }),
      });
      setPreview(await response.json());
      await refresh();
    } catch {
      setError("Run preview failed because the API is not reachable.");
    }
  }

  return (
    <>
      <h1>Command Center</h1>
      {error ? <p className="blocked">{error}</p> : null}
      <div className="grid">
        <section className="panel">
          <h2>
            <ShieldCheck size={18} />
            Workspace
          </h2>
          <div className="meta">
            <span className="chip">{workspace?.name ?? "Loading"}</span>
            <span className="chip">Mode: {workspace?.mode ?? "loading"}</span>
            <span className="chip">Scope: {scope ? "configured" : "loading"}</span>
            <span className="chip">Max risk: {scope?.max_risk_tier ?? "-"}</span>
            <span className="chip">Policy: {scope?.policy_version ?? "-"}</span>
          </div>
          <h3>Scope</h3>
          <p>Allowed roots: {scope?.allowed_roots.join(", ") ?? "-"}</p>
          <p>Excluded roots: {scope?.excluded_roots.join(", ") ?? "-"}</p>
          <p>{scope?.authorization_text ?? "Loading scope declaration."}</p>
        </section>

        <section className="panel">
          <h2>Run Preview</h2>
          <div className="form">
            <div className="field">
              <label htmlFor="target">Target</label>
              <input id="target" value={target} onChange={(event) => setTarget(event.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="target-type">Target type</label>
              <select id="target-type" value={targetType} onChange={(event) => setTargetType(event.target.value)}>
                <option value="local_path">Local path</option>
                <option value="url">URL</option>
                <option value="domain">Domain</option>
                <option value="ip">IP</option>
                <option value="repo">Repo</option>
                <option value="package">Package</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="risk-tier">Risk tier</label>
              <select id="risk-tier" value={riskTier} onChange={(event) => setRiskTier(Number(event.target.value))}>
                <option value={0}>0 - Offline/demo</option>
                <option value={1}>1 - Passive read-only</option>
                <option value={2}>2 - Low-impact active</option>
                <option value={3}>3 - Intrusive active</option>
                <option value={4}>4 - Prohibited</option>
              </select>
            </div>
            <button className="button" type="button" onClick={runPreview}>
              Preview Decision
            </button>
          </div>
          {preview ? (
            <div>
              <h3 className={preview.decision === "allowed" ? "allowed" : "blocked"}>{preview.decision}</h3>
              <ul>
                {preview.reasons.map((reason) => (
                  <li key={reason}>{reason}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </section>
      </div>

      <section className="panel" style={{ marginTop: 16 }}>
        <h2>Audit Events</h2>
        {events.length === 0 ? <p>No run previews recorded yet.</p> : null}
        {events.map((event) => (
          <div className="event" key={event.id}>
            {event.created_at} | {event.decision} | risk {event.risk_tier} | {event.target}
          </div>
        ))}
      </section>
    </>
  );
}
