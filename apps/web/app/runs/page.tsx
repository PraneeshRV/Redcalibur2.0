"use client";

import { Activity, Ban, ChevronDown, ChevronRight, Play, Square } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000";

type Job = {
  id: string;
  tool_id: string;
  status: string;
  output_summary: Record<string, unknown> | null;
  error: string | null;
  started_at: string;
  finished_at: string | null;
};

type EvidenceItem = {
  id: string;
  source_tool: string;
  evidence_type: string;
  title: string;
  summary: string;
  normalized: Record<string, unknown>;
  collected_at: string;
};

type Run = {
  id: string;
  kind: string;
  status: string;
  started_at: string;
  finished_at: string | null;
};

type RunResponse = { run: Run; jobs: Job[]; evidence: EvidenceItem[] };
type WorkspaceSummary = { id: string; name: string };

const TERMINAL = new Set(["complete", "failed", "cancelled"]);
const ACTIVE = new Set(["queued", "running", "cancelling"]);

function shortTool(toolId: string): string {
  return toolId.split(".").pop() ?? toolId;
}

function statusClass(status: string): string {
  if (status === "complete") return "allowed";
  if (status === "failed") return "blocked";
  return "";
}

export default function RunsPage() {
  const [workspace, setWorkspace] = useState<WorkspaceSummary | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  const [selected, setSelected] = useState<RunResponse | null>(null);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadRuns = useCallback(async (workspaceId: string) => {
    try {
      const list = (await fetch(`${API_BASE}/workspaces/${workspaceId}/runs`).then((r) => r.json())) as Run[];
      setRuns(list);
      return list;
    } catch {
      return [] as Run[];
    }
  }, []);

  const loadRun = useCallback(async (runId: string) => {
    try {
      const data = (await fetch(`${API_BASE}/runs/${runId}`).then((r) => r.json())) as RunResponse;
      setSelected(data);
      return data;
    } catch {
      return null;
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
        const list = await loadRuns(ws.id);
        if (list[0]) await loadRun(list[0].id);
      } catch {
        setError("Failed to load runs.");
      }
    })();
  }, [loadRuns, loadRun]);

  // Live progress: while the selected run is active, poll it (and the run list)
  // until it reaches a terminal state.
  useEffect(() => {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
    const runId = selected?.run.id;
    const status = selected?.run.status;
    if (!runId || !status || TERMINAL.has(status)) return;
    pollRef.current = setInterval(async () => {
      const data = await loadRun(runId);
      if (workspace) await loadRuns(workspace.id);
      if (data && TERMINAL.has(data.run.status) && pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    }, 700);
    return () => {
      if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
    };
  }, [selected?.run.id, selected?.run.status, workspace, loadRun, loadRuns]);

  async function startBaseline() {
    if (!workspace) return;
    setStarting(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/workspaces/${workspace.id}/runs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ kind: "baseline", wait: false }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setError((body as { detail?: string }).detail ?? "Failed to start run.");
        return;
      }
      const data = (await res.json()) as RunResponse;
      setSelected(data);
      await loadRuns(workspace.id);
    } catch {
      setError("Failed to start run — API not reachable.");
    } finally {
      setStarting(false);
    }
  }

  async function cancelRun(runId: string) {
    try {
      const res = await fetch(`${API_BASE}/runs/${runId}/cancel`, { method: "POST" });
      if (res.ok) setSelected((await res.json()) as RunResponse);
    } catch {
      setError("Cancel failed — API not reachable.");
    }
  }

  function toggle(id: string) {
    setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));
  }

  const run = selected?.run ?? null;
  const isActive = run ? ACTIVE.has(run.status) : false;
  const jobsDone = selected?.jobs.filter((j) => TERMINAL.has(j.status)).length ?? 0;
  const jobsTotal = selected?.jobs.length ?? 0;

  return (
    <>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 18 }}>
        <h1 style={{ margin: 0 }}>Runs</h1>
        <button className="button" type="button" onClick={startBaseline} disabled={starting || !workspace}>
          <Play size={14} style={{ marginRight: 6, verticalAlign: "middle" }} />
          {starting ? "Starting…" : "Start Baseline Assessment"}
        </button>
      </div>

      {error ? <p className="blocked">{error}</p> : null}

      <div className="grid">
        <section className="panel">
          <h2><Activity size={16} /> Run History</h2>
          {runs.length === 0 ? <p style={{ color: "var(--muted)" }}>No runs yet.</p> : null}
          {runs.map((r) => (
            <div
              key={r.id}
              className={`event${selected?.run.id === r.id ? " nav-item--active" : ""}`}
              style={{ cursor: "pointer", display: "flex", justifyContent: "space-between", gap: 8 }}
              onClick={() => loadRun(r.id)}
            >
              <span>{r.kind}</span>
              <span className={statusClass(r.status)}>{r.status}</span>
              <span style={{ color: "var(--muted)" }}>{r.started_at.slice(0, 19).replace("T", " ")}</span>
            </div>
          ))}
        </section>

        <section className="panel">
          <h2>Run Detail</h2>
          {!run ? (
            <p style={{ color: "var(--muted)" }}>Select a run, or start a baseline assessment.</p>
          ) : (
            <>
              <div className="meta" style={{ marginBottom: 12 }}>
                <span className="chip">Kind: {run.kind}</span>
                <span className={`chip ${statusClass(run.status)}`}>Status: {run.status}</span>
                <span className="chip">Jobs: {jobsDone}/{jobsTotal}</span>
                {isActive ? (
                  <button className="button" type="button" onClick={() => cancelRun(run.id)} style={{ padding: "2px 10px" }}>
                    <Square size={12} style={{ marginRight: 4, verticalAlign: "middle" }} />
                    Cancel
                  </button>
                ) : null}
              </div>

              <h3>Jobs</h3>
              {(selected?.jobs ?? []).map((job) => {
                const ev = (selected?.evidence ?? []).filter((e) => e.source_tool === job.tool_id);
                return (
                  <div key={job.id} style={{ borderTop: "1px solid var(--border)", padding: "8px 0" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, cursor: ev.length ? "pointer" : "default" }} onClick={() => ev.length && toggle(job.id)}>
                      {ev.length ? (expanded[job.id] ? <ChevronDown size={14} /> : <ChevronRight size={14} />) : <span style={{ width: 14 }} />}
                      <strong style={{ fontFamily: "ui-monospace, monospace" }}>{shortTool(job.tool_id)}</strong>
                      <span className={`chip ${statusClass(job.status)}`} style={{ fontSize: 11 }}>{job.status}</span>
                      {job.status === "failed" && job.error?.includes("exceeds") ? (
                        <span className="blocked" style={{ fontSize: 11 }}><Ban size={11} style={{ verticalAlign: "middle" }} /> blocked by policy</span>
                      ) : null}
                      <span style={{ marginLeft: "auto", color: "var(--muted)", fontSize: 12 }}>{ev.length} evidence</span>
                    </div>
                    {job.error ? <p className="blocked" style={{ fontSize: 12, margin: "4px 0 0 22px" }}>{job.error}</p> : null}
                    {expanded[job.id] && ev.map((item) => (
                      <div key={item.id} style={{ margin: "8px 0 0 22px", padding: 8, background: "var(--panel-2, rgba(0,0,0,0.15))", borderRadius: 6 }}>
                        <div style={{ fontWeight: 600 }}>{item.title}</div>
                        <div style={{ color: "var(--muted)", fontSize: 12, marginBottom: 6 }}>{item.evidence_type}</div>
                        <p style={{ margin: 0, fontSize: 13 }}>{item.summary}</p>
                      </div>
                    ))}
                  </div>
                );
              })}
            </>
          )}
        </section>
      </div>
    </>
  );
}
