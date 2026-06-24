import { useEffect, useState } from "react";
import { api, ScanSummary, ScanResults } from "../api";

function DiffCell({ a, b }: { a: number; b: number }) {
  const diff = b - a;
  if (diff === 0) return <span className="text-slate-400">{b}</span>;
  if (diff > 0) return <span className="text-red-400 font-semibold">{b} (+{diff})</span>;
  return <span className="text-green-400 font-semibold">{b} ({diff})</span>;
}

export default function CompareScans() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [leftId, setLeftId] = useState<number | "">("");
  const [rightId, setRightId] = useState<number | "">("");
  const [leftResults, setLeftResults] = useState<ScanResults | null>(null);
  const [rightResults, setRightResults] = useState<ScanResults | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api.listScans().then((s) => setScans(s.filter((x) => x.status === "done"))).catch(() => {});
  }, []);

  const handleCompare = async () => {
    if (!leftId || !rightId) return;
    setLoading(true);
    const [l, r] = await Promise.all([
      api.getResults(Number(leftId)).catch(() => null),
      api.getResults(Number(rightId)).catch(() => null),
    ]);
    setLeftResults(l);
    setRightResults(r);
    setLoading(false);
  };

  const leftScan = scans.find((s) => s.id === leftId);
  const rightScan = scans.find((s) => s.id === rightId);

  const rows = [
    { label: "Bandit", left: leftScan?.bandit_count ?? 0, right: rightScan?.bandit_count ?? 0 },
    { label: "Semgrep", left: leftScan?.semgrep_count ?? 0, right: rightScan?.semgrep_count ?? 0 },
    { label: "pip-audit", left: leftScan?.pip_audit_count ?? 0, right: rightScan?.pip_audit_count ?? 0 },
    { label: "Gitleaks", left: leftScan?.gitleaks_count ?? 0, right: rightScan?.gitleaks_count ?? 0 },
    { label: "Total", left: leftScan?.total_count ?? 0, right: rightScan?.total_count ?? 0 },
  ];

  const selectCls = "w-full bg-surface2 border border-border text-sm text-slate-200 rounded-lg px-3 py-2.5 focus:outline-none focus:border-indigo-500";

  return (
    <div className="p-8 space-y-6 max-w-5xl">
      <div>
        <h1 className="text-2xl font-bold">Compare Scans</h1>
        <p className="text-slate-400 text-sm mt-1">Side-by-side comparison of two completed scans</p>
      </div>

      {/* Selectors */}
      <div className="bg-surface border border-border rounded-xl p-6 flex items-end gap-6">
        <div className="flex-1">
          <label className="block text-xs font-medium text-slate-400 mb-2 uppercase tracking-wide">Baseline (Left)</label>
          <select value={leftId} onChange={(e) => setLeftId(Number(e.target.value) || "")} className={selectCls}>
            <option value="">Select scan…</option>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>#{s.id} — {s.repo_name} / {s.branch}</option>
            ))}
          </select>
        </div>
        <div className="text-slate-600 font-bold text-xl pb-2">vs</div>
        <div className="flex-1">
          <label className="block text-xs font-medium text-slate-400 mb-2 uppercase tracking-wide">Target (Right)</label>
          <select value={rightId} onChange={(e) => setRightId(Number(e.target.value) || "")} className={selectCls}>
            <option value="">Select scan…</option>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>#{s.id} — {s.repo_name} / {s.branch}</option>
            ))}
          </select>
        </div>
        <button
          onClick={handleCompare}
          disabled={!leftId || !rightId || loading}
          className="px-6 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 rounded-lg text-sm font-semibold transition-colors shrink-0"
        >
          {loading ? "Loading…" : "Compare"}
        </button>
      </div>

      {/* Summary table */}
      {leftScan && rightScan && (
        <div className="bg-surface border border-border rounded-xl overflow-hidden">
          <div className="border-b border-border px-6 py-4">
            <h2 className="text-sm font-semibold text-slate-300">Finding Counts</h2>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-xs text-slate-500 uppercase tracking-wide">
                <th className="px-6 py-3 text-left">Tool</th>
                <th className="px-6 py-3 text-center">#{leftScan.id} {leftScan.repo_name}</th>
                <th className="px-6 py-3 text-center">#{rightScan.id} {rightScan.repo_name}</th>
                <th className="px-6 py-3 text-center">Δ Change</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.label} className="border-b border-border/50">
                  <td className="px-6 py-3 font-medium text-slate-300">{r.label}</td>
                  <td className="px-6 py-3 text-center text-slate-300">{r.left}</td>
                  <td className="px-6 py-3 text-center"><DiffCell a={r.left} b={r.right} /></td>
                  <td className="px-6 py-3 text-center">
                    {(() => {
                      const d = r.right - r.left;
                      if (d === 0) return <span className="text-slate-500">—</span>;
                      return <span className={d > 0 ? "text-red-400" : "text-green-400"}>{d > 0 ? `+${d}` : d}</span>;
                    })()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* New findings in right not in left */}
      {leftResults && rightResults && (
        <div className="space-y-4">
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wide">
            New Bandit findings in #{rightScan?.id} not present in #{leftScan?.id}
          </h2>
          {(() => {
            const leftFiles = new Set(leftResults.bandit.findings.map((f) => `${f.file}:${f.line}:${f.title}`));
            const newFindings = rightResults.bandit.findings.filter(
              (f) => !leftFiles.has(`${f.file}:${f.line}:${f.title}`)
            );
            if (newFindings.length === 0) {
              return <p className="text-slate-500 italic text-sm">No new Bandit findings.</p>;
            }
            return (
              <div className="bg-surface border border-border rounded-xl overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border text-xs text-slate-500 uppercase">
                      <th className="px-4 py-3 text-left">Severity</th>
                      <th className="px-4 py-3 text-left">File</th>
                      <th className="px-4 py-3 text-left">Line</th>
                      <th className="px-4 py-3 text-left">Rule</th>
                      <th className="px-4 py-3 text-left">Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {newFindings.map((f, i) => (
                      <tr key={i} className="border-b border-border/50 bg-red-950/10">
                        <td className="px-4 py-2.5">
                          <span className={`badge-${f.severity} inline-block px-2 py-0.5 rounded text-xs font-semibold uppercase`}>{f.severity}</span>
                        </td>
                        <td className="px-4 py-2.5 font-mono text-xs text-purple-400 max-w-xs truncate">{f.file}</td>
                        <td className="px-4 py-2.5 text-slate-400 text-xs">{f.line}</td>
                        <td className="px-4 py-2.5 text-xs text-slate-300">{f.title}</td>
                        <td className="px-4 py-2.5 text-xs text-slate-400 max-w-sm">{f.detail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            );
          })()}
        </div>
      )}
    </div>
  );
}
