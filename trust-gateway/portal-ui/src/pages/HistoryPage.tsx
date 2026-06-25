import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Trash2, RefreshCw } from "lucide-react";
import { api, ScanSummary } from "../api";
import { StatusBadge } from "../components/Badge";
import { format } from "date-fns";

export default function HistoryPage() {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  const load = async () => {
    setLoading(true);
    const data = await api.listScans().catch(() => []);
    setScans(data);
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const handleDelete = async (e: React.MouseEvent, id: number) => {
    e.stopPropagation();
    if (!confirm("Delete this scan?")) return;
    await api.deleteScan(id);
    setScans((prev) => prev.filter((s) => s.id !== id));
  };

  return (
    <div className="p-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Scan History</h1>
          <p className="text-slate-400 text-sm mt-1">{scans.length} scans total</p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 px-3 py-2 text-sm bg-surface2 hover:bg-border rounded-lg border border-border transition-colors"
        >
          <RefreshCw size={14} className={loading ? "animate-spin" : ""} /> Refresh
        </button>
      </div>

      <div className="bg-surface border border-border rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs text-slate-500 uppercase tracking-wide">
              <th className="px-6 py-3">#</th>
              <th className="px-4 py-3">Repo</th>
              <th className="px-4 py-3">Branch</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Total</th>
              <th className="px-4 py-3">Bandit</th>
              <th className="px-4 py-3">Semgrep</th>
              <th className="px-4 py-3">pip-audit</th>
              <th className="px-4 py-3">Gitleaks</th>
              <th className="px-4 py-3">DAST</th>
              <th className="px-4 py-3">Duration</th>
              <th className="px-4 py-3">Date</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr
                key={s.id}
                onClick={() => navigate(`/scan/${s.id}`)}
                className="border-b border-border/50 hover:bg-surface2 cursor-pointer transition-colors"
              >
                <td className="px-6 py-3 text-slate-500 text-xs">#{s.id}</td>
                <td className="px-4 py-3 font-medium text-slate-200 max-w-[160px] truncate">
                  <div>{s.repo_name}</div>
                  <div className="text-xs text-slate-500 truncate">{s.repo_url}</div>
                </td>
                <td className="px-4 py-3 font-mono text-xs text-slate-400">{s.branch}</td>
                <td className="px-4 py-3"><StatusBadge status={s.status} /></td>
                <td className="px-4 py-3 font-semibold text-slate-200">{s.status === "done" ? s.total_count : "—"}</td>
                <td className="px-4 py-3 text-orange-400">{s.status === "done" ? s.bandit_count : "—"}</td>
                <td className="px-4 py-3 text-indigo-400">{s.status === "done" ? s.semgrep_count : "—"}</td>
                <td className="px-4 py-3 text-red-400">{s.status === "done" ? s.pip_audit_count : "—"}</td>
                <td className="px-4 py-3 text-purple-400">{s.status === "done" ? s.gitleaks_count : "—"}</td>
                <td className="px-4 py-3 text-blue-400">
                  <span title={s.target_url || undefined}>
                    {s.status === "done" ? s.dast_count : "—"}
                  </span>
                </td>
                <td className="px-4 py-3 text-slate-500 text-xs">
                  {s.duration_sec != null ? `${s.duration_sec.toFixed(0)}s` : "—"}
                </td>
                <td className="px-4 py-3 text-slate-500 text-xs">
                  {format(new Date(s.created_at), "dd MMM HH:mm")}
                </td>
                <td className="px-4 py-3">
                  <button
                    onClick={(e) => handleDelete(e, s.id)}
                    className="text-slate-600 hover:text-red-400 transition-colors"
                  >
                    <Trash2 size={14} />
                  </button>
                </td>
              </tr>
            ))}
            {scans.length === 0 && !loading && (
              <tr>
                <td colSpan={13} className="px-6 py-10 text-center text-slate-500">
                  No scans yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
