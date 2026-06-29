import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend,
} from "recharts";
import {
  ShieldAlert, ShieldCheck, Layers, KeyRound, Bug, ScanSearch,
} from "lucide-react";
import { api, Stats, ScanSummary } from "../api";
import { StatCard } from "../components/StatCard";
import { StatusBadge } from "../components/Badge";

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [recent, setRecent] = useState<ScanSummary[]>([]);
  const navigate = useNavigate();

  useEffect(() => {
    api.getStats().then(setStats).catch(console.error);
    api.listScans().then((s) => setRecent(s.slice(0, 5))).catch(console.error);
    const iv = setInterval(() => {
      api.getStats().then(setStats).catch(() => {});
      api.listScans().then((s) => setRecent(s.slice(0, 5))).catch(() => {});
    }, 5000);
    return () => clearInterval(iv);
  }, []);

  const chartData = (stats?.history ?? []).map((h) => ({
    name: h.repo_name.slice(0, 12),
    Bandit: h.bandit_count,
    Semgrep: h.semgrep_count,
    "pip-audit": h.pip_audit_count,
    "npm audit": h.npm_audit_count,
    Gitleaks: h.gitleaks_count,
  }));

  return (
    <div className="p-8 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="text-slate-400 text-sm mt-1">Security scan overview</p>
        </div>
        <button
          onClick={() => navigate("/scan")}
          className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 px-4 py-2 rounded-lg text-sm font-medium transition-colors"
        >
          <ScanSearch size={16} /> New Scan
        </button>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <StatCard label="Total Scans" value={stats?.total_scans ?? "—"} icon={Layers} color="slate" />
        <StatCard label="Completed" value={stats?.done ?? "—"} icon={ShieldCheck} color="green" />
        <StatCard label="Failed" value={stats?.failed ?? "—"} icon={ShieldAlert} color="red" />
        <StatCard label="Bandit" value={stats?.bandit_total ?? "—"} icon={Bug} color="orange" sub="SAST findings" />
        <StatCard label="pip-audit" value={stats?.pip_audit_total ?? "—"} icon={Layers} color="red" sub="Python CVE" />
        <StatCard label="npm audit" value={stats?.npm_audit_total ?? "—"} icon={Layers} color="pink" sub="Node CVE" />
        <StatCard label="Secrets" value={stats?.gitleaks_total ?? "—"} icon={KeyRound} color="purple" sub="Gitleaks" />
      </div>

      {/* Chart */}
      {chartData.length > 0 && (
        <div className="bg-surface border border-border rounded-xl p-6">
          <h2 className="text-sm font-semibold text-slate-300 mb-4">Findings per scan</h2>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={chartData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
              <XAxis dataKey="name" tick={{ fill: "#64748b", fontSize: 11 }} />
              <YAxis tick={{ fill: "#64748b", fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: "#1a1d27", border: "1px solid #2e3250", borderRadius: 8 }}
                labelStyle={{ color: "#e2e8f0" }}
              />
              <Legend wrapperStyle={{ fontSize: 12, color: "#94a3b8" }} />
              <Bar dataKey="Bandit" fill="#f97316" radius={[3, 3, 0, 0]} />
              <Bar dataKey="Semgrep" fill="#6366f1" radius={[3, 3, 0, 0]} />
              <Bar dataKey="pip-audit" fill="#ef4444" radius={[3, 3, 0, 0]} />
              <Bar dataKey="Gitleaks" fill="#a855f7" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Recent scans */}
      <div className="bg-surface border border-border rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-border flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-300">Recent Scans</h2>
          <button onClick={() => navigate("/history")} className="text-xs text-indigo-400 hover:text-indigo-300">
            View all →
          </button>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left text-xs text-slate-500 uppercase tracking-wide">
              <th className="px-6 py-3">Repo</th>
              <th className="px-4 py-3">Branch</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Findings</th>
              <th className="px-4 py-3">Time</th>
            </tr>
          </thead>
          <tbody>
            {recent.map((s) => (
              <tr
                key={s.id}
                onClick={() => navigate(`/scan/${s.id}`)}
                className="border-b border-border/50 hover:bg-surface2 cursor-pointer transition-colors"
              >
                <td className="px-6 py-3 font-medium text-slate-200">{s.repo_name}</td>
                <td className="px-4 py-3 text-slate-400 font-mono text-xs">{s.branch}</td>
                <td className="px-4 py-3"><StatusBadge status={s.status} /></td>
                <td className="px-4 py-3">
                  {s.status === "done" ? (
                    <span className={s.total_count > 0 ? "text-orange-400 font-semibold" : "text-green-400"}>
                      {s.total_count}
                    </span>
                  ) : "—"}
                </td>
                <td className="px-4 py-3 text-slate-500 text-xs">
                  {s.duration_sec != null ? `${s.duration_sec.toFixed(0)}s` : "—"}
                </td>
              </tr>
            ))}
            {recent.length === 0 && (
              <tr>
                <td colSpan={5} className="px-6 py-8 text-center text-slate-500">
                  No scans yet. <button onClick={() => navigate("/scan")} className="text-indigo-400 underline">Start one</button>.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
