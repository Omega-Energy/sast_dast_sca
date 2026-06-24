import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { ArrowLeft, Download, Trash2, ChevronDown, ChevronUp } from "lucide-react";
import { api, ScanSummary, ScanResults } from "../api";
import { Badge, StatusBadge } from "../components/Badge";

type Tab = "bandit" | "semgrep" | "pip_audit" | "gitleaks" | "yara" | "dast" | "binary" | "clamav";

function TruncText({ text, max = 120 }: { text: string; max?: number }) {
  const [open, setOpen] = useState(false);
  if (!text) return <span className="text-slate-600 italic">—</span>;
  const clean = text.replace(/#{1,6}\s?/g, "").replace(/\*\*/g, "").replace(/\[([^\]]+)\]\([^)]+\)/g, "$1").trim();
  if (clean.length <= max) return <span>{clean}</span>;
  return (
    <span>
      {open ? clean : clean.slice(0, max) + "…"}
      <button
        onClick={() => setOpen(!open)}
        className="ml-1 inline-flex items-center text-indigo-400 hover:text-indigo-300"
      >
        {open ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
      </button>
    </span>
  );
}

const severityOrder: Record<string, number> = { HIGH: 0, ERROR: 0, MEDIUM: 1, WARNING: 1, LOW: 2, INFO: 3 };
const sortBySeverity = (a: { severity: string }, b: { severity: string }) =>
  (severityOrder[a.severity?.toUpperCase()] ?? 4) - (severityOrder[b.severity?.toUpperCase()] ?? 4);

export default function ScanDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [scan, setScan] = useState<ScanSummary | null>(null);
  const [results, setResults] = useState<ScanResults | null>(null);
  const [tab, setTab] = useState<Tab>("bandit");
  const [filter, setFilter] = useState("");
  const [sevFilter, setSevFilter] = useState("ALL");
  const [logs, setLogs] = useState<string[]>([]);

  useEffect(() => {
    if (!id) return;
    const load = async () => {
      const s = await api.getScan(Number(id));
      setScan(s);
      if (s.status === "done") {
        const r = await api.getResults(Number(id)).catch(() => null);
        setResults(r);
      }
    };
    load();
    const iv = setInterval(async () => {
      const s = await api.getScan(Number(id)).catch(() => null);
      if (!s) return;
      setScan(s);
      if (s.status === "done" && !results) {
        const r = await api.getResults(Number(id)).catch(() => null);
        setResults(r);
        clearInterval(iv);
      }
      if (s.status === "failed") clearInterval(iv);
    }, 3000);
    return () => clearInterval(iv);
  }, [id]);

  // Live log via WebSocket while scan is running
  useEffect(() => {
    if (!id || !scan) return;
    if (scan.status !== "running") return;
    const wsUrl = `ws://${window.location.host}/ws/scans/${id}/log`;
    const ws = new WebSocket(wsUrl);
    ws.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        const msg: string = data.message ?? e.data;
        if (msg === "__DONE__" || msg === "__FAILED__") return;
        setLogs((prev) => [...prev, msg].slice(-100));
      } catch {
        setLogs((prev) => [...prev, e.data].slice(-100));
      }
    };
    ws.onerror = () => ws.close();
    return () => ws.close();
  }, [id, scan?.status]);

  const handleDelete = async () => {
    if (!confirm("Delete this scan?")) return;
    await api.deleteScan(Number(id));
    navigate("/history");
  };

  const downloadJson = () => {
    if (!results) return;
    const blob = new Blob([JSON.stringify(results, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `scan-${id}-results.json`;
    a.click();
  };

  const tabs: { key: Tab; label: string; count: number }[] = [
    { key: "bandit",    label: "Bandit",    count: scan?.bandit_count ?? 0 },
    { key: "semgrep",   label: "Semgrep",   count: scan?.semgrep_count ?? 0 },
    { key: "pip_audit", label: "pip-audit", count: scan?.pip_audit_count ?? 0 },
    { key: "gitleaks",  label: "Gitleaks",  count: scan?.gitleaks_count ?? 0 },
    { key: "yara",      label: "YARA",       count: scan?.yara_count ?? 0 },
    { key: "dast",      label: "DAST (ZAP)", count: scan?.dast_count ?? 0 },
    { key: "binary",    label: "Binaries",    count: scan?.binary_count ?? 0 },
    { key: "clamav",    label: "ClamAV",      count: scan?.clamav_count ?? 0 },
  ];

  const applyFilters = <T extends { file?: string; severity?: string; title?: string; detail?: string; rule?: string; package?: string }>(
    items: T[]
  ): T[] => {
    let out = [...items];
    if (sevFilter !== "ALL") out = out.filter((i) => i.severity?.toUpperCase() === sevFilter);
    if (filter) {
      const q = filter.toLowerCase();
      out = out.filter((i) =>
        JSON.stringify(i).toLowerCase().includes(q)
      );
    }
    return out;
  };

  if (!scan) return <div className="p-8 text-slate-400">Loading…</div>;

  const banditFindings = results ? applyFilters([...results.bandit.findings].sort(sortBySeverity)) : [];
  const semgrepFindings = results ? applyFilters([...results.semgrep.findings].sort(sortBySeverity)) : [];
  const pipFindings = results ? results.pip_audit.findings.filter((f) =>
    !filter || JSON.stringify(f).toLowerCase().includes(filter.toLowerCase())
  ) : [];
  const gitleaksFindings = results ? results.gitleaks.findings.filter((f) =>
    !filter || JSON.stringify(f).toLowerCase().includes(filter.toLowerCase())
  ) : [];
  const yaraFindings = results ? applyFilters([...(results.yara?.findings ?? [])].sort(sortBySeverity)) : [];
  const dastFindings = results ? applyFilters([...(results.dast?.findings ?? [])].sort(sortBySeverity)) : [];
  const dastMeta = results?.dast;
  const binaryFindings = results ? [...(results.binary?.findings ?? [])].sort(sortBySeverity)
    .filter((f) => !filter || JSON.stringify(f).toLowerCase().includes(filter.toLowerCase())) : [];
  const clamavFindings = results ? applyFilters([...(results.clamav?.findings ?? [])].sort(sortBySeverity)) : [];
  const clamavError = results?.clamav?.error;

  return (
    <div className="p-8 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-4">
          <button onClick={() => navigate(-1)} className="mt-1 text-slate-400 hover:text-slate-200">
            <ArrowLeft size={18} />
          </button>
          <div>
            <h1 className="text-xl font-bold">{scan.repo_name}</h1>
            <a href={scan.repo_url} target="_blank" rel="noreferrer" className="text-sm text-indigo-400 hover:underline">
              {scan.repo_url}
            </a>
            <div className="flex items-center gap-3 mt-2">
              <StatusBadge status={scan.status} />
              <span className="text-xs text-slate-500 font-mono">branch: {scan.branch}</span>
              {scan.duration_sec != null && (
                <span className="text-xs text-slate-500">{scan.duration_sec.toFixed(1)}s</span>
              )}
            </div>
            {scan.error && (
              <div className="mt-2 text-xs text-red-400 bg-red-950/40 px-3 py-2 rounded-lg border border-red-800/40">
                {scan.error}
              </div>
            )}
          </div>
        </div>
        <div className="flex gap-2">
          {results && (
            <button
              onClick={downloadJson}
              className="flex items-center gap-1.5 px-3 py-2 text-xs bg-surface2 hover:bg-border rounded-lg border border-border transition-colors"
            >
              <Download size={14} /> JSON
            </button>
          )}
          <button
            onClick={handleDelete}
            className="flex items-center gap-1.5 px-3 py-2 text-xs bg-red-950/40 hover:bg-red-900/40 rounded-lg border border-red-800/40 text-red-400 transition-colors"
          >
            <Trash2 size={14} /> Delete
          </button>
        </div>
      </div>

      {/* Summary cards */}
      {scan.status === "done" && (
        <div className="grid grid-cols-4 gap-3">
          {[
            { label: "Bandit", count: scan.bandit_count, color: "text-orange-400" },
            { label: "Semgrep", count: scan.semgrep_count, color: "text-indigo-400" },
            { label: "pip-audit", count: scan.pip_audit_count, color: "text-red-400" },
            { label: "Gitleaks", count: scan.gitleaks_count, color: "text-purple-400" },
          ].map((c) => (
            <div key={c.label} className="bg-surface border border-border rounded-xl px-5 py-4">
              <div className="text-xs text-slate-500 uppercase tracking-wide mb-1">{c.label}</div>
              <div className={`text-3xl font-bold ${c.color}`}>{c.count}</div>
            </div>
          ))}
        </div>
      )}

      {scan.status !== "done" && scan.status !== "failed" && (
        <div className="bg-surface border border-border rounded-xl overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border bg-surface2">
            <span className="inline-block w-2 h-2 rounded-full bg-green-400 animate-pulse" />
            <span className="text-xs text-slate-400 font-mono">Live log</span>
          </div>
          <div className="font-mono text-xs text-slate-300 p-4 space-y-0.5 min-h-[160px] max-h-[400px] overflow-y-auto bg-[#0d1117]">
            {logs.length === 0 ? (
              <div className="text-slate-600 italic">Waiting for output…</div>
            ) : (
              logs.map((line, i) => {
                const isError = /error|fail|exception/i.test(line);
                const isWarn  = /warn|skip/i.test(line);
                const isOk    = /done|complete|found|✓/i.test(line);
                return (
                  <div key={i} className={
                    isError ? "text-red-400" :
                    isWarn  ? "text-yellow-400" :
                    isOk    ? "text-green-400" :
                    "text-slate-300"
                  }>
                    <span className="text-slate-600 select-none mr-2">&gt;</span>{line}
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}

      {/* Results */}
      {results && (
        <div className="bg-surface border border-border rounded-xl overflow-hidden">
          {/* Tabs + filters */}
          <div className="border-b border-border flex items-center justify-between px-2">
            <div className="flex">
              {tabs.map((t) => (
                <button
                  key={t.key}
                  onClick={() => { setTab(t.key); setFilter(""); setSevFilter("ALL"); }}
                  className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors ${
                    tab === t.key
                      ? "border-indigo-500 text-indigo-300"
                      : "border-transparent text-slate-500 hover:text-slate-300"
                  }`}
                >
                  {t.label}
                  <span className={`ml-2 text-xs px-1.5 py-0.5 rounded-full ${
                    t.count > 0 ? "bg-orange-900/60 text-orange-300" : "bg-surface2 text-slate-500"
                  }`}>
                    {t.count}
                  </span>
                </button>
              ))}
            </div>
            <div className="flex items-center gap-2 pr-4">
              {(tab === "bandit" || tab === "semgrep") && (
                <select
                  value={sevFilter}
                  onChange={(e) => setSevFilter(e.target.value)}
                  className="bg-surface2 border border-border text-xs text-slate-300 rounded-lg px-2 py-1.5 focus:outline-none"
                >
                  {["ALL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => (
                    <option key={s}>{s}</option>
                  ))}
                </select>
              )}
              <input
                type="text"
                placeholder="Filter…"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                className="bg-surface2 border border-border text-xs text-slate-300 rounded-lg px-3 py-1.5 focus:outline-none focus:border-indigo-500 w-40"
              />
            </div>
          </div>

          {/* Tab content */}
          <div className="overflow-x-auto">
            {tab === "bandit" && (
              <FindingsTable
                empty={banditFindings.length === 0}
                headers={["Severity", "Confidence", "File", "Line", "Rule", "Detail"]}
              >
                {banditFindings.map((f, i) => (
                  <tr key={i} className="border-b border-border/50 hover:bg-surface2/50">
                    <td className="px-4 py-2.5"><Badge severity={f.severity} /></td>
                    <td className="px-4 py-2.5"><Badge severity={f.confidence} /></td>
                    <td className="px-4 py-2.5 font-mono text-xs text-purple-400 max-w-xs truncate">{f.file}</td>
                    <td className="px-4 py-2.5 text-slate-400 text-xs">{f.line}</td>
                    <td className="px-4 py-2.5 text-xs text-slate-300">{f.title}{f.cwe && ` (CWE-${f.cwe})`}</td>
                    <td className="px-4 py-2.5 text-xs text-slate-400 max-w-sm">{f.detail}</td>
                  </tr>
                ))}
              </FindingsTable>
            )}

            {tab === "semgrep" && (
              <FindingsTable
                empty={semgrepFindings.length === 0}
                headers={["Severity", "File", "Line", "Rule", "Detail"]}
              >
                {semgrepFindings.map((f, i) => (
                  <tr key={i} className="border-b border-border/50 hover:bg-surface2/50">
                    <td className="px-4 py-2.5"><Badge severity={f.severity} /></td>
                    <td className="px-4 py-2.5 font-mono text-xs text-purple-400 max-w-xs truncate">{f.file}</td>
                    <td className="px-4 py-2.5 text-slate-400 text-xs">{f.line}</td>
                    <td className="px-4 py-2.5 text-xs text-slate-300 max-w-xs truncate">{f.title}</td>
                    <td className="px-4 py-2.5 text-xs text-slate-400 max-w-sm"><TruncText text={f.detail} /></td>
                  </tr>
                ))}
              </FindingsTable>
            )}

            {tab === "pip_audit" && (
              <FindingsTable
                empty={pipFindings.length === 0}
                headers={["Package", "Installed", "CVE / ID", "Fix Version", "Description"]}
              >
                {pipFindings.map((f, i) => (
                  <tr key={i} className="border-b border-border/50 hover:bg-surface2/50 align-top">
                    <td className="px-4 py-3 font-semibold text-slate-200 whitespace-nowrap">{f.package}</td>
                    <td className="px-4 py-3 font-mono text-xs text-slate-400 whitespace-nowrap">{f.version}</td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="font-mono text-xs text-red-300 bg-red-950/50 px-2 py-0.5 rounded border border-red-800/40">
                        {f.vuln_id || "VULN"}
                      </span>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="font-mono text-xs text-green-400">{f.fix}</span>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400 max-w-lg">
                      <TruncText text={f.detail} max={200} />
                    </td>
                  </tr>
                ))}
              </FindingsTable>
            )}

            {tab === "gitleaks" && (
              <FindingsTable
                empty={gitleaksFindings.length === 0}
                headers={["File", "Line", "Rule", "Description", "Match", "Commit"]}
              >
                {gitleaksFindings.map((f, i) => (
                  <tr key={i} className="border-b border-border/50 hover:bg-surface2/50">
                    <td className="px-4 py-2.5 font-mono text-xs text-purple-400 max-w-xs truncate">{f.file}</td>
                    <td className="px-4 py-2.5 text-slate-400 text-xs">{f.line}</td>
                    <td className="px-4 py-2.5"><Badge severity="HIGH" /></td>
                    <td className="px-4 py-2.5 text-xs text-slate-300"><TruncText text={f.description} max={80} /></td>
                    <td className="px-4 py-2.5">
                      <code className="text-xs bg-surface2 px-2 py-0.5 rounded text-yellow-400">{f.match}</code>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-slate-500">{f.commit}</td>
                  </tr>
                ))}
              </FindingsTable>
            )}

            {tab === "dast" && (
              <div>
                {dastMeta?.skipped && (
                  <div className="px-6 py-4 text-sm text-amber-400 bg-amber-950/30 border border-amber-800/30 rounded-lg mx-4 my-3">
                    <span className="font-semibold">DAST skipped:</span> {dastMeta.reason}
                  </div>
                )}
                {dastMeta?.target_url && (
                  <div className="px-6 py-2 text-xs text-slate-500">
                    Target: <span className="font-mono text-indigo-400">{dastMeta.target_url}</span>
                  </div>
                )}
                <FindingsTable
                  empty={dastFindings.length === 0}
                  headers={["Severity", "Alert", "CWE", "Count", "Description", "Solution"]}
                >
                  {dastFindings.map((f, i) => (
                    <tr key={i} className="border-b border-border/50 hover:bg-surface2/50 align-top">
                      <td className="px-4 py-3 whitespace-nowrap"><Badge severity={f.severity} /></td>
                      <td className="px-4 py-3 text-sm font-semibold text-slate-200 whitespace-nowrap">{f.name}</td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        {f.cwe ? (
                          <span className="font-mono text-xs text-blue-300 bg-blue-950/40 px-2 py-0.5 rounded border border-blue-800/40">
                            CWE-{f.cwe}
                          </span>
                        ) : <span className="text-slate-600">—</span>}
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400 text-center">{f.count}</td>
                      <td className="px-4 py-3 text-xs text-slate-400 max-w-sm">
                        <TruncText text={f.description} max={150} />
                      </td>
                      <td className="px-4 py-3 text-xs text-green-400 max-w-xs">
                        <TruncText text={f.solution} max={120} />
                      </td>
                    </tr>
                  ))}
                </FindingsTable>
              </div>
            )}

            {tab === "yara" && (
              <FindingsTable
                empty={yaraFindings.length === 0}
                headers={["Severity", "File", "Rule", "Category", "Description", "Matched String"]}
              >
                {yaraFindings.map((f, i) => (
                  <tr key={i} className="border-b border-border/50 hover:bg-surface2/50 align-top">
                    <td className="px-4 py-3 whitespace-nowrap"><Badge severity={f.severity} /></td>
                    <td className="px-4 py-3 font-mono text-xs text-purple-400 max-w-xs truncate whitespace-nowrap">{f.file}</td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="text-xs font-mono text-amber-300 bg-amber-950/40 px-2 py-0.5 rounded border border-amber-800/40">
                        {f.rule}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400 whitespace-nowrap">{f.category || "—"}</td>
                    <td className="px-4 py-3 text-xs text-slate-400 max-w-xs">
                      <TruncText text={f.detail} max={100} />
                    </td>
                    <td className="px-4 py-3">
                      {f.strings?.[0] && (
                        <code className="text-xs bg-surface2 px-2 py-0.5 rounded text-yellow-400 break-all">
                          {f.strings[0].match}
                        </code>
                      )}
                    </td>
                  </tr>
                ))}
              </FindingsTable>
            )}

            {tab === "binary" && (
              <FindingsTable
                empty={binaryFindings.length === 0}
                headers={["Severity", "File", "Size", "Entropy", "Issues"]}
              >
                {binaryFindings.map((f, i) => (
                  <tr key={i} className="border-b border-border/50 hover:bg-surface2/50 align-top">
                    <td className="px-4 py-3 whitespace-nowrap"><Badge severity={f.severity} /></td>
                    <td className="px-4 py-3 font-mono text-xs text-orange-400 max-w-xs break-all">{f.file}</td>
                    <td className="px-4 py-3 text-xs text-slate-400 whitespace-nowrap">{f.size_kb} KB</td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className={`font-mono text-xs px-2 py-0.5 rounded border ${
                        f.entropy > 7.5 ? "text-red-300 bg-red-950/40 border-red-800/40"
                        : f.entropy > 7.0 ? "text-orange-300 bg-orange-950/40 border-orange-800/40"
                        : "text-slate-400 bg-surface2 border-border"
                      }`}>{f.entropy}/8.0</span>
                    </td>
                    <td className="px-4 py-3 text-xs space-y-1">
                      {f.issues.map((issue, j) => (
                        <div key={j} className="flex items-start gap-2">
                          <Badge severity={issue.severity} />
                          <span className="text-slate-300">{issue.detail}</span>
                          {issue.match && (
                            <code className="ml-1 text-xs bg-surface2 px-1.5 py-0.5 rounded text-yellow-400 break-all">{issue.match}</code>
                          )}
                        </div>
                      ))}
                    </td>
                  </tr>
                ))}
              </FindingsTable>
            )}

            {tab === "clamav" && (
              <div>
                {clamavError && (
                  <div className="px-6 py-4 text-sm text-amber-400 bg-amber-950/30 border border-amber-800/30 rounded-lg mx-4 my-3">
                    <span className="font-semibold">ClamAV note:</span> {clamavError}
                  </div>
                )}
                {!clamavError && clamavFindings.length === 0 && (
                  <div className="px-6 py-10 text-center">
                    <div className="text-green-400 text-lg font-semibold mb-1">✓ No threats detected</div>
                    <div className="text-slate-500 text-sm">ClamAV antivirus scan completed — no malware, viruses, or trojans found.</div>
                  </div>
                )}
                {clamavFindings.length > 0 && (
                  <FindingsTable
                    empty={false}
                    headers={["Severity", "File", "Threat"]}
                  >
                    {clamavFindings.map((f, i) => (
                      <tr key={i} className="border-b border-border/50 hover:bg-surface2/50">
                        <td className="px-4 py-2.5"><Badge severity={f.severity} /></td>
                        <td className="px-4 py-2.5 font-mono text-xs text-red-400 max-w-sm break-all">{f.file}</td>
                        <td className="px-4 py-2.5">
                          <span className="text-xs font-mono text-red-300 bg-red-950/40 px-2 py-0.5 rounded border border-red-800/40">
                            {f.threat}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </FindingsTable>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function FindingsTable({
  headers, children, empty,
}: {
  headers: string[];
  children: React.ReactNode;
  empty: boolean;
}) {
  if (empty) {
    return <div className="px-6 py-10 text-center text-slate-500 italic">No findings.</div>;
  }
  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="border-b border-border text-left text-xs text-slate-500 uppercase tracking-wide">
          {headers.map((h) => <th key={h} className="px-4 py-3 font-medium">{h}</th>)}
        </tr>
      </thead>
      <tbody>{children}</tbody>
    </table>
  );
}
