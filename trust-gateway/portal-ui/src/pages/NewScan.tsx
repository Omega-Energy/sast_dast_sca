import { useState, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { ScanSearch, Eye, EyeOff, Github, FolderOpen, Shield, Globe, Zap, AlertTriangle, CheckCircle2 } from "lucide-react";
import { api, ScanSummary } from "../api";

export default function NewScan() {
  const [mode, setMode] = useState<"github" | "local">("github");
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("main");
  const [token, setToken] = useState("");
  const [showToken, setShowToken] = useState(false);
  const [localPath, setLocalPath] = useState("");
  const [localName, setLocalName] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [dastEnabled, setDastEnabled] = useState(false);
  const [loading, setLoading] = useState(false);

  const targetUrlValid = !targetUrl.trim() || /^https?:\/\/.+/.test(targetUrl.trim());
  const dastMode = dastEnabled && targetUrl.trim() ? "zap" : dastEnabled ? "local" : "off";
  const [scan, setScan] = useState<ScanSummary | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [done, setDone] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logs]);

  function toContainerPath(p: string): string {
    // Convert Windows path like C:\DEV\foo → /mnt/c/DEV/foo
    const win = p.match(/^([A-Za-z]):[\\\/](.*)/);
    if (win) {
      const drive = win[1].toLowerCase();
      const rest = win[2].replace(/\\/g, "/");
      return `/mnt/${drive}/${rest}`;
    }
    return p;
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (mode === "github" && !repoUrl.trim()) return;
    if (mode === "local" && !localPath.trim()) return;
    setLoading(true);
    setLogs([]);
    setDone(false);
    try {
      const s = mode === "github"
        ? await api.createScan(repoUrl.trim(), branch.trim() || "main", token.trim(), targetUrl.trim())
        : await api.createLocalScan(toContainerPath(localPath.trim()), localName.trim(), targetUrl.trim());
      setScan(s);
      const ws = api.wsLog(s.id);
      ws.onmessage = (ev) => {
        const data = JSON.parse(ev.data);
        const msg: string = data.message;
        if (msg === "__DONE__") {
          setDone(true);
          ws.close();
          setLoading(false);
        } else if (msg === "__FAILED__") {
          setDone(true);
          ws.close();
          setLoading(false);
        } else {
          setLogs((prev) => [...prev, msg]);
        }
      };
      ws.onerror = () => {
        setLoading(false);
        setDone(true);
      };
    } catch (err) {
      setLogs([`Error: ${err}`]);
      setLoading(false);
    }
  }

  return (
    <div className="p-8 max-w-3xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">New Scan</h1>
        <p className="text-slate-400 text-sm mt-1">Scan a GitHub repository or a local directory</p>
      </div>

      <form onSubmit={handleSubmit} className="bg-surface border border-border rounded-xl p-6 space-y-5">
        {/* Mode switcher */}
        <div className="flex gap-2 p-1 bg-surface2 rounded-lg w-fit">
          <button type="button" onClick={() => setMode("github")}
            className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              mode === "github" ? "bg-indigo-600 text-white" : "text-slate-400 hover:text-slate-200"
            }`}>
            <Github size={14} /> GitHub URL
          </button>
          <button type="button" onClick={() => setMode("local")}
            className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              mode === "local" ? "bg-indigo-600 text-white" : "text-slate-400 hover:text-slate-200"
            }`}>
            <FolderOpen size={14} /> Local Path
          </button>
        </div>

        {mode === "github" && (
          <>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">Repository URL *</label>
              <input type="url" value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/owner/repo" required={mode==="github"} disabled={loading}
                className="w-full bg-surface2 border border-border rounded-lg px-4 py-2.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-indigo-500 disabled:opacity-50" />
            </div>
            <div className="flex gap-4">
              <div className="flex-1">
                <label className="block text-sm font-medium text-slate-300 mb-1.5">Branch</label>
                <input type="text" value={branch} onChange={(e) => setBranch(e.target.value)} disabled={loading}
                  className="w-full bg-surface2 border border-border rounded-lg px-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-indigo-500 disabled:opacity-50" />
              </div>
              <div className="flex-1">
                <label className="block text-sm font-medium text-slate-300 mb-1.5">
                  GitHub Token <span className="text-slate-500">(private repos)</span>
                </label>
                <div className="relative">
                  <input type={showToken ? "text" : "password"} value={token} onChange={(e) => setToken(e.target.value)}
                    placeholder="ghp_…" disabled={loading}
                    className="w-full bg-surface2 border border-border rounded-lg px-4 py-2.5 pr-10 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-indigo-500 disabled:opacity-50" />
                  <button type="button" onClick={() => setShowToken((v) => !v)}
                    className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300">
                    {showToken ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>
            </div>
          </>
        )}

        {mode === "local" && (
          <>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">Local Path (inside container) *</label>
              <input type="text" value={localPath} onChange={(e) => setLocalPath(e.target.value)}
                placeholder="/mnt/projects/my-app  or  /app/projects/my-app"
                required={mode==="local"} disabled={loading}
                className="w-full bg-surface2 border border-border rounded-lg px-4 py-2.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-indigo-500 disabled:opacity-50" />
              <p className="text-xs text-slate-500 mt-1">Mount your project folder via docker-compose volume, e.g.: <code className="bg-surface2 px-1 rounded">./my-app:/mnt/projects/my-app</code></p>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-1.5">Display Name <span className="text-slate-500">(optional)</span></label>
              <input type="text" value={localName} onChange={(e) => setLocalName(e.target.value)}
                placeholder="my-app" disabled={loading}
                className="w-full bg-surface2 border border-border rounded-lg px-4 py-2.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-indigo-500 disabled:opacity-50" />
            </div>
          </>
        )}

        <div className="border border-border rounded-lg p-4 space-y-4 bg-surface/50">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield size={18} className="text-indigo-400" />
              <span className="text-sm font-semibold text-slate-200">Dynamic Application Security Testing (DAST)</span>
            </div>
            <label className="inline-flex items-center gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={dastEnabled}
                onChange={(e) => setDastEnabled(e.target.checked)}
                disabled={loading}
                className="rounded border-border bg-surface2 text-indigo-600 focus:ring-indigo-500"
              />
              <span className="text-sm text-slate-300">Enable DAST</span>
            </label>
          </div>

          {dastEnabled && (
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-xs">
                {dastMode === "zap" ? (
                  <span className="flex items-center gap-1 px-2 py-1 rounded bg-blue-950/40 border border-blue-800/40 text-blue-300">
                    <Zap size={12} /> OWASP ZAP mode
                  </span>
                ) : (
                  <span className="flex items-center gap-1 px-2 py-1 rounded bg-amber-950/40 border border-amber-800/40 text-amber-300">
                    <AlertTriangle size={12} /> Local auto-launch mode
                  </span>
                )}
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1.5">
                  Target URL <span className="text-slate-500">(optional)</span>
                </label>
                <div className="relative">
                  <Globe size={16} className="absolute left-3 top-3 text-slate-500" />
                  <input
                    type="url"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    placeholder="http://localhost:3000"
                    disabled={loading}
                    className={`w-full bg-surface2 border rounded-lg pl-10 pr-4 py-2.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-indigo-500 disabled:opacity-50 ${
                      targetUrlValid ? "border-border" : "border-red-500 focus:border-red-500"
                    }`}
                  />
                </div>
                {targetUrlValid ? (
                  <p className="text-xs text-slate-500 mt-1.5 flex items-center gap-1">
                    <CheckCircle2 size={12} />
                    {dastMode === "zap"
                      ? "OWASP ZAP will spider and actively scan the provided URL."
                      : "The scanner will try to auto-launch and test the local application."}
                  </p>
                ) : (
                  <p className="text-xs text-red-400 mt-1.5">Please enter a valid http:// or https:// URL.</p>
                )}
              </div>
            </div>
          )}

          {!dastEnabled && (
            <p className="text-xs text-slate-500">Enable DAST to scan a running application with OWASP ZAP or the local fallback scanner.</p>
          )}
        </div>

        <button type="submit"
          disabled={loading || (mode==="github" ? !repoUrl.trim() : !localPath.trim()) || !targetUrlValid}
          className="w-full flex items-center justify-center gap-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed px-6 py-3 rounded-lg text-sm font-semibold transition-colors">
          <ScanSearch size={16} />
          {loading ? "Scanning…" : "Start Scan"}
        </button>
      </form>

      {/* Log output */}
      {(logs.length > 0 || loading) && (
        <div className="bg-surface border border-border rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-border flex items-center justify-between">
            <span className="text-sm font-medium text-slate-300">
              {loading && <span className="inline-block w-2 h-2 rounded-full bg-blue-400 animate-pulse mr-2" />}
              Live Log
            </span>
            {done && scan && (
              <button
                onClick={() => navigate(`/scan/${scan.id}`)}
                className="text-xs bg-indigo-600 hover:bg-indigo-500 px-3 py-1 rounded-md transition-colors"
              >
                View Report →
              </button>
            )}
          </div>
          <div
            ref={logRef}
            className="p-4 font-mono text-xs text-green-400 bg-black/40 h-72 overflow-y-auto space-y-0.5"
          >
            {logs.map((l, i) => (
              <div key={i} className={l.includes("[ERROR]") ? "text-red-400" : ""}>{l}</div>
            ))}
            {loading && <div className="text-slate-500 animate-pulse">▋</div>}
          </div>
        </div>
      )}
    </div>
  );
}
