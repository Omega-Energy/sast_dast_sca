export interface ScanSummary {
  id: number;
  repo_url: string;
  repo_name: string;
  branch: string;
  status: "pending" | "running" | "done" | "failed";
  created_at: string;
  finished_at: string | null;
  duration_sec: number | null;
  bandit_count: number;
  semgrep_count: number;
  pip_audit_count: number;
  gitleaks_count: number;
  yara_count: number;
  dast_count: number;
  binary_count: number;
  clamav_count: number;
  total_count: number;
  error: string | null;
}

export interface ScanResults {
  meta: { repo: string; branch: string; scan_id: number; timestamp: string };
  bandit: { findings: BanditFinding[]; error?: string };
  semgrep: { findings: SemgrepFinding[]; error?: string };
  pip_audit: { findings: PipFinding[]; error?: string };
  gitleaks: { findings: GitleaksFinding[]; error?: string };
  yara: { findings: YaraFinding[]; error?: string };
  dast: { findings: DastFinding[]; skipped?: boolean; reason?: string; target_url?: string };
  binary: { findings: BinaryFinding[] };
  clamav: { findings: ClamavFinding[]; error?: string };
}

export interface BanditFinding {
  file: string; line: number; severity: string; confidence: string;
  title: string; detail: string; cwe: string;
}

export interface SemgrepFinding {
  file: string; line: number; severity: string; title: string; detail: string;
}

export interface PipFinding {
  package: string; version: string; vuln_id: string; detail: string; fix: string;
  url: string; aliases: string[];
}

export interface BinaryFinding {
  file: string; size_kb: number; entropy: number; ext: string; severity: string;
  issues: { type: string; severity: string; detail: string; match: string }[];
}

export interface DastFinding {
  name: string; severity: string; confidence: string;
  description: string; solution: string; reference: string;
  cwe: string; wasc: string; urls: string[]; count: number;
}

export interface YaraFinding {
  file: string; rule: string; severity: string; category: string;
  detail: string; strings: { offset: number; match: string }[];
}

export interface GitleaksFinding {
  file: string; line: number; rule: string; description: string; match: string; commit: string;
}

export interface ClamavFinding {
  file: string; threat: string; severity: string;
}

export interface Stats {
  total_scans: number; done: number; failed: number; running: number;
  total_findings: number; bandit_total: number; semgrep_total: number;
  pip_audit_total: number; gitleaks_total: number; yara_total: number; dast_total: number; binary_total: number; clamav_total: number;
  history: {
    id: number; repo_name: string; created_at: string; total_count: number;
    bandit_count: number; semgrep_count: number; pip_audit_count: number;
    gitleaks_count: number; yara_count: number; dast_count: number;
  }[];
}

const BASE = "";

export const api = {
  async createScan(repo_url: string, branch: string, github_token: string): Promise<ScanSummary> {
    const r = await fetch(`${BASE}/api/scans`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ repo_url, branch, github_token }),
    });
    if (!r.ok) throw new Error(await r.text());
    return r.json();
  },

  async listScans(): Promise<ScanSummary[]> {
    const r = await fetch(`${BASE}/api/scans`);
    return r.json();
  },

  async getScan(id: number): Promise<ScanSummary> {
    const r = await fetch(`${BASE}/api/scans/${id}`);
    return r.json();
  },

  async getResults(id: number): Promise<ScanResults> {
    const r = await fetch(`${BASE}/api/scans/${id}/results`);
    if (!r.ok) throw new Error("Results not ready");
    return r.json();
  },

  async deleteScan(id: number): Promise<void> {
    await fetch(`${BASE}/api/scans/${id}`, { method: "DELETE" });
  },

  async getStats(): Promise<Stats> {
    const r = await fetch(`${BASE}/api/stats`);
    return r.json();
  },

  async createLocalScan(local_path: string, name: string): Promise<ScanSummary> {
    const r = await fetch(`${BASE}/api/scans/local`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ local_path, name }),
    });
    if (!r.ok) throw new Error(await r.text());
    return r.json();
  },

  wsLog(id: number): WebSocket {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    return new WebSocket(`${proto}://${location.host}/ws/scans/${id}/log`);
  },
};
