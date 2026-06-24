#!/usr/bin/env python3
"""
Security pipeline: SAST (Bandit + Semgrep) + SCA (pip-audit) + Secrets (Gitleaks)
Usage: set TARGET_REPO env var to a GitHub repo URL, then run via Docker Compose.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

REPORT_DIR = Path("/app/reports")
TEMPLATE_PATH = Path("/app/report_template.html")
REPO_DIR = Path("/tmp/repo")


def log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}] {msg}", flush=True)


def run(cmd: list[str], cwd: Path | None = None, check: bool = False) -> subprocess.CompletedProcess:
    log(f"$ {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, check=check)


def clone_repo(repo_url: str, branch: str, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    token = os.environ.get("GITHUB_TOKEN", "")
    if token and "github.com" in repo_url:
        repo_url = repo_url.replace("https://", f"https://{token}@")
    log(f"Cloning {repo_url} (branch: {branch}) → {dest}")
    run(["git", "clone", "--depth=1", "--branch", branch, repo_url, str(dest)], check=True)


def run_bandit(repo: Path) -> dict:
    log("Running Bandit (SAST)…")
    result = run(
        ["bandit", "-r", str(repo), "-f", "json", "-ll", "--exit-zero"],
        cwd=repo,
    )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": result.stderr or result.stdout, "results": [], "metrics": {}}

    findings = []
    for item in data.get("results", []):
        findings.append({
            "file": item.get("filename", ""),
            "line": item.get("line_number", 0),
            "severity": item.get("issue_severity", "UNKNOWN"),
            "confidence": item.get("issue_confidence", "UNKNOWN"),
            "title": item.get("test_name", ""),
            "detail": item.get("issue_text", ""),
            "cwe": item.get("issue_cwe", {}).get("id", ""),
        })
    return {
        "findings": findings,
        "totals": data.get("metrics", {}).get("_totals", {}),
    }


def run_semgrep(repo: Path) -> dict:
    log("Running Semgrep (SAST)…")
    result = run(
        [
            "semgrep",
            "--config", "p/python",
            "--config", "p/secrets",
            "--json",
            "--no-git-ignore",
            "--quiet",
            str(repo),
        ]
    )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": result.stderr or result.stdout, "findings": []}

    findings = []
    for item in data.get("results", []):
        findings.append({
            "file": item.get("path", ""),
            "line": item.get("start", {}).get("line", 0),
            "severity": item.get("extra", {}).get("severity", "INFO"),
            "title": item.get("check_id", ""),
            "detail": item.get("extra", {}).get("message", ""),
            "cwe": "",
        })
    return {"findings": findings}


def run_pip_audit(repo: Path) -> dict:
    log("Running pip-audit (SCA)…")
    req_files = list(repo.rglob("requirements*.txt")) + list(repo.rglob("pyproject.toml"))
    if not req_files:
        log("  No requirements files found — scanning installed packages.")
        req_args: list[str] = []
    else:
        req_args = []
        for rf in req_files[:3]:
            req_args += ["-r", str(rf)]

    cmd = ["pip-audit", "--format", "json", "--progress-spinner", "off"] + req_args
    result = run(cmd)

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": result.stderr or result.stdout, "findings": []}

    findings = []
    for pkg in data.get("dependencies", []):
        for vuln in pkg.get("vulns", []):
            findings.append({
                "package": pkg.get("name", ""),
                "version": pkg.get("version", ""),
                "vuln_id": vuln.get("id", ""),
                "detail": vuln.get("description", ""),
                "fix": ", ".join(vuln.get("fix_versions", [])) or "No fix available",
            })
    return {"findings": findings}


def run_gitleaks(repo: Path) -> dict:
    log("Running Gitleaks (secrets scanning)…")
    out_file = REPORT_DIR / "gitleaks_raw.json"
    result = run(
        [
            "gitleaks",
            "detect",
            "--source", str(repo),
            "--report-format", "json",
            "--report-path", str(out_file),
            "--no-banner",
            "--exit-code", "0",
        ]
    )
    if out_file.exists():
        try:
            data = json.loads(out_file.read_text())
        except json.JSONDecodeError:
            data = []
        out_file.unlink(missing_ok=True)
    else:
        data = []

    findings = []
    if isinstance(data, list):
        for item in data:
            findings.append({
                "file": item.get("File", ""),
                "line": item.get("StartLine", 0),
                "rule": item.get("RuleID", ""),
                "description": item.get("Description", ""),
                "match": item.get("Match", "")[:80] + "…" if len(item.get("Match", "")) > 80 else item.get("Match", ""),
                "commit": item.get("Commit", "")[:8],
            })
    return {"findings": findings}


def severity_order(s: str) -> int:
    return {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "WARNING": 1, "ERROR": 0, "INFO": 3}.get(s.upper(), 4)


def build_report(repo_url: str, branch: str, results: dict) -> Path:
    log("Generating HTML report…")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    repo_name = repo_url.rstrip("/").split("/")[-1]

    bandit = results.get("bandit", {})
    semgrep = results.get("semgrep", {})
    pip_audit = results.get("pip_audit", {})
    gitleaks = results.get("gitleaks", {})

    bandit_findings = sorted(bandit.get("findings", []), key=lambda x: severity_order(x["severity"]))
    semgrep_findings = sorted(semgrep.get("findings", []), key=lambda x: severity_order(x["severity"]))

    summary = {
        "bandit": len(bandit_findings),
        "semgrep": len(semgrep_findings),
        "pip_audit": len(pip_audit.get("findings", [])),
        "gitleaks": len(gitleaks.get("findings", [])),
    }
    summary["total"] = sum(summary.values())

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_PATH.parent)))
    template = env.get_template(TEMPLATE_PATH.name)

    html = template.render(
        repo_url=repo_url,
        repo_name=repo_name,
        branch=branch,
        generated_at=now,
        summary=summary,
        bandit_findings=bandit_findings,
        bandit_errors=bandit.get("error", ""),
        semgrep_findings=semgrep_findings,
        semgrep_errors=semgrep.get("error", ""),
        pip_findings=pip_audit.get("findings", []),
        pip_errors=pip_audit.get("error", ""),
        gitleaks_findings=gitleaks.get("findings", []),
    )

    out_html = REPORT_DIR / f"report_{repo_name}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.html"
    out_html.write_text(html, encoding="utf-8")

    out_json = REPORT_DIR / f"report_{repo_name}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    out_json.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")

    return out_html


def main() -> None:
    repo_url = os.environ.get("TARGET_REPO", "").strip()
    branch = os.environ.get("BRANCH", "main").strip()

    if not repo_url:
        print("ERROR: TARGET_REPO environment variable is not set.", file=sys.stderr)
        print("Example: TARGET_REPO=https://github.com/owner/repo docker compose up", file=sys.stderr)
        sys.exit(1)

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    clone_repo(repo_url, branch, REPO_DIR)

    results = {
        "meta": {
            "repo": repo_url,
            "branch": branch,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "bandit": run_bandit(REPO_DIR),
        "semgrep": run_semgrep(REPO_DIR),
        "pip_audit": run_pip_audit(REPO_DIR),
        "gitleaks": run_gitleaks(REPO_DIR),
    }

    report_path = build_report(repo_url, branch, results)

    log("=" * 60)
    log("SCAN COMPLETE")
    log(f"  Bandit  : {len(results['bandit'].get('findings', []))} findings")
    log(f"  Semgrep : {len(results['semgrep'].get('findings', []))} findings")
    log(f"  pip-audit: {len(results['pip_audit'].get('findings', []))} vulnerabilities")
    log(f"  Gitleaks: {len(results['gitleaks'].get('findings', []))} secrets")
    log(f"  Report  : /app/reports/{report_path.name}")
    log("=" * 60)


if __name__ == "__main__":
    main()
