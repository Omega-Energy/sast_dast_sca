"""
Celery tasks for async security scanning and integrations.
"""
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from celery_app import app


REPO_BASE = Path(os.environ.get("REPO_BASE", "/tmp/repos"))
REPORT_DIR = Path(os.environ.get("REPORT_DIR", "/app/reports"))


@app.task(bind=True, name="workers.scan_repo")
def scan_repo(self, scan_id: int, repo_url: str, branch: str, token: str = ""):
    """
    Full scan pipeline task. Clones repo and runs all scanners.
    Updates task state for real-time monitoring.
    """
    self.update_state(state="CLONING", meta={"scan_id": scan_id})

    repo_dir = REPO_BASE / str(scan_id)
    repo_dir.mkdir(parents=True, exist_ok=True)

    # Clone
    url = repo_url
    if token and "github.com" in url:
        url = url.replace("https://", f"https://{token}@")
    elif token and "gitlab" in url:
        url = url.replace("https://", f"https://oauth2:{token}@")

    result = subprocess.run(
        ["git", "clone", "--depth=1", "--branch", branch, url, str(repo_dir)],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return {"status": "failed", "error": f"Clone failed: {result.stderr}"}

    results = {"meta": {"scan_id": scan_id, "repo": repo_url, "branch": branch}}

    # Bandit
    self.update_state(state="SCANNING", meta={"scan_id": scan_id, "tool": "bandit"})
    results["bandit"] = _run_bandit(repo_dir)

    # Semgrep
    self.update_state(state="SCANNING", meta={"scan_id": scan_id, "tool": "semgrep"})
    results["semgrep"] = _run_semgrep(repo_dir)

    # pip-audit
    self.update_state(state="SCANNING", meta={"scan_id": scan_id, "tool": "pip-audit"})
    results["pip_audit"] = _run_pip_audit(repo_dir)

    # Gitleaks
    self.update_state(state="SCANNING", meta={"scan_id": scan_id, "tool": "gitleaks"})
    results["gitleaks"] = _run_gitleaks(repo_dir, scan_id)

    # Cleanup
    shutil.rmtree(repo_dir, ignore_errors=True)

    return {"status": "done", "results": results}


@app.task(name="workers.import_sonarqube")
def import_sonarqube(connector_id: int, project_key: str):
    """Import results from SonarQube for a given project."""
    # This would be called with connector details from the DB
    # Placeholder for the actual implementation
    return {"status": "done", "connector_id": connector_id, "project_key": project_key}


@app.task(name="workers.sync_gitlab_projects")
def sync_gitlab_projects(connector_id: int):
    """Sync project list from GitLab."""
    return {"status": "done", "connector_id": connector_id}


# ── Scanner helpers ──────────────────────────────────────────────────────────

def _run_bandit(repo_dir: Path) -> dict:
    r = subprocess.run(
        ["bandit", "-r", str(repo_dir), "-f", "json", "-ll", "--exit-zero"],
        capture_output=True, text=True
    )
    try:
        data = json.loads(r.stdout)
        findings = []
        for item in data.get("results", []):
            findings.append({
                "file": item.get("filename", ""),
                "line": item.get("line_number", 0),
                "severity": item.get("issue_severity", "UNKNOWN"),
                "confidence": item.get("issue_confidence", "UNKNOWN"),
                "title": item.get("test_name", ""),
                "detail": item.get("issue_text", ""),
            })
        return {"findings": findings}
    except Exception as e:
        return {"findings": [], "error": str(e)}


def _run_semgrep(repo_dir: Path) -> dict:
    r = subprocess.run(
        ["semgrep", "--config", "p/python", "--config", "p/secrets",
         "--json", "--no-git-ignore", "--quiet", str(repo_dir)],
        capture_output=True, text=True
    )
    try:
        data = json.loads(r.stdout)
        findings = []
        for item in data.get("results", []):
            findings.append({
                "file": item.get("path", ""),
                "line": item.get("start", {}).get("line", 0),
                "severity": item.get("extra", {}).get("severity", "INFO"),
                "title": item.get("check_id", ""),
                "detail": item.get("extra", {}).get("message", ""),
            })
        return {"findings": findings}
    except Exception as e:
        return {"findings": [], "error": str(e)}


def _run_pip_audit(repo_dir: Path) -> dict:
    req_files = list(repo_dir.rglob("requirements*.txt"))
    req_args = []
    for rf in req_files[:3]:
        req_args += ["-r", str(rf)]
    cmd = ["pip-audit", "--format", "json", "--progress-spinner", "off"] + req_args
    r = subprocess.run(cmd, capture_output=True, text=True)
    try:
        data = json.loads(r.stdout)
        findings = []
        for pkg in data.get("dependencies", []):
            for vuln in pkg.get("vulns", []):
                findings.append({
                    "package": pkg.get("name", ""),
                    "version": pkg.get("version", ""),
                    "vuln_id": vuln.get("id", ""),
                    "detail": vuln.get("description", ""),
                    "fix": ", ".join(vuln.get("fix_versions", [])) or "No fix",
                })
        return {"findings": findings}
    except Exception as e:
        return {"findings": [], "error": str(e)}


def _run_gitleaks(repo_dir: Path, scan_id: int) -> dict:
    out_file = REPORT_DIR / f"gitleaks_{scan_id}.json"
    subprocess.run(
        ["gitleaks", "detect", "--source", str(repo_dir),
         "--report-format", "json", "--report-path", str(out_file),
         "--no-banner", "--exit-code", "0"],
        capture_output=True, text=True
    )
    try:
        raw = json.loads(out_file.read_text()) if out_file.exists() else []
        out_file.unlink(missing_ok=True)
        findings = []
        for item in (raw or []):
            findings.append({
                "file": item.get("File", ""),
                "line": item.get("StartLine", 0),
                "rule": item.get("RuleID", ""),
                "description": item.get("Description", ""),
            })
        return {"findings": findings}
    except Exception as e:
        return {"findings": [], "error": str(e)}
