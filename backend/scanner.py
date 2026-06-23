"""
Core scanning logic — reusable by the API backend.
"""
import asyncio
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from dast import run_dast, DOCKER_AVAILABLE as DAST_AVAILABLE

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

REPO_BASE = Path("/tmp/repos")
REPORT_DIR = Path("/app/reports")
YARA_RULES_DIR = Path("/app/yara_rules")

EXCLUDE_EXTS = {".pyc", ".jpg", ".jpeg", ".png", ".gif", ".ico",
                ".zip", ".gz", ".tar", ".whl", ".egg", ".so", ".dll"}


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)


async def stream_scan(
    scan_id: int,
    repo_url: str,
    branch: str,
    github_token: str,
    log_cb: Callable,
) -> dict:
    """
    Run full scan pipeline, calling log_cb(line) for each log line.
    Returns the results dict.
    """
    repo_dir = REPO_BASE / str(scan_id)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    async def log(msg: str):
        result = log_cb(f"[{_ts()}] {msg}")
        if asyncio.iscoroutine(result):
            await result

    # Clone
    await log(f"Cloning {repo_url} (branch: {branch})…")
    url = repo_url
    if github_token and "github.com" in url:
        url = url.replace("https://", f"https://{github_token}@")
    if repo_dir.exists():
        shutil.rmtree(repo_dir)

    proc = await asyncio.create_subprocess_exec(
        "git", "clone", "--depth=1", "--branch", branch, url, str(repo_dir),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    _, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise RuntimeError(f"git clone failed: {stderr.decode()}")
    await log("Clone complete.")

    results: dict = {
        "meta": {
            "repo": repo_url,
            "branch": branch,
            "scan_id": scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    }

    # Bandit
    await log("Running Bandit (SAST)…")
    r = await asyncio.to_thread(
        _run, ["bandit", "-r", str(repo_dir), "-f", "json", "-ll", "--exit-zero"]
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
                "cwe": item.get("issue_cwe", {}).get("id", ""),
            })
        results["bandit"] = {"findings": findings}
    except Exception as e:
        results["bandit"] = {"findings": [], "error": str(e)}
    await log(f"Bandit: {len(results['bandit']['findings'])} findings.")

    # Semgrep
    await log("Running Semgrep (SAST + secrets patterns)…")
    r = await asyncio.to_thread(
        _run,
        ["semgrep", "--config", "p/python", "--config", "p/secrets",
         "--json", "--no-git-ignore", "--quiet", str(repo_dir)]
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
        results["semgrep"] = {"findings": findings}
    except Exception as e:
        results["semgrep"] = {"findings": [], "error": str(e)}
    await log(f"Semgrep: {len(results['semgrep']['findings'])} findings.")

    # pip-audit
    await log("Running pip-audit (SCA)…")
    req_files = list(repo_dir.rglob("requirements*.txt")) + list(repo_dir.rglob("pyproject.toml"))
    req_args: list[str] = []
    for rf in req_files[:3]:
        req_args += ["-r", str(rf)]
    cmd = ["pip-audit", "--format", "json", "--progress-spinner", "off"] + req_args
    r = await asyncio.to_thread(_run, cmd)
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
        results["pip_audit"] = {"findings": findings}
    except Exception as e:
        results["pip_audit"] = {"findings": [], "error": str(e)}
    await log(f"pip-audit: {len(results['pip_audit']['findings'])} vulnerabilities.")

    # Gitleaks
    await log("Running Gitleaks (secrets in git history)…")
    gl_out = REPORT_DIR / f"gitleaks_{scan_id}.json"
    r = await asyncio.to_thread(
        _run,
        ["gitleaks", "detect", "--source", str(repo_dir),
         "--report-format", "json", "--report-path", str(gl_out),
         "--no-banner", "--exit-code", "0"]
    )
    try:
        raw = json.loads(gl_out.read_text()) if gl_out.exists() else []
        gl_out.unlink(missing_ok=True)
        findings = []
        for item in (raw or []):
            match = item.get("Match", "")
            findings.append({
                "file": item.get("File", ""),
                "line": item.get("StartLine", 0),
                "rule": item.get("RuleID", ""),
                "description": item.get("Description", ""),
                "match": (match[:80] + "…") if len(match) > 80 else match,
                "commit": item.get("Commit", "")[:8],
            })
        results["gitleaks"] = {"findings": findings}
    except Exception as e:
        results["gitleaks"] = {"findings": [], "error": str(e)}
    await log(f"Gitleaks: {len(results['gitleaks']['findings'])} secrets.")

    # YARA
    if YARA_AVAILABLE and YARA_RULES_DIR.exists():
        await log("Running YARA (custom rules)…")
        results["yara"] = await asyncio.to_thread(_run_yara, repo_dir)
        await log(f"YARA: {len(results['yara']['findings'])} matches.")
    else:
        results["yara"] = {"findings": [], "error": "yara-python not available"}

    # DAST
    if DAST_AVAILABLE:
        await log("Running DAST (OWASP ZAP)…")
        dast_log_lines: list[str] = []

        def _log_collect(msg: str):
            dast_log_lines.append(msg)

        results["dast"] = await asyncio.to_thread(run_dast, repo_dir, _log_collect)
        for line in dast_log_lines:
            await log(line)
        skipped = results["dast"].get("skipped", False)
        if skipped:
            await log(f"DAST: skipped — {results['dast'].get('reason', '')}")
        else:
            await log(f"DAST: {len(results['dast'].get('findings', []))} findings.")
    else:
        results["dast"] = {"findings": [], "skipped": True, "reason": "docker SDK not available"}

    # Cleanup
    shutil.rmtree(repo_dir, ignore_errors=True)
    await log("Scan complete.")
    return results


def _run_yara(repo_dir: Path) -> dict:
    """Compile all .yar rules and scan all text files in repo."""
    try:
        rule_files = list(YARA_RULES_DIR.glob("*.yar"))
        if not rule_files:
            return {"findings": [], "error": "No .yar rule files found"}

        rules = yara.compile(filepaths={f.stem: str(f) for f in rule_files})
        findings = []

        for path in repo_dir.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix in EXCLUDE_EXTS:
                continue
            if path.stat().st_size > 500_000:
                continue
            try:
                matches = rules.match(str(path))
                for m in matches:
                    findings.append({
                        "file": str(path.relative_to(repo_dir)),
                        "rule": m.rule,
                        "severity": m.meta.get("severity", "MEDIUM"),
                        "category": m.meta.get("category", ""),
                        "detail": m.meta.get("description", ""),
                        "strings": [
                            {"offset": s.instances[0].offset if s.instances else 0,
                             "match": s.instances[0].matched_data.decode(errors="replace")[:120]
                             if s.instances else ""}
                            for s in m.strings[:3]
                        ],
                    })
            except Exception:
                continue

        return {"findings": findings}
    except Exception as e:
        return {"findings": [], "error": str(e)}
