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

from dast import run_dast
DAST_AVAILABLE = True

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
    local_path: str = "",
    target_url: str = "",
) -> dict:
    """
    Run full scan pipeline, calling log_cb(line) for each log line.
    If local_path is set, skip git clone and scan that directory directly.
    If target_url is set, pass it to DAST for ZAP-based scanning.
    Returns the results dict.
    """
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    async def log(msg: str):
        result = log_cb(f"[{_ts()}] {msg}")
        if asyncio.iscoroutine(result):
            await result

    # ── Source: local dir or git clone ───────────────────────────────────────
    if local_path:
        repo_dir = Path(local_path)
        if not repo_dir.exists() or not repo_dir.is_dir():
            raise ValueError(f"Local path does not exist or is not a directory: {local_path}")
        await log(f"Scanning local directory: {repo_dir}")
        _cloned = False
    else:
        repo_dir = REPO_BASE / str(scan_id)
        await log(f"Cloning {repo_url} (branch: {branch})…")
        url = repo_url
        if github_token and "github.com" in url:
            url = url.replace("https://", f"https://{github_token}@")
        if repo_dir.exists():
            shutil.rmtree(repo_dir)
        _cloned = True

    if _cloned:
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
         "--json", "--no-git-ignore", "--quiet",
         "--exclude", "venv", "--exclude", ".venv",
         "--exclude", "node_modules", "--exclude", "*.min.js",
         "--exclude", "dist", "--exclude", "build", "--exclude", ".git",
         "--timeout", "60",
         str(repo_dir)]
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
                desc = vuln.get("description", "")
                # Extract first meaningful sentence as summary (before PoC/code blocks)
                summary = _extract_pip_summary(desc)
                vuln_id = vuln.get("id", "")
                # Build advisory URL
                if vuln_id.startswith("GHSA-"):
                    url = f"https://github.com/advisories/{vuln_id}"
                elif vuln_id.startswith("CVE-"):
                    url = f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
                elif vuln_id.startswith("PYSEC-"):
                    url = f"https://osv.dev/vulnerability/{vuln_id}"
                else:
                    url = ""
                findings.append({
                    "package": pkg.get("name", ""),
                    "version": pkg.get("version", ""),
                    "vuln_id": vuln_id,
                    "detail": summary,
                    "fix": ", ".join(vuln.get("fix_versions", [])) or "No fix",
                    "url": url,
                    "aliases": vuln.get("aliases", []),
                })
        results["pip_audit"] = {"findings": findings}
    except Exception as e:
        results["pip_audit"] = {"findings": [], "error": str(e)}
    await log(f"pip-audit: {len(results['pip_audit']['findings'])} vulnerabilities.")

    # npm audit
    await log("Running npm audit (SCA)…")
    results["npm_audit"] = await asyncio.to_thread(_run_npm_audit, repo_dir)
    await log(f"npm audit: {len(results['npm_audit']['findings'])} vulnerabilities.")

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

    # Binary analysis
    await log("Running binary analysis (strings + entropy)…")
    results["binary"] = await asyncio.to_thread(_run_binary_analysis, repo_dir)
    await log(f"Binary: {len(results['binary']['findings'])} suspicious binaries.")

    # ClamAV
    await log("Running ClamAV (antivirus)…")
    results["clamav"] = await asyncio.to_thread(_run_clamav, repo_dir)
    clamav_count = len(results["clamav"].get("findings", []))
    if results["clamav"].get("error"):
        await log(f"ClamAV: skipped — {results['clamav']['error']}")
    else:
        await log(f"ClamAV: {clamav_count} threat(s) detected.")

    # DAST
    if DAST_AVAILABLE:
        await log("Running DAST (OWASP ZAP)…")
        dast_log_lines: list[str] = []

        def _log_collect(msg: str):
            dast_log_lines.append(msg)

        results["dast"] = await asyncio.to_thread(run_dast, repo_dir, _log_collect, target_url)
        for line in dast_log_lines:
            await log(line)
        skipped = results["dast"].get("skipped", False)
        if skipped:
            await log(f"DAST: skipped — {results['dast'].get('reason', '')}")
        else:
            await log(f"DAST: {len(results['dast'].get('findings', []))} findings.")
    else:
        results["dast"] = {"findings": [], "skipped": True, "reason": "docker SDK not available"}

    # Cleanup: only remove cloned repos, never touch local paths
    if _cloned:
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


# ── Binary file analysis ───────────────────────────────────────────────────────

BINARY_EXTS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".dat", ".pyd",
    ".pyc", ".pyo", ".class", ".jar", ".war", ".ear",
    ".o", ".obj", ".lib", ".a",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
}

SUSPICIOUS_STRINGS_RE = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key", "HIGH"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "Private Key", "HIGH"),
    (r"(?:password|passwd|secret)\s*[=:]\s*\S{6,}", "Hardcoded credential", "MEDIUM"),
    (r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "Hardcoded IP URL", "MEDIUM"),
    (r"(?:/bin/sh|/bin/bash|cmd\.exe)", "Shell reference", "MEDIUM"),
    (r"(?:CreateRemoteThread|VirtualAlloc|WriteProcessMemory)", "Win32 injection API", "HIGH"),
    (r"(?:socket\.connect|recv\(|send\()", "Network socket", "LOW"),
]


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (0.0 - 8.0). >7.0 = likely packed/encrypted."""
    import math
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    length = len(data)
    for f in freq:
        if f:
            p = f / length
            entropy -= p * math.log2(p)
    return round(entropy, 2)


def _extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    """Extract printable ASCII strings from binary data."""
    import re
    return re.findall(rb"[ -~]{%d,}" % min_len, data)


def _run_binary_analysis(repo_dir: Path) -> dict:
    """Scan binary files for suspicious strings, entropy, and known patterns."""
    import re
    findings = []
    compiled = [(re.compile(pat, re.IGNORECASE), desc, sev) for pat, desc, sev in SUSPICIOUS_STRINGS_RE]

    for path in repo_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in BINARY_EXTS:
            continue
        if path.stat().st_size > 10_000_000:  # skip >10MB
            continue

        try:
            data = path.read_bytes()
        except Exception:
            continue

        rel = str(path.relative_to(repo_dir))
        entropy = _shannon_entropy(data)
        strings = _extract_strings(data)
        strings_text = b"\n".join(strings).decode(errors="replace")

        file_findings = []

        # Entropy check — packed/encrypted binary
        if entropy > 7.2:
            file_findings.append({
                "type": "high_entropy",
                "severity": "MEDIUM",
                "detail": f"Shannon entropy {entropy}/8.0 — possibly packed, encrypted or obfuscated",
                "match": "",
            })

        # Suspicious string patterns
        for pattern, desc, sev in compiled:
            m = pattern.search(strings_text)
            if m:
                file_findings.append({
                    "type": "suspicious_string",
                    "severity": sev,
                    "detail": desc,
                    "match": m.group(0)[:120],
                })

        if file_findings:
            findings.append({
                "file": rel,
                "size_kb": round(path.stat().st_size / 1024, 1),
                "entropy": entropy,
                "ext": path.suffix.lower(),
                "issues": file_findings,
                "severity": max(
                    (f["severity"] for f in file_findings),
                    key=lambda s: {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(s, 0),
                ),
            })

    findings.sort(key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(x["severity"], 3))
    return {"findings": findings}


# ── ClamAV antivirus scan ─────────────────────────────────────────────────────

def _run_clamav(repo_dir: Path) -> dict:
    """Run ClamAV clamscan on repository files."""
    try:
        r = subprocess.run(
            ["clamscan", "--recursive", "--infected", "--no-summary",
             "--max-filesize=50M", "--max-scansize=100M",
             "--stdout", str(repo_dir)],
            capture_output=True, text=True, timeout=300
        )
    except FileNotFoundError:
        return {"findings": [], "error": "clamscan not installed"}
    except subprocess.TimeoutExpired:
        return {"findings": [], "error": "ClamAV scan timed out (5 min)"}

    findings = []
    for line in r.stdout.strip().split("\n"):
        if not line or "OK" in line or "Empty file" in line:
            continue
        if "FOUND" in line:
            parts = line.rsplit(":", 1)
            if len(parts) == 2:
                file_path = parts[0].strip()
                threat = parts[1].replace("FOUND", "").strip()
                # Make path relative to repo_dir
                try:
                    rel_path = str(Path(file_path).relative_to(repo_dir))
                except ValueError:
                    rel_path = file_path
                findings.append({
                    "file": rel_path,
                    "threat": threat,
                    "severity": _classify_clamav_severity(threat),
                })

    return {"findings": findings}


def _classify_clamav_severity(threat_name: str) -> str:
    """Classify ClamAV threat severity."""
    t = threat_name.lower()
    if any(k in t for k in ("trojan", "backdoor", "rootkit", "ransomware", "exploit")):
        return "CRITICAL"
    if any(k in t for k in ("virus", "worm", "miner", "keylogger", "stealer")):
        return "HIGH"
    if any(k in t for k in ("adware", "pup", "potentially", "heuristic", "suspicious")):
        return "MEDIUM"
    return "HIGH"


def _extract_pip_summary(description: str, max_len: int = 300) -> str:
    """Extract a concise summary from pip-audit advisory description.

    Strips markdown code blocks, PoC sections, and returns the first
    meaningful paragraph up to max_len characters.
    """
    import re
    if not description:
        return ""
    # Remove code blocks
    text = re.sub(r"```[\s\S]*?```", "", description)
    # Remove inline code
    text = re.sub(r"`[^`]+`", "", text)
    # Remove markdown headers
    text = re.sub(r"#{1,6}\s+", "", text)
    # Remove markdown links, keep text
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    # Remove bold/italic markers
    text = re.sub(r"\*{1,2}([^*]+)\*{1,2}", r"\1", text)
    # Collapse whitespace
    text = re.sub(r"\s+", " ", text).strip()
    # Take text up to PoC/Impact/Details sections if present
    for marker in ["PoC", "Proof of", "Exploitation", "Impact", "Details"]:
        idx = text.find(marker)
        if idx > 30:
            text = text[:idx].strip()
            break
    # Truncate
    if len(text) > max_len:
        text = text[:max_len].rsplit(" ", 1)[0] + "…"
    return text


# ── npm audit (Node.js SCA) ───────────────────────────────────────────────────


def _run_npm_audit(repo_dir: Path) -> dict:
    """Run npm audit for Node.js projects and parse findings."""
    pkg_files = list(repo_dir.rglob("package.json"))
    if not pkg_files:
        return {"findings": [], "error": "No package.json found"}

    findings = []
    errors: list[str] = []

    for pkg_file in pkg_files[:3]:
        cwd = pkg_file.parent
        r = _run(["npm", "audit", "--json"], cwd=cwd)
        if not r.stdout.strip():
            if r.stderr.strip():
                errors.append(f"{cwd}: {r.stderr.strip()[:200]}")
            continue
        try:
            data = json.loads(r.stdout)
        except Exception as e:
            errors.append(f"{cwd}: JSON parse error: {e}")
            continue

        # npm v7+ format
        for pkg_name, info in data.get("vulnerabilities", {}).items():
            severity = info.get("severity", "UNKNOWN")
            via_list = info.get("via", [])
            range_ = info.get("range", "")
            fix = info.get("fixAvailable", {})
            fix_version = fix.get("version", "") if isinstance(fix, dict) else ("" if not fix else "available")
            for v in via_list:
                if isinstance(v, dict):
                    findings.append({
                        "package": pkg_name,
                        "version": "",
                        "vuln_id": str(v.get("source", "")),
                        "severity": v.get("severity", severity),
                        "title": v.get("title", ""),
                        "detail": v.get("title", ""),
                        "range": v.get("range", range_),
                        "fix": fix_version,
                        "url": v.get("url", ""),
                        "aliases": [],
                    })
                elif isinstance(v, str):
                    findings.append({
                        "package": pkg_name,
                        "version": "",
                        "vuln_id": "",
                        "severity": severity,
                        "title": v,
                        "detail": v,
                        "range": range_,
                        "fix": fix_version,
                        "url": "",
                        "aliases": [],
                    })

        # npm v6 format
        for adv_id, adv in data.get("advisories", {}).items():
            findings.append({
                "package": adv.get("module_name", ""),
                "version": "",
                "vuln_id": str(adv_id),
                "severity": adv.get("severity", "UNKNOWN"),
                "title": adv.get("title", ""),
                "detail": adv.get("overview", ""),
                "range": adv.get("vulnerable_versions", ""),
                "fix": adv.get("patched_versions", ""),
                "url": adv.get("url", ""),
                "aliases": [],
            })

    return {"findings": findings, "error": "; ".join(errors) if errors else None}
