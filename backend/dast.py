"""
DAST module: launch target app as subprocess, run lightweight Python HTTP scanner.
No Docker, no ZAP — fast and non-blocking.
"""
import os
import re
import sys
import time
import signal
import socket
import subprocess
from pathlib import Path
from typing import Callable
from urllib.parse import urljoin, urlparse, quote

import requests
from requests.exceptions import RequestException

APP_STARTUP_WAIT = 8     # seconds to wait for app to be ready
APP_PORT_RANGE   = (18000, 18999)  # port range for target apps
SCAN_TIMEOUT     = 5     # per-request timeout seconds
MAX_CRAWL_DEPTH  = 20    # max URLs to test


def _free_port() -> int:
    """Find a free TCP port on the host."""
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def run_dast(repo_dir: Path, log: Callable[[str], None]) -> dict:
    """
    1. Detect project type & entrypoint.
    2. Launch app as subprocess on a free port.
    3. Wait for it to respond.
    4. Run lightweight HTTP security checks.
    5. Kill app, return findings.
    """
    project_type = _detect_project_type(repo_dir)
    if not project_type:
        return {"findings": [], "skipped": True, "reason": "Could not detect project type — DAST skipped"}

    launch_cmd = _build_launch_command(repo_dir, project_type)
    if not launch_cmd:
        return {"findings": [], "skipped": True, "reason": f"No launch command for project type '{project_type}' — DAST skipped"}

    port = _free_port()
    target_url = f"http://127.0.0.1:{port}"
    log(f"DAST: detected {project_type} project, launching on port {port}…")

    # Install Python deps if requirements.txt present and no valid venv
    if project_type == "python":
        req_file = repo_dir / "requirements.txt"
        venv_ok = any([
            (repo_dir / "venv" / "bin" / "python").exists(),
            (repo_dir / ".venv" / "bin" / "python").exists(),
        ])
        if req_file.exists() and not venv_ok:
            log("DAST: installing requirements.txt…")
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", "-q", "-r", str(req_file),
                     "--break-system-packages"],
                    timeout=120, capture_output=True
                )
            except Exception as pip_err:
                log(f"DAST: pip install warning: {pip_err}")

    env = {**os.environ, "PORT": str(port), "HOST": "127.0.0.1", "FLASK_ENV": "production"}
    proc = None

    try:
        proc = subprocess.Popen(
            launch_cmd,
            cwd=str(repo_dir),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

        # Wait for app to respond
        log(f"DAST: waiting up to {APP_STARTUP_WAIT}s for app to start…")
        ready = _wait_for_port(port, timeout=APP_STARTUP_WAIT)
        if not ready:
            return {"findings": [], "skipped": True, "reason": "App did not start in time — DAST skipped"}

        log("DAST: app is up, running HTTP security checks…")
        findings = _run_http_checks(target_url, log)
        log(f"DAST: {len(findings)} findings.")
        return {"findings": findings, "skipped": False, "target_url": target_url}

    except Exception as e:
        return {"findings": [], "skipped": True, "reason": f"DAST error: {e}"}

    finally:
        if proc and proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass


# ── Project detection & launch ────────────────────────────────────────────────

def _detect_project_type(repo_dir: Path) -> str | None:
    checks = [
        ("python", ["requirements.txt", "setup.py", "pyproject.toml", "app.py", "main.py", "manage.py"]),
        ("node",   ["package.json"]),
        ("go",     ["go.mod"]),
        ("ruby",   ["Gemfile", "config.ru"]),
    ]
    for ptype, sigs in checks:
        if any((repo_dir / s).exists() for s in sigs):
            return ptype
    return None


def _detect_python_entrypoint(repo_dir: Path) -> str | None:
    candidates = ["app.py", "main.py", "run.py", "server.py", "wsgi.py", "asgi.py"]
    for c in candidates:
        p = repo_dir / c
        if p.exists():
            try:
                content = p.read_text(errors="replace")
                if any(kw in content for kw in ["Flask(", "FastAPI(", "Starlette(", "app.run", "uvicorn", "django"]):
                    return c
            except Exception:
                pass
    # fallback: any .py with web framework
    for py in repo_dir.glob("*.py"):
        try:
            content = py.read_text(errors="replace")
            if any(kw in content for kw in ["Flask(", "FastAPI(", "Starlette("]):
                return py.name
        except Exception:
            continue
    return None


def _build_launch_command(repo_dir: Path, project_type: str) -> list | None:
    if project_type == "python":
        # Check both Linux and Windows venv layouts (project may come from Windows host)
        venv_candidates = [
            repo_dir / "venv" / "bin" / "python",
            repo_dir / ".venv" / "bin" / "python",
            repo_dir / "venv" / "Scripts" / "python.exe",
            repo_dir / ".venv" / "Scripts" / "python.exe",
        ]
        venv_python = next((p for p in venv_candidates if p.exists()), None)
        python_bin = str(venv_python) if venv_python else sys.executable
        entrypoint = _detect_python_entrypoint(repo_dir)
        if entrypoint:
            return [python_bin, entrypoint]
        # Try uvicorn if FastAPI
        return [python_bin, "-c",
                "import sys; sys.path.insert(0,''); "
                "exec(open(next(f for f in ['app.py','main.py'] if __import__('os').path.exists(f))).read())"]
    if project_type == "node":
        pkg = repo_dir / "package.json"
        try:
            import json
            data = json.loads(pkg.read_text())
            start = data.get("scripts", {}).get("start", "")
            if start:
                return ["sh", "-c", start]
        except Exception:
            pass
        for entry in ["server.js", "app.js", "index.js", "src/index.js"]:
            if (repo_dir / entry).exists():
                return ["node", entry]
    if project_type == "ruby":
        if (repo_dir / "config.ru").exists():
            return ["ruby", "-e", "require 'rack'; Rack::Server.start(config: 'config.ru')"]
    return None


def _wait_for_port(port: int, timeout: int) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


# ── HTTP Security Checks ──────────────────────────────────────────────────────

def _run_http_checks(base_url: str, log: Callable[[str], None]) -> list:
    findings = []
    session = requests.Session()
    session.verify = False
    session.max_redirects = 3

    # 1. Fetch root to get baseline headers & links
    try:
        root_resp = session.get(base_url, timeout=SCAN_TIMEOUT, allow_redirects=True)
    except RequestException as e:
        return [{"name": "App unreachable", "severity": "INFO",
                 "description": str(e), "url": base_url}]

    # ── Security headers check ────────────────────────────────────────────────
    log("DAST: checking security headers…")
    findings += _check_security_headers(root_resp)

    # ── Collect URLs to test ──────────────────────────────────────────────────
    urls = _extract_urls(root_resp, base_url)
    log(f"DAST: found {len(urls)} endpoints to probe…")

    # ── Check each endpoint ───────────────────────────────────────────────────
    tested = set()
    for url in list(urls)[:MAX_CRAWL_DEPTH]:
        if url in tested:
            continue
        tested.add(url)
        try:
            findings += _check_endpoint(session, url, base_url, log)
        except Exception:
            pass

    findings.sort(key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}.get(x.get("severity", "INFO"), 4))
    return findings


def _check_security_headers(resp: requests.Response) -> list:
    findings = []
    headers = {k.lower(): v for k, v in resp.headers.items()}
    url = resp.url

    required = {
        "x-frame-options":           ("MEDIUM", "Missing X-Frame-Options header — clickjacking risk"),
        "x-content-type-options":    ("LOW",    "Missing X-Content-Type-Options header"),
        "strict-transport-security": ("MEDIUM", "Missing HSTS header"),
        "content-security-policy":   ("MEDIUM", "Missing Content-Security-Policy header"),
        "referrer-policy":           ("LOW",    "Missing Referrer-Policy header"),
        "permissions-policy":        ("LOW",    "Missing Permissions-Policy header"),
    }
    for header, (sev, msg) in required.items():
        if header not in headers:
            findings.append({"name": f"Missing {header}", "severity": sev,
                             "description": msg, "url": url})

    # Server header leaks version
    server = headers.get("server", "")
    if re.search(r"[\d.]{3,}", server):
        findings.append({"name": "Server version disclosure", "severity": "LOW",
                         "description": f"Server header exposes version: {server}", "url": url})

    # X-Powered-By leaks tech
    powered = headers.get("x-powered-by", "")
    if powered:
        findings.append({"name": "X-Powered-By disclosure", "severity": "LOW",
                         "description": f"X-Powered-By header reveals tech stack: {powered}", "url": url})

    # Cookies without Secure/HttpOnly
    for cookie in resp.cookies:
        issues = []
        if not cookie.secure:
            issues.append("missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append("missing HttpOnly flag")
        if issues:
            findings.append({"name": "Insecure cookie", "severity": "MEDIUM",
                             "description": f"Cookie '{cookie.name}': {', '.join(issues)}", "url": url})

    return findings


def _extract_urls(resp: requests.Response, base_url: str) -> list:
    urls = [base_url]
    try:
        text = resp.text
        # href links
        for href in re.findall(r'href=["\']([^"\'#?]+)', text):
            full = urljoin(base_url, href)
            if full.startswith(base_url):
                urls.append(full)
        # form actions
        for action in re.findall(r'action=["\']([^"\']+)', text):
            full = urljoin(base_url, action)
            if full.startswith(base_url):
                urls.append(full)
    except Exception:
        pass
    return list(dict.fromkeys(urls))


def _check_endpoint(session: requests.Session, url: str, base_url: str,
                    log: Callable[[str], None]) -> list:
    findings = []

    # ── SQL injection probes ──────────────────────────────────────────────────
    sql_payloads = ["'", "\" OR \"1\"=\"1", "' OR '1'='1", "1; DROP TABLE users--"]
    sql_errors = ["sql syntax", "mysql_fetch", "ORA-", "pg_query", "sqlite3", "syntax error",
                  "unclosed quotation", "unterminated string"]
    for payload in sql_payloads[:2]:
        probe_url = url + ("&" if "?" in url else "?") + f"id={quote(payload)}"
        try:
            r = session.get(probe_url, timeout=SCAN_TIMEOUT)
            body_lower = r.text.lower()
            for err in sql_errors:
                if err in body_lower:
                    findings.append({"name": "Possible SQL Injection", "severity": "HIGH",
                                     "description": f"SQL error pattern '{err}' in response to payload: {payload}",
                                     "url": probe_url})
                    break
        except RequestException:
            pass

    # ── XSS probe ─────────────────────────────────────────────────────────────
    xss_payload = "<script>alert(1)</script>"
    probe_url = url + ("&" if "?" in url else "?") + f"q={quote(xss_payload)}"
    try:
        r = session.get(probe_url, timeout=SCAN_TIMEOUT)
        if xss_payload in r.text:
            findings.append({"name": "Reflected XSS", "severity": "HIGH",
                             "description": "XSS payload reflected unescaped in response",
                             "url": probe_url})
    except RequestException:
        pass

    # ── Open redirect probe ───────────────────────────────────────────────────
    redirect_payload = "https://evil.example.com"
    for param in ["redirect", "next", "url", "return", "goto"]:
        probe_url = url + ("&" if "?" in url else "?") + f"{param}={quote(redirect_payload)}"
        try:
            r = session.get(probe_url, timeout=SCAN_TIMEOUT, allow_redirects=False)
            loc = r.headers.get("location", "")
            if "evil.example.com" in loc:
                findings.append({"name": "Open Redirect", "severity": "MEDIUM",
                                 "description": f"Parameter '{param}' causes redirect to external URL",
                                 "url": probe_url})
        except RequestException:
            pass

    # ── Directory traversal probe ─────────────────────────────────────────────
    traversal = "../../../../etc/passwd"
    probe_url = url + ("&" if "?" in url else "?") + f"file={quote(traversal)}"
    try:
        r = session.get(probe_url, timeout=SCAN_TIMEOUT)
        if "root:x:" in r.text or "root:0:0" in r.text:
            findings.append({"name": "Path Traversal", "severity": "HIGH",
                             "description": "App may be vulnerable to directory traversal (/etc/passwd content detected)",
                             "url": probe_url})
    except RequestException:
        pass

    # ── HTTP methods check ────────────────────────────────────────────────────
    try:
        r = session.options(url, timeout=SCAN_TIMEOUT)
        allow = r.headers.get("allow", r.headers.get("Allow", ""))
        dangerous = [m for m in ["PUT", "DELETE", "TRACE", "CONNECT"] if m in allow]
        if dangerous:
            findings.append({"name": "Dangerous HTTP methods enabled", "severity": "MEDIUM",
                             "description": f"Server allows: {', '.join(dangerous)}",
                             "url": url})
    except RequestException:
        pass

    return findings
