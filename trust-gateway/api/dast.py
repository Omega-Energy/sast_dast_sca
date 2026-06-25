"""
Hybrid DAST module.

1. If target_url is provided, the scan is routed through the OWASP ZAP container
   (spider + active scan). This is the proper DAST mode for already-running apps.
2. If target_url is omitted, the module falls back to the legacy behaviour:
   auto-detect project type, launch the app locally, and run lightweight HTTP
   security checks.
"""
import os
import re
import sys
import time
import uuid
import signal
import socket
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable
from urllib.parse import urljoin, quote

import requests
from requests.exceptions import RequestException

try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

APP_STARTUP_WAIT = 8     # seconds to wait for app to be ready
CONTAINER_START_WAIT = 30  # seconds to wait for a containerized app
SCAN_TIMEOUT     = 5     # per-request timeout seconds
MAX_CRAWL_DEPTH  = 20    # max URLs to test

ZAP_URL = os.environ.get("ZAP_API_URL", "http://zap:8090")
ZAP_POLL_INTERVAL = 2    # seconds between ZAP status polls
ZAP_SCAN_TIMEOUT = 600   # max seconds to wait for ZAP active scan


def run_dast(repo_dir: Path, log: Callable[[str], None], target_url: str = "") -> dict:
    """
    Run DAST.

    - If target_url is given, use OWASP ZAP against that URL.
    - Otherwise, try to build/run a temporary container from the repo
      (Dockerfile if present, otherwise generated from project type) and
      scan it with ZAP or the built-in checks.
    - If containerization fails, fall back to the legacy local auto-launch.
    """
    if target_url:
        return _run_zap_dast(target_url, log)

    if DOCKER_AVAILABLE:
        log("DAST: no target_url provided, trying containerized launch…")
        try:
            container_result = _run_containerized_dast(repo_dir, log)
            if not container_result.get("skipped"):
                return container_result
            log(f"DAST: containerized launch skipped — {container_result.get('reason', '')}")
        except Exception as exc:
            log(f"DAST: containerized launch failed ({exc}), falling back to local launch")
    else:
        log("DAST: docker SDK not available, using local auto-launch")

    return _run_local_dast(repo_dir, log)


# ── ZAP-based DAST ───────────────────────────────────────────────────────────


def _run_zap_dast(target_url: str, log: Callable[[str], None]) -> dict:
    """Use OWASP ZAP API to spider and actively scan a running target URL."""
    log(f"DAST: using OWASP ZAP against {target_url}…")
    try:
        from zapv2 import ZAPv2
    except ImportError as exc:
        log(f"DAST: ZAP Python client not installed ({exc}), falling back to built-in scanner")
        return _run_http_checks(target_url, log, via_zap=False)

    try:
        zap = ZAPv2(proxies={"http": ZAP_URL, "https": ZAP_URL})
        # Quick health check
        version = zap.core.version
        log(f"DAST: connected to ZAP {version}")
    except Exception as exc:
        log(f"DAST: cannot reach ZAP at {ZAP_URL} ({exc}), falling back to built-in scanner")
        return _run_http_checks(target_url, log, via_zap=False)

    try:
        # Make sure ZAP sees the target
        zap.urlopen(target_url)
        time.sleep(1)

        # Spider scan
        log("DAST: starting ZAP spider…")
        spider_id = zap.spider.scan(target_url)
        if not spider_id or spider_id == "-1":
            raise RuntimeError("ZAP refused to start spider scan")
        _wait_for_zap(zap.spider.status, spider_id, log, "spider")
        log(f"DAST: ZAP spider finished, found {len(zap.spider.results(spider_id))} URLs")

        # Active scan
        log("DAST: starting ZAP active scan…")
        ascan_id = zap.ascan.scan(target_url)
        if not ascan_id or ascan_id == "-1":
            raise RuntimeError("ZAP refused to start active scan")
        _wait_for_zap(zap.ascan.status, ascan_id, log, "active scan", timeout=ZAP_SCAN_TIMEOUT)
        log("DAST: ZAP active scan finished")

        # Collect alerts
        alerts = zap.core.alerts(baseurl=target_url)
        findings = [_zap_alert_to_finding(a) for a in alerts]
        log(f"DAST: ZAP found {len(findings)} alert(s)")
        return {"findings": findings, "skipped": False, "target_url": target_url, "tool": "zap"}

    except Exception as exc:
        log(f"DAST: ZAP scan failed ({exc}), falling back to built-in scanner")
        return _run_http_checks(target_url, log, via_zap=False)


def _wait_for_zap(status_fn, scan_id: str, log: Callable[[str], None],
                  phase: str, timeout: int = ZAP_SCAN_TIMEOUT) -> None:
    """Poll ZAP until a scan phase reaches 100%."""
    deadline = time.time() + timeout
    last_status = ""
    while time.time() < deadline:
        try:
            status = str(status_fn(scan_id))
        except Exception:
            status = "0"
        if status != last_status:
            log(f"DAST: ZAP {phase} progress {status}%")
            last_status = status
        if status == "100":
            return
        time.sleep(ZAP_POLL_INTERVAL)
    raise TimeoutError(f"ZAP {phase} did not finish within {timeout}s")


def _zap_alert_to_finding(alert: dict) -> dict:
    """Normalize a ZAP alert to the platform finding format."""
    risk = alert.get("risk", "Informational")
    severity = {
        "High": "HIGH",
        "Medium": "MEDIUM",
        "Low": "LOW",
        "Informational": "INFO",
    }.get(risk, "INFO")
    return {
        "name": alert.get("alert", "ZAP alert"),
        "severity": severity,
        "confidence": alert.get("confidence", "Medium"),
        "description": alert.get("description", ""),
        "solution": alert.get("solution", ""),
        "reference": alert.get("reference", ""),
        "cwe": alert.get("cweid", ""),
        "wasc": alert.get("wascid", ""),
        "urls": [alert.get("url", "")],
        "count": 1,
    }


# ── Containerized auto-launch DAST ────────────────────────────────────────────


def _run_containerized_dast(repo_dir: Path, log: Callable[[str], None]) -> dict:
    """Build a temporary image from the repo (Dockerfile or generated) and scan the container."""
    if not DOCKER_AVAILABLE:
        return {"findings": [], "skipped": True, "reason": "docker SDK not available"}

    project_type = _detect_project_type(repo_dir)
    dockerfile_path = repo_dir / "Dockerfile"
    has_dockerfile = dockerfile_path.exists()

    if not has_dockerfile and not project_type:
        return {"findings": [], "skipped": True,
                "reason": "No Dockerfile and unsupported project type for containerized DAST"}

    client = docker.from_env()
    image_tag = f"sast-dast-target-{uuid.uuid4().hex[:8]}"
    container_name = f"sast-dast-target-{uuid.uuid4().hex[:8]}"
    temp_build_dir = None

    try:
        if has_dockerfile:
            log("DAST: found Dockerfile, building temporary image…")
            build_context = str(repo_dir)
            internal_port = _dockerfile_exposed_port(dockerfile_path)
        else:
            log(f"DAST: generating Dockerfile for {project_type} project…")
            generated = _generate_dockerfile(repo_dir, project_type)
            if not generated:
                return {"findings": [], "skipped": True,
                        "reason": f"Could not generate Dockerfile for project type '{project_type}'"}
            temp_build_dir = tempfile.mkdtemp(prefix="sast-dast-")
            build_context = temp_build_dir
            shutil.copytree(repo_dir, Path(temp_build_dir) / "app", dirs_exist_ok=True)
            (Path(temp_build_dir) / "Dockerfile").write_text(generated, encoding="utf-8")
            internal_port = 8080

        for line in client.images.build(path=build_context, tag=image_tag, rm=True, forcerm=True):
            if isinstance(line, dict) and "stream" in line and line["stream"].strip():
                log(f"DAST build: {line['stream'].strip()}")

        network = _guess_worker_network(client)
        target_url = f"http://{container_name}:{internal_port}"
        log(f"DAST: starting container {container_name} on {network} ({target_url})…")

        container = client.containers.run(
            image_tag,
            name=container_name,
            network=network,
            detach=True,
            environment={"PORT": str(internal_port), "HOST": "0.0.0.0"},
            remove=True,
        )

        ready = _wait_for_http(target_url, timeout=CONTAINER_START_WAIT)
        if not ready:
            return {"findings": [], "skipped": True,
                    "reason": "Containerized app did not become ready in time — DAST skipped"}

        log("DAST: containerized app is ready, starting scan…")
        return _run_zap_dast(target_url, log)

    except Exception as exc:
        log(f"DAST: containerized run failed ({exc})")
        return {"findings": [], "skipped": True, "reason": f"Containerized DAST error: {exc}"}

    finally:
        try:
            c = client.containers.get(container_name)
            if c:
                c.stop(timeout=5)
                c.remove(force=True)
        except Exception:
            pass
        try:
            client.images.remove(image_tag, force=True)
        except Exception:
            pass
        if temp_build_dir:
            shutil.rmtree(temp_build_dir, ignore_errors=True)
        client.close()


def _dockerfile_exposed_port(dockerfile_path: Path) -> int:
    """Parse the first EXPOSE instruction in a Dockerfile."""
    try:
        text = dockerfile_path.read_text(encoding="utf-8")
        for line in text.splitlines():
            match = re.match(r"^\s*EXPOSE\s+(\d+)", line, re.IGNORECASE)
            if match:
                return int(match.group(1))
    except Exception:
        pass
    return 8080


def _guess_worker_network(client) -> str:
    """Try to attach the target container to the same network as the current worker."""
    try:
        hostname = os.environ.get("HOSTNAME", "")
        if hostname:
            for container in client.containers.list():
                if container.id.startswith(hostname) or container.short_id == hostname:
                    networks = list(container.attrs.get("NetworkSettings", {}).get("Networks", {}).keys())
                    if networks:
                        return networks[0]
    except Exception:
        pass
    return "bridge"


def _wait_for_http(url: str, timeout: int) -> bool:
    """Poll a URL until it responds or timeout passes."""
    deadline = time.time() + timeout
    session = requests.Session()
    session.verify = False
    while time.time() < deadline:
        try:
            resp = session.get(url, timeout=3, allow_redirects=True)
            if resp.status_code < 500:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


def _generate_dockerfile(repo_dir: Path, project_type: str) -> str | None:
    """Generate a minimal Dockerfile for supported project types."""
    if project_type == "python":
        entrypoint = _detect_python_entrypoint(repo_dir)
        cmd = f'CMD ["python", "{entrypoint}"]' if entrypoint else 'CMD ["python", "app.py"]'
        return f"""FROM python:3.12-slim
WORKDIR /app
COPY app /app
RUN if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt --break-system-packages; fi
EXPOSE 8080
ENV PORT=8080 HOST=0.0.0.0
{cmd}
"""
    if project_type == "node":
        pkg = repo_dir / "package.json"
        try:
            import json
            data = json.loads(pkg.read_text(encoding="utf-8"))
            has_start = "start" in data.get("scripts", {})
        except Exception:
            has_start = False
        if has_start:
            cmd = 'CMD ["npm", "start"]'
        elif (repo_dir / "server.js").exists():
            cmd = 'CMD ["node", "server.js"]'
        elif (repo_dir / "app.js").exists():
            cmd = 'CMD ["node", "app.js"]'
        else:
            cmd = 'CMD ["node", "index.js"]'
        return f"""FROM node:20-slim
WORKDIR /app
COPY app /app
RUN if [ -f package.json ]; then npm install; fi
EXPOSE 8080
ENV PORT=8080 HOST=0.0.0.0
{cmd}
"""
    if project_type == "ruby":
        return """FROM ruby:3-slim
WORKDIR /app
COPY app /app
RUN bundle install || true
EXPOSE 8080
ENV PORT=8080 HOST=0.0.0.0
CMD ["ruby", "-e", "require 'rack'; Rack::Server.start(config: 'config.ru', Port: (ENV['PORT'] || 8080).to_i, Host: '0.0.0.0')"]
"""
    if project_type == "static":
        return """FROM python:3.12-slim
WORKDIR /app
COPY app /app
EXPOSE 8080
ENV PORT=8080 HOST=0.0.0.0
CMD ["python", "-m", "http.server", "8080"]
"""
    return None


# ── Local auto-launch + lightweight scanner ───────────────────────────────────


def _run_local_dast(repo_dir: Path, log: Callable[[str], None]) -> dict:
    """Legacy mode: detect project type, launch locally, run built-in checks."""
    project_type = _detect_project_type(repo_dir)
    if not project_type:
        return {"findings": [], "skipped": True, "reason": "Could not detect project type — DAST skipped"}

    launch_cmd = _build_launch_command(repo_dir, project_type)
    if not launch_cmd:
        return {"findings": [], "skipped": True,
                "reason": f"No launch command for project type '{project_type}' — DAST skipped"}

    port = _free_port()
    target_url = f"http://127.0.0.1:{port}"
    log(f"DAST: detected {project_type} project, launching on port {port}…")

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

        log(f"DAST: waiting up to {APP_STARTUP_WAIT}s for app to start…")
        ready = _wait_for_port(port, timeout=APP_STARTUP_WAIT)
        if not ready:
            return {"findings": [], "skipped": True, "reason": "App did not start in time — DAST skipped"}

        log("DAST: app is up, running built-in HTTP security checks…")
        findings = _run_http_checks(target_url, log)
        log(f"DAST: {len(findings)} findings.")
        return {"findings": findings, "skipped": False, "target_url": target_url, "tool": "builtin"}

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
    if any((repo_dir / s).exists() for s in ["index.html", "public/index.html", "dist/index.html"]):
        return "static"
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


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


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


def _run_http_checks(base_url: str, log: Callable[[str], None], via_zap: bool = False) -> dict:
    """Lightweight built-in HTTP checks. Returns a DAST result dict."""
    findings = []
    session = requests.Session()
    session.verify = False
    session.max_redirects = 3

    try:
        root_resp = session.get(base_url, timeout=SCAN_TIMEOUT, allow_redirects=True)
    except RequestException as e:
        return {
            "findings": [{"name": "App unreachable", "severity": "INFO",
                          "description": str(e), "url": base_url}],
            "skipped": False,
            "target_url": base_url,
            "tool": "zap-fallback" if via_zap else "builtin",
        }

    log("DAST: checking security headers…")
    findings += _check_security_headers(root_resp)

    urls = _extract_urls(root_resp, base_url)
    log(f"DAST: found {len(urls)} endpoints to probe…")

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
    return {
        "findings": findings,
        "skipped": False,
        "target_url": base_url,
        "tool": "zap-fallback" if via_zap else "builtin",
    }


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

    server = headers.get("server", "")
    if re.search(r"[\d.]{3,}", server):
        findings.append({"name": "Server version disclosure", "severity": "LOW",
                         "description": f"Server header exposes version: {server}", "url": url})

    powered = headers.get("x-powered-by", "")
    if powered:
        findings.append({"name": "X-Powered-By disclosure", "severity": "LOW",
                         "description": f"X-Powered-By header reveals tech stack: {powered}", "url": url})

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
        for href in re.findall(r'href=["\']([^"\'#?]+)', text):
            full = urljoin(base_url, href)
            if full.startswith(base_url):
                urls.append(full)
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
