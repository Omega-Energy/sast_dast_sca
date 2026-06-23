"""
DAST module: build target app from repo Dockerfile, run OWASP ZAP active scan.
Requires Docker socket mounted at /var/run/docker.sock.
"""
import time
import uuid
import socket
from pathlib import Path
from typing import Callable

try:
    import docker
    from docker.errors import BuildError, APIError, NotFound
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
ZAP_TIMEOUT = 300        # seconds to wait for ZAP scan
APP_STARTUP_WAIT = 15    # seconds to wait for app to be ready
APP_PORT = 8080          # default port to try


def _free_port() -> int:
    """Find a free TCP port on the host."""
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def run_dast(repo_dir: Path, log: Callable[[str], None]) -> dict:
    """
    1. Look for Dockerfile in repo_dir.
    2. Build the image.
    3. Run container, expose a port.
    4. Pull ZAP image (if not cached) and run baseline + active scan.
    5. Return structured findings list.
    """
    if not DOCKER_AVAILABLE:
        return {"findings": [], "skipped": True, "reason": "docker SDK not available"}

    dockerfile_path = _find_dockerfile(repo_dir)
    _auto_generated = False

    if dockerfile_path is None:
        project_type = _detect_project_type(repo_dir)
        if project_type:
            log(f"DAST: no Dockerfile found, detected project type '{project_type}' — auto-generating Dockerfile…")
            dockerfile_path = _generate_dockerfile(repo_dir, project_type)
            _auto_generated = True
        if dockerfile_path is None:
            return {
                "findings": [],
                "skipped": True,
                "reason": "No Dockerfile found and project type could not be detected — DAST skipped",
            }

    try:
        client = docker.from_env()
    except Exception as e:
        return {"findings": [], "skipped": True, "reason": f"Docker socket error: {e}"}

    run_id = uuid.uuid4().hex[:8]
    app_image_tag = f"sast-dast-target-{run_id}"
    app_container = None
    network = None

    try:
        # ── Build target image ────────────────────────────────────────────────
        log("DAST: building target Docker image…")
        build_context = str(dockerfile_path.parent)
        df_relative = dockerfile_path.relative_to(dockerfile_path.parent)

        try:
            image, build_logs = client.images.build(
                path=build_context,
                dockerfile=str(df_relative),
                tag=app_image_tag,
                rm=True,
                timeout=180,
            )
        except BuildError as e:
            return {"findings": [], "skipped": True, "reason": f"Docker build failed: {e}"}

        log("DAST: target image built.")

        # ── Run target container ──────────────────────────────────────────────
        host_port = _free_port()
        network_name = f"dast-net-{run_id}"
        network = client.networks.create(network_name, driver="bridge")

        app_container = client.containers.run(
            app_image_tag,
            detach=True,
            network=network_name,
            name=f"dast-target-{run_id}",
            environment={"PORT": str(APP_PORT)},
            ports={f"{APP_PORT}/tcp": host_port},
            remove=False,
        )
        log(f"DAST: target container started on host port {host_port}, waiting {APP_STARTUP_WAIT}s…")
        time.sleep(APP_STARTUP_WAIT)

        # Check if container is still running
        app_container.reload()
        if app_container.status != "running":
            logs_out = app_container.logs(tail=20).decode(errors="replace")
            return {
                "findings": [],
                "skipped": True,
                "reason": f"Target container exited early. Logs:\n{logs_out}",
            }

        target_url = f"http://host.docker.internal:{host_port}"
        log(f"DAST: running OWASP ZAP scan against {target_url}…")

        # ── Pull ZAP if needed ────────────────────────────────────────────────
        try:
            client.images.get(ZAP_IMAGE)
        except NotFound:
            log("DAST: pulling ZAP image (first time, may take a minute)…")
            client.images.pull(ZAP_IMAGE)

        # ── Run ZAP baseline + active scan ────────────────────────────────────
        zap_output = client.containers.run(
            ZAP_IMAGE,
            command=[
                "zap-baseline.py",
                "-t", target_url,
                "-J", "/zap/wrk/report.json",
                "-I",   # don't fail on warnings
                "-a",   # include ajax spider
                "-d",   # debug
            ],
            volumes={f"/tmp/zap-{run_id}": {"bind": "/zap/wrk", "mode": "rw"}},
            remove=True,
            extra_hosts={"host.docker.internal": "host-gateway"},
        )

        log("DAST: ZAP scan complete, parsing results…")

        # ── Parse ZAP JSON report ─────────────────────────────────────────────
        report_path = Path(f"/tmp/zap-{run_id}/report.json")
        findings = _parse_zap_report(report_path)
        log(f"DAST: {len(findings)} findings.")

        return {"findings": findings, "skipped": False, "target_url": target_url}

    except Exception as e:
        return {"findings": [], "skipped": True, "reason": str(e)}

    finally:
        # Cleanup
        if app_container:
            try:
                app_container.stop(timeout=5)
                app_container.remove(force=True)
            except Exception:
                pass
        if network:
            try:
                network.remove()
            except Exception:
                pass
        try:
            client.images.remove(app_image_tag, force=True)
        except Exception:
            pass
        import shutil
        shutil.rmtree(f"/tmp/zap-{run_id}", ignore_errors=True)
        if _auto_generated and dockerfile_path and dockerfile_path.exists():
            try:
                dockerfile_path.unlink()
            except Exception:
                pass


def _find_dockerfile(repo_dir: Path) -> Path | None:
    """Search for Dockerfile in root or common subdirectories."""
    candidates = [
        repo_dir / "Dockerfile",
        repo_dir / "docker" / "Dockerfile",
        repo_dir / "app" / "Dockerfile",
    ]
    for c in candidates:
        if c.exists():
            return c
    # Recursive search limited to depth 3
    for p in repo_dir.rglob("Dockerfile"):
        parts = p.relative_to(repo_dir).parts
        if len(parts) <= 3:
            return p
    return None


# ── Project type detection & auto-Dockerfile ──────────────────────────────────

def _detect_project_type(repo_dir: Path) -> str | None:
    """Detect project type from file signatures."""
    checks = [
        ("python",  ["requirements.txt", "setup.py", "pyproject.toml", "app.py", "main.py", "manage.py"]),
        ("node",    ["package.json"]),
        ("java",    ["pom.xml", "build.gradle", "build.gradle.kts"]),
        ("go",      ["go.mod"]),
        ("php",     ["composer.json", "index.php"]),
        ("ruby",    ["Gemfile"]),
    ]
    for project_type, signatures in checks:
        if any((repo_dir / sig).exists() for sig in signatures):
            return project_type
    return None


def _detect_python_entrypoint(repo_dir: Path) -> str:
    """Try to find the main Python web app entrypoint."""
    # Priority order
    candidates = ["app.py", "main.py", "run.py", "server.py", "manage.py", "wsgi.py", "asgi.py"]
    for c in candidates:
        if (repo_dir / c).exists():
            return c
    # Look for any .py with Flask/FastAPI/Django import
    for py in repo_dir.glob("*.py"):
        try:
            content = py.read_text(errors="replace")
            if any(kw in content for kw in ["Flask(", "FastAPI(", "Starlette(", "django"]):
                return py.name
        except Exception:
            continue
    return "app.py"  # fallback


_DOCKERFILE_TEMPLATES = {
    "python": """\
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt 2>/dev/null || true
EXPOSE 8080
ENV PORT=8080 HOST=0.0.0.0
CMD ["python", "{entrypoint}"]
""",
    "node": """\
FROM node:20-slim
WORKDIR /app
COPY . .
RUN npm install --production 2>/dev/null || true
EXPOSE 8080
ENV PORT=8080
CMD ["node", "server.js"]
""",
    "java": """\
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY . .
EXPOSE 8080
CMD ["java", "-jar", "app.jar"]
""",
    "go": """\
FROM golang:1.21-alpine AS build
WORKDIR /app
COPY . .
RUN go build -o app . 2>/dev/null || true
FROM alpine:latest
WORKDIR /app
COPY --from=build /app/app .
EXPOSE 8080
CMD ["./app"]
""",
    "php": """\
FROM php:8.2-apache
COPY . /var/www/html/
RUN sed -i 's/80/8080/g' /etc/apache2/ports.conf /etc/apache2/sites-available/*.conf 2>/dev/null || true
EXPOSE 8080
""",
}


def _generate_dockerfile(repo_dir: Path, project_type: str) -> Path | None:
    """Write a temporary auto-generated Dockerfile into repo_dir."""
    template = _DOCKERFILE_TEMPLATES.get(project_type)
    if not template:
        return None
    if project_type == "python":
        entrypoint = _detect_python_entrypoint(repo_dir)
        template = template.format(entrypoint=entrypoint)
    dockerfile = repo_dir / "_auto_Dockerfile"
    dockerfile.write_text(template)
    return dockerfile


def _parse_zap_report(report_path: Path) -> list:
    """Parse ZAP JSON report into a flat findings list."""
    import json

    if not report_path.exists():
        return []

    try:
        data = json.loads(report_path.read_text())
    except Exception:
        return []

    findings = []
    risk_map = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}

    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            risk = risk_map.get(str(alert.get("riskcode", "1")), "LOW")
            instances = alert.get("instances", [])
            urls = [i.get("uri", "") for i in instances[:5]]
            findings.append({
                "name": alert.get("alert", ""),
                "severity": risk,
                "confidence": alert.get("confidence", ""),
                "description": alert.get("desc", "").replace("<p>", "").replace("</p>", " ").strip(),
                "solution": alert.get("solution", "").replace("<p>", "").replace("</p>", " ").strip(),
                "reference": alert.get("reference", ""),
                "cwe": alert.get("cweid", ""),
                "wasc": alert.get("wascid", ""),
                "urls": urls,
                "count": alert.get("count", len(instances)),
            })

    findings.sort(key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}.get(x["severity"], 4))
    return findings
