import asyncio
import json
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from models import Scan, Project, Connector
from scanner import stream_scan

DATABASE_URL = "sqlite+aiosqlite:///./data/scans.db"
engine = create_async_engine(DATABASE_URL, echo=False)
SessionFactory = async_sessionmaker(engine, expire_on_commit=False)

REPORT_DIR = Path("/app/reports")

# Active WebSocket connections per scan_id
_ws_clients: Dict[int, List[WebSocket]] = defaultdict(list)
# Buffered log lines per scan_id (for late WS connections)
_scan_logs: Dict[int, List[str]] = defaultdict(list)
# Running scan tasks
_scan_tasks: Dict[int, asyncio.Task] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        from sqlmodel import SQLModel
        await conn.run_sync(SQLModel.metadata.create_all)
        # Safe migrations: add missing columns if schema changed
        for col, typedef in [
            ("yara_count", "INTEGER NOT NULL DEFAULT 0"),
            ("dast_count", "INTEGER NOT NULL DEFAULT 0"),
            ("binary_count", "INTEGER NOT NULL DEFAULT 0"),
            ("npm_audit_count", "INTEGER NOT NULL DEFAULT 0"),
        ]:
            try:
                await conn.execute(
                    __import__("sqlalchemy").text(f"ALTER TABLE scan ADD COLUMN {col} {typedef}")
                )
            except Exception:
                pass  # column already exists
        # Add project_id, clamav_count and target_url to scan if missing
        for col, typedef in [
            ("project_id", "INTEGER"),
            ("clamav_count", "INTEGER NOT NULL DEFAULT 0"),
            ("target_url", "TEXT"),
        ]:
            try:
                await conn.execute(
                    __import__("sqlalchemy").text(f"ALTER TABLE scan ADD COLUMN {col} {typedef}")
                )
            except Exception:
                pass
    # Mark stale 'running' scans as failed (left over from previous crash/restart)
    async with AsyncSession(engine) as session:
        import sqlalchemy
        await session.execute(
            sqlalchemy.text(
                "UPDATE scan SET status='failed', finished_at=datetime('now') "
                "WHERE status='running'"
            )
        )
        await session.commit()
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    Path("./data").mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(title="SAST Pipeline API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Models ────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    repo_url: str
    branch: str = "main"
    github_token: str = ""
    target_url: str = ""  # optional DAST target URL


class LocalScanRequest(BaseModel):
    local_path: str
    name: str = ""  # optional display name
    target_url: str = ""  # optional DAST target URL


class ScanSummary(BaseModel):
    id: int
    repo_url: str
    repo_name: str
    branch: str
    target_url: Optional[str]
    status: str
    created_at: str
    finished_at: Optional[str]
    duration_sec: Optional[float]
    bandit_count: int
    semgrep_count: int
    pip_audit_count: int
    npm_audit_count: int
    gitleaks_count: int
    yara_count: int
    dast_count: int
    binary_count: int
    clamav_count: int
    total_count: int
    error: Optional[str]


class ProjectCreate(BaseModel):
    name: str
    description: str = ""
    repo_url: str = ""
    default_branch: str = "main"


class ProjectResponse(BaseModel):
    id: int
    name: str
    description: str
    repo_url: str
    default_branch: str
    created_at: str
    is_active: bool


class ConnectorCreate(BaseModel):
    name: str
    connector_type: str  # gitlab | sonarqube | cuckoo | assemblyline
    base_url: str = ""
    api_token: str = ""
    config: dict = {}


class ConnectorResponse(BaseModel):
    id: int
    name: str
    connector_type: str
    base_url: str
    status: str
    last_sync_at: Optional[str]
    created_at: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def _repo_name(url: str) -> str:
    return url.rstrip("/").split("/")[-1].removesuffix(".git")


async def _broadcast(scan_id: int, msg: str):
    dead = []
    for ws in _ws_clients[scan_id]:
        try:
            await ws.send_text(json.dumps({"type": "log", "message": msg}))
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_clients[scan_id].remove(ws)


async def _run_scan(scan_id: int, repo_url: str, branch: str, token: str, local_path: str = "", target_url: str = ""):
    async with SessionFactory() as session:
        scan = await session.get(Scan, scan_id)
        scan.status = "running"
        session.add(scan)
        await session.commit()

    t0 = datetime.now(timezone.utc)
    logs: List[str] = []

    async def log_cb(msg: str):
        logs.append(msg)
        _scan_logs[scan_id].append(msg)
        await _broadcast(scan_id, msg)

    try:
        results = await stream_scan(scan_id, repo_url, branch, token, log_cb, local_path=local_path, target_url=target_url)
        b = len(results.get("bandit", {}).get("findings", []))
        s = len(results.get("semgrep", {}).get("findings", []))
        p = len(results.get("pip_audit", {}).get("findings", []))
        n = len(results.get("npm_audit", {}).get("findings", []))
        g = len(results.get("gitleaks", {}).get("findings", []))
        y = len(results.get("yara", {}).get("findings", []))
        da = len(results.get("dast", {}).get("findings", []))
        bi = len(results.get("binary", {}).get("findings", []))
        cl = len(results.get("clamav", {}).get("findings", []))

        async with SessionFactory() as session:
            scan = await session.get(Scan, scan_id)
            scan.status = "done"
            scan.finished_at = datetime.now(timezone.utc)
            scan.duration_sec = (scan.finished_at - t0).total_seconds()
            scan.bandit_count = b
            scan.semgrep_count = s
            scan.pip_audit_count = p
            scan.npm_audit_count = n
            scan.gitleaks_count = g
            scan.yara_count = y
            scan.dast_count = da
            scan.binary_count = bi
            scan.clamav_count = cl
            scan.total_count = b + s + p + n + g + y + da + bi + cl
            scan.results_json = json.dumps(results, ensure_ascii=False)
            session.add(scan)
            await session.commit()

        await _broadcast(scan_id, "__DONE__")

    except Exception as exc:
        async with SessionFactory() as session:
            scan = await session.get(Scan, scan_id)
            scan.status = "failed"
            scan.finished_at = datetime.now(timezone.utc)
            scan.duration_sec = (scan.finished_at - t0).total_seconds()
            scan.error = str(exc)
            session.add(scan)
            await session.commit()
        await _broadcast(scan_id, f"[ERROR] {exc}")
        await _broadcast(scan_id, "__FAILED__")

    finally:
        _scan_tasks.pop(scan_id, None)
        async def _clear_logs():
            await asyncio.sleep(300)
            _scan_logs.pop(scan_id, None)
        asyncio.create_task(_clear_logs())


# ── API Routes ────────────────────────────────────────────────────────────────

@app.post("/api/scans", response_model=ScanSummary)
async def create_scan(req: ScanRequest):
    async with SessionFactory() as session:
        scan = Scan(
            repo_url=req.repo_url,
            repo_name=_repo_name(req.repo_url),
            branch=req.branch,
            target_url=req.target_url or None,
            status="pending",
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        sid = scan.id

    task = asyncio.create_task(_run_scan(sid, req.repo_url, req.branch, req.github_token, target_url=req.target_url))
    _scan_tasks[sid] = task

    async with SessionFactory() as session:
        scan = await session.get(Scan, sid)
        return _to_summary(scan)


@app.post("/api/scans/local", response_model=ScanSummary)
async def create_local_scan(req: LocalScanRequest):
    display_name = req.name or Path(req.local_path).name
    async with SessionFactory() as session:
        scan = Scan(
            repo_url=f"local://{req.local_path}",
            repo_name=display_name,
            branch="local",
            target_url=req.target_url or None,
            status="pending",
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        sid = scan.id

    task = asyncio.create_task(_run_scan(sid, f"local://{req.local_path}", "local", "", local_path=req.local_path, target_url=req.target_url))
    _scan_tasks[sid] = task

    async with SessionFactory() as session:
        scan = await session.get(Scan, sid)
        return _to_summary(scan)


@app.get("/api/scans", response_model=List[ScanSummary])
async def list_scans():
    async with SessionFactory() as session:
        result = await session.execute(select(Scan).order_by(Scan.id.desc()))
        scans = result.scalars().all()
    return [_to_summary(s) for s in scans]


@app.get("/api/scans/{scan_id}", response_model=ScanSummary)
async def get_scan(scan_id: int):
    async with SessionFactory() as session:
        scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return _to_summary(scan)


@app.get("/api/scans/{scan_id}/results")
async def get_results(scan_id: int):
    async with SessionFactory() as session:
        scan = await session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if not scan.results_json:
        raise HTTPException(404, "Results not available yet")
    return json.loads(scan.results_json)


@app.delete("/api/scans/{scan_id}")
async def delete_scan(scan_id: int):
    async with SessionFactory() as session:
        scan = await session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(404, "Scan not found")
        await session.delete(scan)
        await session.commit()
    return {"ok": True}


@app.get("/api/stats")
async def get_stats():
    async with SessionFactory() as session:
        result = await session.execute(select(Scan))
        scans = result.scalars().all()
    done = [s for s in scans if s.status == "done"]
    return {
        "total_scans": len(scans),
        "done": len(done),
        "failed": sum(1 for s in scans if s.status == "failed"),
        "running": sum(1 for s in scans if s.status == "running"),
        "total_findings": sum(s.total_count for s in done),
        "bandit_total": sum(s.bandit_count for s in done),
        "semgrep_total": sum(s.semgrep_count for s in done),
        "pip_audit_total": sum(s.pip_audit_count for s in done),
        "npm_audit_total": sum(s.npm_audit_count for s in done),
        "gitleaks_total": sum(s.gitleaks_count for s in done),
        "yara_total": sum(s.yara_count for s in done),
        "dast_total": sum(s.dast_count for s in done),
        "binary_total": sum(s.binary_count for s in done),
        "clamav_total": sum(s.clamav_count for s in done),
        "history": [
            {
                "id": s.id,
                "repo_name": s.repo_name,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "total_count": s.total_count,
                "bandit_count": s.bandit_count,
                "semgrep_count": s.semgrep_count,
                "pip_audit_count": s.pip_audit_count,
                "npm_audit_count": s.npm_audit_count,
                "gitleaks_count": s.gitleaks_count,
                "yara_count": s.yara_count,
                "dast_count": s.dast_count,
            }
            for s in sorted(done, key=lambda x: x.id)[-20:]
        ],
    }


# ── Projects API ──────────────────────────────────────────────────────────────

@app.post("/api/projects", response_model=ProjectResponse)
async def create_project(req: ProjectCreate):
    async with SessionFactory() as session:
        project = Project(
            name=req.name,
            description=req.description,
            repo_url=req.repo_url,
            default_branch=req.default_branch,
        )
        session.add(project)
        await session.commit()
        await session.refresh(project)
        return _to_project_response(project)


@app.get("/api/projects", response_model=List[ProjectResponse])
async def list_projects():
    async with SessionFactory() as session:
        result = await session.execute(select(Project).order_by(Project.id.desc()))
        projects = result.scalars().all()
    return [_to_project_response(p) for p in projects]


@app.get("/api/projects/{project_id}", response_model=ProjectResponse)
async def get_project(project_id: int):
    async with SessionFactory() as session:
        project = await session.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    return _to_project_response(project)


@app.put("/api/projects/{project_id}", response_model=ProjectResponse)
async def update_project(project_id: int, req: ProjectCreate):
    async with SessionFactory() as session:
        project = await session.get(Project, project_id)
        if not project:
            raise HTTPException(404, "Project not found")
        project.name = req.name
        project.description = req.description
        project.repo_url = req.repo_url
        project.default_branch = req.default_branch
        project.updated_at = datetime.now(timezone.utc)
        session.add(project)
        await session.commit()
        await session.refresh(project)
        return _to_project_response(project)


@app.delete("/api/projects/{project_id}")
async def delete_project(project_id: int):
    async with SessionFactory() as session:
        project = await session.get(Project, project_id)
        if not project:
            raise HTTPException(404, "Project not found")
        await session.delete(project)
        await session.commit()
    return {"ok": True}


@app.get("/api/projects/{project_id}/scans", response_model=List[ScanSummary])
async def list_project_scans(project_id: int):
    async with SessionFactory() as session:
        result = await session.execute(
            select(Scan).where(Scan.project_id == project_id).order_by(Scan.id.desc())
        )
        scans = result.scalars().all()
    return [_to_summary(s) for s in scans]


# ── Connectors API ────────────────────────────────────────────────────────────

@app.post("/api/connectors", response_model=ConnectorResponse)
async def create_connector(req: ConnectorCreate):
    async with SessionFactory() as session:
        connector = Connector(
            name=req.name,
            connector_type=req.connector_type,
            base_url=req.base_url,
            api_token=req.api_token or None,
            config_json=json.dumps(req.config) if req.config else None,
            status="inactive",
        )
        session.add(connector)
        await session.commit()
        await session.refresh(connector)
        return _to_connector_response(connector)


@app.get("/api/connectors", response_model=List[ConnectorResponse])
async def list_connectors():
    async with SessionFactory() as session:
        result = await session.execute(select(Connector).order_by(Connector.id.desc()))
        connectors = result.scalars().all()
    return [_to_connector_response(c) for c in connectors]


@app.get("/api/connectors/{connector_id}", response_model=ConnectorResponse)
async def get_connector(connector_id: int):
    async with SessionFactory() as session:
        connector = await session.get(Connector, connector_id)
    if not connector:
        raise HTTPException(404, "Connector not found")
    return _to_connector_response(connector)


@app.post("/api/connectors/{connector_id}/test")
async def test_connector(connector_id: int):
    async with SessionFactory() as session:
        connector = await session.get(Connector, connector_id)
    if not connector:
        raise HTTPException(404, "Connector not found")

    # Test connectivity based on connector type
    from connectors.base import test_connection
    success, message = await test_connection(connector)

    async with SessionFactory() as session:
        conn = await session.get(Connector, connector_id)
        conn.status = "active" if success else "error"
        session.add(conn)
        await session.commit()

    return {"ok": success, "message": message}


@app.delete("/api/connectors/{connector_id}")
async def delete_connector(connector_id: int):
    async with SessionFactory() as session:
        connector = await session.get(Connector, connector_id)
        if not connector:
            raise HTTPException(404, "Connector not found")
        await session.delete(connector)
        await session.commit()
    return {"ok": True}


# ── Webhooks ──────────────────────────────────────────────────────────────────

@app.post("/api/webhooks/gitlab")
async def gitlab_webhook(payload: dict):
    """Handle GitLab webhook events — trigger scans on push."""
    event = payload.get("object_kind", "")
    if event != "push":
        return {"ok": True, "skipped": True, "reason": f"Ignoring event: {event}"}

    repo_url = payload.get("project", {}).get("git_http_url", "")
    branch = payload.get("ref", "refs/heads/main").split("/")[-1]
    repo_name = payload.get("project", {}).get("name", _repo_name(repo_url))

    if not repo_url:
        raise HTTPException(400, "No repo URL in webhook payload")

    # Find matching project or create one
    async with SessionFactory() as session:
        result = await session.execute(select(Project).where(Project.repo_url == repo_url))
        project = result.scalars().first()
        if not project:
            project = Project(name=repo_name, repo_url=repo_url, default_branch=branch)
            session.add(project)
            await session.commit()
            await session.refresh(project)

    # Create scan
    async with SessionFactory() as session:
        scan = Scan(
            project_id=project.id,
            repo_url=repo_url,
            repo_name=repo_name,
            branch=branch,
            status="pending",
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        sid = scan.id

    # Find gitlab connector token
    token = ""
    async with SessionFactory() as session:
        result = await session.execute(
            select(Connector).where(Connector.connector_type == "gitlab")
        )
        gl_connector = result.scalars().first()
        if gl_connector and gl_connector.api_token:
            token = gl_connector.api_token

    task = asyncio.create_task(_run_scan(sid, repo_url, branch, token))
    _scan_tasks[sid] = task

    return {"ok": True, "scan_id": sid}


# ── WebSocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws/scans/{scan_id}/log")
async def scan_log_ws(websocket: WebSocket, scan_id: int):
    await websocket.accept()
    # Replay buffered log lines so late clients catch up
    for past_msg in _scan_logs.get(scan_id, []):
        try:
            await websocket.send_text(json.dumps({"type": "log", "message": past_msg}))
        except Exception:
            return
    _ws_clients[scan_id].append(websocket)
    try:
        async with SessionFactory() as session:
            scan = await session.get(Scan, scan_id)
        if scan and scan.status in ("done", "failed"):
            await websocket.send_text(json.dumps({
                "type": "log",
                "message": f"__{'DONE' if scan.status == 'done' else 'FAILED'}__"
            }))
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in _ws_clients[scan_id]:
            _ws_clients[scan_id].remove(websocket)


# ── Static frontend ───────────────────────────────────────────────────────────

FRONTEND = Path("/app/static")

if FRONTEND.exists() and (FRONTEND / "assets").exists():
    app.mount("/assets", StaticFiles(directory=str(FRONTEND / "assets")), name="assets")


@app.get("/{full_path:path}", include_in_schema=False)
async def spa(full_path: str):
    if full_path.startswith("api/") or full_path.startswith("ws/"):
        raise HTTPException(404)
    index = FRONTEND / "index.html"
    if index.exists():
        return HTMLResponse(index.read_text())
    return HTMLResponse("<h1>Frontend not built</h1><p>Run: docker compose up --build</p>")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _to_summary(scan: Scan) -> ScanSummary:
    return ScanSummary(
        id=scan.id,
        repo_url=scan.repo_url,
        repo_name=scan.repo_name,
        branch=scan.branch,
        target_url=scan.target_url,
        status=scan.status,
        created_at=scan.created_at.isoformat() if scan.created_at else "",
        finished_at=scan.finished_at.isoformat() if scan.finished_at else None,
        duration_sec=scan.duration_sec,
        bandit_count=scan.bandit_count,
        semgrep_count=scan.semgrep_count,
        pip_audit_count=scan.pip_audit_count,
        npm_audit_count=scan.npm_audit_count,
        gitleaks_count=scan.gitleaks_count,
        yara_count=scan.yara_count,
        dast_count=scan.dast_count,
        binary_count=scan.binary_count,
        clamav_count=scan.clamav_count,
        total_count=scan.total_count,
        error=scan.error,
    )


def _to_project_response(project: Project) -> ProjectResponse:
    return ProjectResponse(
        id=project.id,
        name=project.name,
        description=project.description,
        repo_url=project.repo_url,
        default_branch=project.default_branch,
        created_at=project.created_at.isoformat() if project.created_at else "",
        is_active=project.is_active,
    )


def _to_connector_response(connector: Connector) -> ConnectorResponse:
    return ConnectorResponse(
        id=connector.id,
        name=connector.name,
        connector_type=connector.connector_type,
        base_url=connector.base_url,
        status=connector.status,
        last_sync_at=connector.last_sync_at.isoformat() if connector.last_sync_at else None,
        created_at=connector.created_at.isoformat() if connector.created_at else "",
    )
