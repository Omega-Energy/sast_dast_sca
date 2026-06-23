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

from models import Scan
from scanner import stream_scan

DATABASE_URL = "sqlite+aiosqlite:///./data/scans.db"
engine = create_async_engine(DATABASE_URL, echo=False)
SessionFactory = async_sessionmaker(engine, expire_on_commit=False)

REPORT_DIR = Path("/app/reports")

# Active WebSocket connections per scan_id
_ws_clients: Dict[int, List[WebSocket]] = defaultdict(list)
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
        ]:
            try:
                await conn.execute(
                    __import__("sqlalchemy").text(f"ALTER TABLE scan ADD COLUMN {col} {typedef}")
                )
            except Exception:
                pass  # column already exists
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


class LocalScanRequest(BaseModel):
    local_path: str
    name: str = ""  # optional display name


class ScanSummary(BaseModel):
    id: int
    repo_url: str
    repo_name: str
    branch: str
    status: str
    created_at: str
    finished_at: Optional[str]
    duration_sec: Optional[float]
    bandit_count: int
    semgrep_count: int
    pip_audit_count: int
    gitleaks_count: int
    yara_count: int
    dast_count: int
    binary_count: int
    total_count: int
    error: Optional[str]


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


async def _run_scan(scan_id: int, repo_url: str, branch: str, token: str, local_path: str = ""):
    async with SessionFactory() as session:
        scan = await session.get(Scan, scan_id)
        scan.status = "running"
        session.add(scan)
        await session.commit()

    t0 = datetime.now(timezone.utc)
    logs: List[str] = []

    async def log_cb(msg: str):
        logs.append(msg)
        await _broadcast(scan_id, msg)

    try:
        results = await stream_scan(scan_id, repo_url, branch, token, log_cb, local_path=local_path)
        b = len(results.get("bandit", {}).get("findings", []))
        s = len(results.get("semgrep", {}).get("findings", []))
        p = len(results.get("pip_audit", {}).get("findings", []))
        g = len(results.get("gitleaks", {}).get("findings", []))
        y = len(results.get("yara", {}).get("findings", []))
        da = len(results.get("dast", {}).get("findings", []))
        bi = len(results.get("binary", {}).get("findings", []))

        async with SessionFactory() as session:
            scan = await session.get(Scan, scan_id)
            scan.status = "done"
            scan.finished_at = datetime.now(timezone.utc)
            scan.duration_sec = (scan.finished_at - t0).total_seconds()
            scan.bandit_count = b
            scan.semgrep_count = s
            scan.pip_audit_count = p
            scan.gitleaks_count = g
            scan.yara_count = y
            scan.dast_count = da
            scan.binary_count = bi
            scan.total_count = b + s + p + g + y + da + bi
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


# ── API Routes ────────────────────────────────────────────────────────────────

@app.post("/api/scans", response_model=ScanSummary)
async def create_scan(req: ScanRequest):
    async with SessionFactory() as session:
        scan = Scan(
            repo_url=req.repo_url,
            repo_name=_repo_name(req.repo_url),
            branch=req.branch,
            status="pending",
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        sid = scan.id

    task = asyncio.create_task(_run_scan(sid, req.repo_url, req.branch, req.github_token))
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
            status="pending",
        )
        session.add(scan)
        await session.commit()
        await session.refresh(scan)
        sid = scan.id

    task = asyncio.create_task(_run_scan(sid, f"local://{req.local_path}", "local", "", local_path=req.local_path))
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
        "gitleaks_total": sum(s.gitleaks_count for s in done),
        "yara_total": sum(s.yara_count for s in done),
        "dast_total": sum(s.dast_count for s in done),
        "binary_total": sum(s.binary_count for s in done),
        "history": [
            {
                "id": s.id,
                "repo_name": s.repo_name,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "total_count": s.total_count,
                "bandit_count": s.bandit_count,
                "semgrep_count": s.semgrep_count,
                "pip_audit_count": s.pip_audit_count,
                "gitleaks_count": s.gitleaks_count,
                "yara_count": s.yara_count,
                "dast_count": s.dast_count,
            }
            for s in sorted(done, key=lambda x: x.id)[-20:]
        ],
    }


# ── WebSocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws/scans/{scan_id}/log")
async def scan_log_ws(websocket: WebSocket, scan_id: int):
    await websocket.accept()
    _ws_clients[scan_id].append(websocket)
    try:
        async with SessionFactory() as session:
            scan = await session.get(Scan, scan_id)
        if scan and scan.status in ("done", "failed"):
            await websocket.send_text(json.dumps({
                "type": "log",
                "message": f"Scan already finished with status: {scan.status}"
            }))
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
        status=scan.status,
        created_at=scan.created_at.isoformat() if scan.created_at else "",
        finished_at=scan.finished_at.isoformat() if scan.finished_at else None,
        duration_sec=scan.duration_sec,
        bandit_count=scan.bandit_count,
        semgrep_count=scan.semgrep_count,
        pip_audit_count=scan.pip_audit_count,
        gitleaks_count=scan.gitleaks_count,
        yara_count=scan.yara_count,
        dast_count=scan.dast_count,
        binary_count=scan.binary_count,
        total_count=scan.total_count,
        error=scan.error,
    )
