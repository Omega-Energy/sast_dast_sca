from datetime import datetime, timezone
from typing import Optional
from sqlmodel import Field, SQLModel, JSON, Column
import sqlalchemy as sa


class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    repo_url: str
    repo_name: str
    branch: str
    status: str = "pending"  # pending | running | done | failed
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None
    duration_sec: Optional[float] = None
    error: Optional[str] = None

    bandit_count: int = 0
    semgrep_count: int = 0
    pip_audit_count: int = 0
    gitleaks_count: int = 0
    yara_count: int = 0
    total_count: int = 0

    report_html: Optional[str] = None
    report_json: Optional[str] = None

    results_json: Optional[str] = Field(default=None, sa_column=Column(sa.Text))
