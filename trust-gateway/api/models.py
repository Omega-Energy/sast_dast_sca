from datetime import datetime, timezone
from typing import Optional
from sqlmodel import Field, SQLModel, JSON, Column
import sqlalchemy as sa


class Project(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    description: str = ""
    repo_url: str = ""
    default_branch: str = "main"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_active: bool = True


class Connector(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    connector_type: str  # gitlab | sonarqube | cuckoo | assemblyline
    base_url: str = ""
    api_token: Optional[str] = None
    config_json: Optional[str] = Field(default=None, sa_column=Column(sa.Text))
    status: str = "inactive"  # active | inactive | error
    last_sync_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Scan(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: Optional[int] = Field(default=None, foreign_key="project.id")
    repo_url: str
    repo_name: str
    branch: str
    target_url: Optional[str] = None
    status: str = "pending"  # pending | running | done | failed
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None
    duration_sec: Optional[float] = None
    error: Optional[str] = None

    bandit_count: int = 0
    semgrep_count: int = 0
    pip_audit_count: int = 0
    npm_audit_count: int = 0
    gitleaks_count: int = 0
    yara_count: int = 0
    dast_count: int = 0
    binary_count: int = 0
    clamav_count: int = 0
    total_count: int = 0

    report_html: Optional[str] = None
    report_json: Optional[str] = None

    results_json: Optional[str] = Field(default=None, sa_column=Column(sa.Text))
