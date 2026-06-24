"""
Celery application configuration for async task processing.
"""
import os

from celery import Celery

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

app = Celery(
    "security_workers",
    broker=REDIS_URL,
    backend=REDIS_URL,
)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max per task
    task_soft_time_limit=3300,  # soft limit at 55 min
    worker_prefetch_multiplier=1,
    worker_concurrency=2,
)

app.autodiscover_tasks(["trust-gateway.workers"])
