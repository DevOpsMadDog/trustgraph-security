"""Shared Celery instance used by both the API (to enqueue) and workers."""
from celery import Celery
from .settings import get_settings

s = get_settings()
celery_app = Celery(
    "trustgraph_security",
    broker=s.celery_broker_url,
    backend=s.celery_result_backend,
    include=["trustgraph_worker.scanners", "trustgraph_worker.pentest"],
)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_expires=3600,
    task_default_queue="default",
    task_routes={
        "scanners.*": {"queue": "scanners"},
        "pentest.*": {"queue": "pentest"},
    },
)
