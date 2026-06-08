import os
from celery import Celery

celery_app = Celery(
    "trustgraph_worker",
    broker=os.environ.get("CELERY_BROKER_URL", "redis://redis:6379/1"),
    backend=os.environ.get("CELERY_RESULT_BACKEND", "redis://redis:6379/2"),
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
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)
