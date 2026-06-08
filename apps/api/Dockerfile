# ──────────────────────────────────────────────────────────────
# tg-api — FastAPI control plane for TrustGraph Security
# ──────────────────────────────────────────────────────────────
FROM python:3.13-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential curl libffi-dev libssl-dev tini \
    && rm -rf /var/lib/apt/lists/*

# ---- build wheels in a separate stage to keep the runtime lean ----
FROM base AS build
WORKDIR /build
COPY pyproject.toml ./
COPY trustgraph_security/__init__.py trustgraph_security/__init__.py
RUN pip install --upgrade pip wheel build setuptools && \
    pip wheel --wheel-dir /wheels --no-deps . && \
    pip wheel --wheel-dir /wheels \
      fastapi==0.115.6 'uvicorn[standard]==0.32.1' \
      pydantic==2.10.3 pydantic-settings==2.7.0 \
      httpx==0.28.1 'python-jose[cryptography]==3.3.0' \
      'passlib[bcrypt]==1.7.4' bcrypt==4.0.1 \
      'celery[redis]==5.4.0' redis==5.2.1 \
      rdflib==7.1.1 structlog==24.4.0 prometheus-client==0.21.1 \
      opentelemetry-api==1.29.0 opentelemetry-sdk==1.29.0 \
      opentelemetry-instrumentation-fastapi==0.50b0 \
      boto3==1.35.84 PyGithub==2.5.0 python-multipart==0.0.20

# ---- runtime ----
FROM base AS runtime
WORKDIR /app
COPY --from=build /wheels /wheels
RUN pip install /wheels/*.whl && rm -rf /wheels

COPY trustgraph_security /app/trustgraph_security
COPY pyproject.toml /app/pyproject.toml
RUN useradd -r -u 10001 tgs && chown -R tgs /app
USER tgs

EXPOSE 8000
ENTRYPOINT ["tini", "--"]
CMD ["uvicorn", "trustgraph_security.main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips=*"]

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
  CMD curl -fsS http://localhost:8000/api/v1/healthz || exit 1
