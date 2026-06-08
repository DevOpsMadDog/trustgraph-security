# ──────────────────────────────────────────────────────────────
# tg-worker — Celery worker with real scanners + pentest toolkit
#   Scanners (SAST/SCA/secrets/DAST):
#     • Semgrep   (pip)         • Trivy     (binary)
#     • Gitleaks  (binary)      • Nuclei    (binary)
#   Pentest toolkit (handed to the CAI AI agent at runtime):
#     • httpx     (PD, binary)  • ffuf      (binary)
#     • sqlmap    (pip)         • zap-baseline.py (alpine zap image
#                                  available as side container)
#     • curl, jq, openssl, dig, nmap, git, python (always-on basics)
# ──────────────────────────────────────────────────────────────
FROM python:3.13-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates git wget unzip jq tini libc6 libssl3 \
      openssl dnsutils nmap netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------------
# Pinned versions (all verified against current GitHub releases).
# Each tool uses a different arch naming scheme — we normalize via
# Docker BuildKit's TARGETARCH (amd64 / arm64). Override at build:
#   docker build --build-arg TRIVY_VERSION=0.72.0 ...
# ------------------------------------------------------------------
ARG TARGETARCH=amd64
ARG TRIVY_VERSION=0.71.0
ARG GITLEAKS_VERSION=8.30.1
ARG NUCLEI_VERSION=3.8.0
ARG HTTPX_VERSION=1.9.0
ARG FFUF_VERSION=2.1.0

# Trivy uses Linux-64bit / Linux-ARM64 (capitalized)
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) TRIVY_ARCH="Linux-64bit" ;; \
      arm64) TRIVY_ARCH="Linux-ARM64" ;; \
      *) echo "unsupported arch: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${TRIVY_ARCH}.tar.gz" \
      | tar -xz -C /usr/local/bin trivy

# Gitleaks uses linux_x64 / linux_arm64
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) GL_ARCH="linux_x64" ;; \
      arm64) GL_ARCH="linux_arm64" ;; \
      *) echo "unsupported arch: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${GL_ARCH}.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks

# Nuclei + httpx + ffuf all use linux_amd64 / linux_arm64 (lowercase)
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64|arm64) PD_ARCH="linux_${TARGETARCH}" ;; \
      *) echo "unsupported arch: ${TARGETARCH}"; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_${PD_ARCH}.zip" && \
    unzip -j /tmp/nuclei.zip nuclei -d /usr/local/bin/ && rm /tmp/nuclei.zip && chmod +x /usr/local/bin/nuclei && \
    curl -fsSL -o /tmp/httpx.zip \
      "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_${PD_ARCH}.zip" && \
    unzip -j /tmp/httpx.zip httpx -d /usr/local/bin/ && rm /tmp/httpx.zip && chmod +x /usr/local/bin/httpx && \
    curl -fsSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_${PD_ARCH}.tar.gz" \
      | tar -xz -C /usr/local/bin ffuf && chmod +x /usr/local/bin/ffuf

# Smoke-test that every binary works on this arch (fails the build fast otherwise)
RUN trivy --version && gitleaks version && nuclei -version 2>&1 | head -2 && httpx -version 2>&1 | head -2 && ffuf -V

# Semgrep + sqlmap + CAI framework + helpers (pip)
RUN pip install --no-cache-dir --upgrade pip wheel && \
    pip install --no-cache-dir \
      'semgrep==1.95.0' \
      'sqlmap==1.8.12' \
      'cai-framework' \
      celery[redis]==5.4.0 redis==5.2.1 httpx==0.28.1 \
      pydantic==2.10.3 pydantic-settings==2.7.0 \
      structlog==24.4.0 GitPython==3.1.43

WORKDIR /app
COPY trustgraph_worker /app/trustgraph_worker
COPY pyproject.toml /app/

# Pre-pull nuclei templates (cached on first run otherwise)
RUN nuclei -update-templates -silent || true

RUN useradd -r -u 10002 tgw && chown -R tgw /app
USER tgw

ENTRYPOINT ["tini", "--"]
CMD ["celery", "-A", "trustgraph_worker.celery_app", "worker", \
     "--loglevel=info", "-Q", "scanners,pentest,default", "-c", "4"]
