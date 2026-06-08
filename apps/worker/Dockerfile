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

ARG TRIVY_VERSION=0.58.1
ARG GITLEAKS_VERSION=8.21.2
ARG NUCLEI_VERSION=3.3.5
ARG TARGETARCH=amd64

# Trivy
RUN curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
      | tar -xz -C /usr/local/bin trivy

# Gitleaks
RUN curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks

# Nuclei
RUN curl -fsSL -o /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip -j /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && rm /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei

# httpx (ProjectDiscovery) + ffuf (recon + fuzzing)
ARG HTTPX_VERSION=1.6.10
ARG FFUF_VERSION=2.1.0
RUN curl -fsSL -o /tmp/httpx.zip \
      "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" \
    && unzip -j /tmp/httpx.zip httpx -d /usr/local/bin/ \
    && rm /tmp/httpx.zip && chmod +x /usr/local/bin/httpx
RUN curl -fsSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_amd64.tar.gz" \
      | tar -xz -C /usr/local/bin ffuf && chmod +x /usr/local/bin/ffuf

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
