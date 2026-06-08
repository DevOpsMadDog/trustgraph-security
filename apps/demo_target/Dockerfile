# ──────────────────────────────────────────────────────────────
# tg-demo-target — DELIBERATELY VULNERABLE payments-platform mock
# Used inside the hackathon sandbox so the AI pentest agent has a
# real target to exploit. NEVER expose this on a real network.
# ──────────────────────────────────────────────────────────────
FROM python:3.13-slim
ENV PYTHONUNBUFFERED=1
RUN pip install --no-cache-dir \
      fastapi==0.115.6 'uvicorn[standard]==0.32.1' pydantic==2.10.3

WORKDIR /app
COPY demo_target /app/demo_target

EXPOSE 9000
CMD ["uvicorn", "demo_target.main:app", "--host", "0.0.0.0", "--port", "9000"]

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://localhost:9000/').status==200 else 1)"

LABEL trustgraph.security.role="vulnerable-demo-target"
LABEL trustgraph.security.warning="intentionally-vulnerable-do-not-deploy"
