# syntax=docker/dockerfile:1.6

# ---------------------------------------------------------------------------
# Stage 1: builder — install Python deps into an isolated venv
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS builder
WORKDIR /build

COPY requirements.txt .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# ---------------------------------------------------------------------------
# Stage 2: runtime — slim final image, non-root user, healthcheck
# ---------------------------------------------------------------------------
FROM python:3.12-slim
WORKDIR /app

# Create non-root user
RUN groupadd -r shadowscope && \
    useradd -r -g shadowscope -d /app -s /sbin/nologin shadowscope

# Copy venv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application package only (.dockerignore filters out the rest)
COPY ioc_tool ./ioc_tool

# Data volume mount point — SQLite cache + KEV catalog cache live here
RUN mkdir -p /app/ioc_tool/data && chown -R shadowscope:shadowscope /app

USER shadowscope

EXPOSE 8765

# Default env vars (overridable at runtime)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SHADOWSCOPE_CORS_ORIGINS=*

# Healthcheck via the FastAPI /health route — uses stdlib so no extra deps
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8765/health', timeout=3).status == 200 else 1)"

# Default command: REST API server bound to all interfaces
CMD ["python", "-m", "ioc_tool.main", "serve", "--host", "0.0.0.0", "--port", "8765"]
