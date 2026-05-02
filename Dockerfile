# ── Build stage ──────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.11-slim
WORKDIR /app
COPY --from=builder /install /usr/local
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
    && rm -rf /var/lib/apt/lists/*
COPY . .

# FIX: Do NOT hardcode PORT — Railway injects it at runtime via env var.
# Removing "ENV PORT=5000" ensures $PORT is always Railway's value (8080 in Docker mode).
EXPOSE 8080

# Use shell form so $PORT is expanded at runtime from Railway's injected env
CMD gunicorn app:app \
        --bind 0.0.0.0:${PORT:-8080} \
        --workers ${WEB_CONCURRENCY:-2} \
        --timeout 120 \
        --preload \
        --access-logfile - \
        --error-logfile -
