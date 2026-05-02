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

# FIX: No hardcoded PORT — Railway injects PORT=8080 at runtime
EXPOSE 8080

# Use gunicorn_config.py for all settings (includes post_fork SSL fix)
CMD ["gunicorn", "app:app", "--config", "gunicorn_config.py"]
