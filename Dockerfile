# ── Build stage ───────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# System deps needed by psycopg2-binary & cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies into a prefix we can copy later
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Runtime stage ──────────────────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Runtime system lib for psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy application source
COPY . .

# Railway injects $PORT at runtime
ENV PORT=5000
EXPOSE 5000

CMD gunicorn app:app \
        --bind 0.0.0.0:$PORT \
        --workers 2 \
        --timeout 120 \
        --access-logfile - \
        --error-logfile -
