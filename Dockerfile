FROM python:3.11-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.11-slim
WORKDIR /app
COPY --from=builder /install /usr/local
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
    && rm -rf /var/lib/apt/lists/*
COPY . .
EXPOSE 8080

# -W suppresses authlib warning at Python interpreter level (applies to all workers)
ENV PYTHONWARNINGS="ignore::DeprecationWarning:authlib"
CMD ["python", "-W", "ignore::DeprecationWarning:authlib", "-m", "gunicorn", "app:app", "--config", "gunicorn_config.py"]
