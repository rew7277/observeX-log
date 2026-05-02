"""ObserveX durable ingestion worker.

Run locally/production when REDIS_URL is configured:
    rq worker observex-ingest

Railway can run this as a second service/process using the same codebase.
"""
import os
import redis
from rq import Worker, Queue
from app import app  # noqa: F401 - loads Flask app and job function import path

listen = [os.environ.get("OBSERVEX_RQ_QUEUE", "observex-ingest")]
redis_url = os.environ.get("REDIS_URL")
if not redis_url:
    raise SystemExit("REDIS_URL is required for worker.py")

conn = redis.from_url(redis_url)

if __name__ == "__main__":
    with conn:
        worker = Worker([Queue(name, connection=conn) for name in listen], connection=conn)
        worker.work()
