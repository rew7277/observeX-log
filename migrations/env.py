"""
migrations/env.py — Alembic migration environment (Flask-Migrate style).

Setup:
  1.  pip install flask-migrate alembic
  2.  export FLASK_APP=app.py
  3.  flask db init           # only once — creates this folder
  4.  flask db migrate -m "initial schema"
  5.  flask db upgrade

After this, never use db.create_all() or ALTER TABLE ADD COLUMN IF NOT EXISTS for schema
changes. Always generate a migration with `flask db migrate -m "description"` and apply
it with `flask db upgrade`.

The ensure_runtime_columns() helper in app.py is kept for backward compat on existing
Railway deployments but will be removed once all instances have been migrated.
"""
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# This is the Alembic Config object
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import the Flask app and its metadata so Alembic can detect models
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import app, db
target_metadata = db.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url, target_metadata=target_metadata,
        literal_binds=True, dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    with app.app_context():
        connectable = db.engine
        with connectable.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                compare_type=True,
            )
            with context.begin_transaction():
                context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
