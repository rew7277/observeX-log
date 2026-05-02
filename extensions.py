"""
extensions.py — Shared Flask extension instances.
Import from here in both app.py and models.py to avoid circular imports.
"""
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail

db   = SQLAlchemy()
mail = Mail()
