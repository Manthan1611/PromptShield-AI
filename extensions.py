"""
Shared Flask extension instances.
Kept separate from app.py to avoid circular imports across models/routes.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

db = SQLAlchemy()
migrate = Migrate()
