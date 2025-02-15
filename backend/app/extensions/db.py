"""
Setup for SQLAlchemy and database migrations.

Classes:
    - Base: Base class for declarative models.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """
    Base class for all declarative models.
    """
    pass


db = SQLAlchemy(model_class=Base)

migrate = Migrate()
