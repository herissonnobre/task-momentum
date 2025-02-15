"""
User model for the database.

Classes:
    - User: Represents a user.
"""
import uuid
from datetime import datetime

from sqlalchemy import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db


class User(db.Model):
    """
    User model.
    """
    __tablename__ = 'users'
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(unique=True, nullable=False)
    password: Mapped[str] = mapped_column(nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=datetime.now)

    tasks: Mapped[list['Task']] = relationship('Task', back_populates='user')

    def __repr__(self):
        return f'<User: {self.email}>'
