"""
Tests user model
"""
import uuid
from datetime import datetime
from sqlalchemy.exc import IntegrityError

import pytest
from flask import Flask

from app.extensions import db
from app.models import User, Task


@pytest.fixture
def app():
    """

    :return:
    """
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


def test_create_user(app):
    with app.app_context():
        user = User(email='test@example.com', password='SecurePassword@123')
        db.session.add(user)
        db.session.commit()

        retrieved_user = User.query.filter_by(email='test@example.com').first()

        assert retrieved_user is not None
        assert retrieved_user.email == 'test@example.com'
        assert retrieved_user.password == 'SecurePassword@123'
        assert isinstance(retrieved_user.id, uuid.UUID)
        assert isinstance(retrieved_user.created_at, datetime)


def test_create_user_duplicate_email(app):
    with app.app_context():
        user = User(email='test@example.com', password='SecurePassword@123')
        db.session.add(user)
        db.session.commit()

        user_duplicated = User(email='test@example.com', password='AnotherPassword@123')
        db.session.add(user_duplicated)

        with pytest.raises(IntegrityError):
            db.session.commit()


def test_user_relationship_with_tasks(app):
    with app.app_context():
        user = User(email='test@example.com', password='SecurePassword@123')
        db.session.add(user)
        db.session.commit()

        task = Task(title='test', description='test', user_id=user.id)
        db.session.add(task)
        db.session.commit()

        retrieved_user = User.query.filter_by(email='test@example.com').first()

        assert retrieved_user is not None
        assert len(retrieved_user.tasks) == 1
        assert retrieved_user.tasks[0].title == 'test'


def test_user_repr_method(app):
    user = User(email='test@example.com', password='SecurePassword@123')
    assert repr(user) == '<User: test@example.com>'
