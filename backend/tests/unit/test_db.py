import pytest
from flask import Flask

from app.extensions import db, migrate


@pytest.fixture
def app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_TESTING'] = True

    db.init_app(app)
    migrate.init_app(app, db)

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()
        db.metadata.clear()


def test_db_initialization(app):
    with app.app_context():
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        assert tables == []


def test_model_creation(app):
    from sqlalchemy import Column, String, Integer

    class User(db.Model):
        __tablename__ = 'users'
        id = Column(Integer, primary_key=True)
        name = Column(String)

    with app.app_context():
        db.create_all()
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        assert 'users' in tables


def test_migrate_initialization(app):
    with app.app_context():
        assert migrate.db == db
