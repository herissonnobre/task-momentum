import os

import pytest
from dotenv import load_dotenv
from flask import Flask

from app.extensions import db, migrate
from app.main import create_app

load_dotenv()


@pytest.fixture
def app():
    """

    :return:
    """
    os.environ['FLASK_ENV'] = 'testing'
    return create_app()


def test_create_app_development():
    os.environ['FLASK_ENV'] = 'development'
    app = create_app()
    assert isinstance(app, Flask)
    assert app.config['DEBUG'] is True
    assert app.config['SQLALCHEMY_DATABASE_URI'] == os.environ.get('DEVELOPMENT_DATABASE_URL')


def test_create_app_testing():
    os.environ['FLASK_ENV'] = 'testing'
    app = create_app()
    assert isinstance(app, Flask)
    assert app.config['DEBUG'] is False
    assert app.config['SQLALCHEMY_DATABASE_URI'] == os.environ.get('TESTING_DATABASE_URL')


def test_create_app_staging():
    os.environ['FLASK_ENV'] = 'staging'
    app = create_app()
    assert isinstance(app, Flask)
    assert app.config['DEBUG'] is False
    assert app.config['SQLALCHEMY_DATABASE_URI'] == os.environ.get('STAGING_DATABASE_URL')


def test_create_app_production():
    os.environ['FLASK_ENV'] = 'production'
    app = create_app()
    assert isinstance(app, Flask)
    assert app.config['DEBUG'] is False
    assert app.config['SQLALCHEMY_DATABASE_URI'] == os.environ.get('PRODUCTION_DATABASE_URL')


def test_db_initialization(app):
    with app.app_context():
        db.create_all()
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        assert 'users' in tables
        assert 'tasks' in tables
        db.session.remove()
        db.drop_all()
        db.metadata.clear()


def test_migrations_initialization(app):
    with app.app_context():
        migrate.init_app(app, db)
        assert migrate.db == db


def test_register_blueprints(app):
    assert 'auth' in app.blueprints
    assert 'tasks' in app.blueprints
