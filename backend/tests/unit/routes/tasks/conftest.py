import pytest
from flask import Flask

from app.extensions import db
from app.routes import auth_blueprint, tasks_blueprint


@pytest.fixture(scope='package')
def testing_app():
    """
    Set up and tear down the Flask testing application.
    """
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    db.init_app(app)
    app.register_blueprint(auth_blueprint, url_prefix='/auth')
    app.register_blueprint(tasks_blueprint)

    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture(scope='package')
def testing_client(testing_app):
    """
    Create a test client for the Flask app.
    """
    return testing_app.test_client()
