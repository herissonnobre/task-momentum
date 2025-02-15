"""
Integration tests for app entry point, including Flask instance creation and blueprints registration
"""
import pytest

from app.extensions import db
from app.main import create_app


@pytest.fixture
def app():
    """
    Fixture to create an app instance
    """
    app = create_app()
    app.config['TESTING'] = True
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture
def client(app):
    """
    Fixture to create a test client

    :param app: Flask app instance
    :return: Flask test client
    """
    return app.test_client()


def test_app_creation(client):
    response = client.get('/')
    assert response.status_code in [200, 404]


def test_register_blueprints(client):
    response = client.get('/auth/register', json={'email': 'test@example.com', 'password': 'password'})
    assert response.status_code != 404
