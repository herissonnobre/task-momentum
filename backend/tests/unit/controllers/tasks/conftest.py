import pytest
from flask import Flask

from app.extensions import db
from app.routes import auth_blueprint, tasks_blueprint


@pytest.fixture(scope='package')
def testing_app():
    """
    Set up and tear down the Flask application for testing.
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


@pytest.fixture(scope='package')
def testing_user_jwt(testing_client):
    """
    Register and log in a user, returning a JWT token.
    """
    testing_client.post('/auth/register', json={'email': 'test@example.com', 'password': 'SecurePassword@123'})
    response = testing_client.post('/auth/login', json={'email': 'test@example.com',
                                                        'password': 'SecurePassword@123'})
    json_data = response.get_json()
    return json_data['token']
