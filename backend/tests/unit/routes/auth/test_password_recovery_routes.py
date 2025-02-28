from unittest.mock import patch

import pytest
from flask import Flask
from flask.testing import FlaskClient

from app.extensions import db
from app.routes import auth_blueprint


@pytest.fixture
def testing_app():
    """
    Set up and tear down the Flask application for testing.
    """
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    db.init_app(app)
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()


@pytest.fixture
def testing_client(testing_app):
    """
    Create a Flask test client.

    :param testing_app:fixture: The Flask testing application.
    :return: FlaskClient: A test client for the Flask testing application.
    """
    return testing_app.test_client()


# Password Recovery Tests

def test_password_recovery_request_success(testing_client: FlaskClient) -> None:
    with patch('app.routes.auth.request_password_reset') as mock_request_password_reset:
        mock_request_password_reset.return_value = ({'message': 'Password reset email sent.'}, 200)
        response = testing_client.post('/auth/password-reset', json={'email': 'test@example.com'})
        assert response.status_code == 200
        assert response.json == {'message': 'Password reset email sent.'}


def test_password_recovery_request_missing_email(testing_client: FlaskClient) -> None:
    with patch('app.routes.auth.request_password_reset') as mock_request_password_reset:
        mock_request_password_reset.return_value = ({'message': 'Email is required.'}, 400)
        response = testing_client.post('/auth/password-reset', json={'email': ''})
        assert response.status_code == 400
        assert response.json == {'message': 'Email is required.'}


def test_password_recovery_request_invalid_email_format(testing_client: FlaskClient) -> None:
    with patch('app.routes.auth.request_password_reset') as mock_request_password_reset:
        mock_request_password_reset.return_value = ({'message': 'Invalid email format.'}, 400)
        response = testing_client.post('/auth/password-reset', json={'email': 'invalid-email'})
        assert response.status_code == 400
        assert response.json == {'message': 'Invalid email format.'}


def test_password_recovery_request_non_existent_user(testing_client: FlaskClient) -> None:
    with patch('app.routes.auth.request_password_reset') as mock_request_password_reset:
        mock_request_password_reset.return_value = ({'message': 'Email not found.'}, 404)
        response = testing_client.post('/auth/password-reset', json={'email': 'nonexistent@example.com'})
        assert response.status_code == 404
        assert response.json == {'message': 'Email not found.'}


def test_password_reset_success(testing_client: FlaskClient) -> None:
    """
    Test resetting the password with a valid token.
    """
    with patch('app.routes.auth.reset_password') as mock_reset_password:
        mock_reset_password.return_value = ({'message': 'Password reset successfully.'}, 200)
        response = testing_client.put('/auth/password-reset', json={'token': 'valid_token',
                                                                    'password': 'NewSecurePass@123'})
        assert response.status_code == 200
        assert response.json == {'message': 'Password reset successfully.'}


def test_password_reset_invalid_token(testing_client: FlaskClient) -> None:
    with patch('app.routes.auth.reset_password') as mock_reset_password:
        mock_reset_password.return_value = ({'message': 'Invalid or expired token.'}, 400)
        response = testing_client.put('/auth/password-reset', json={'token': 'invalid_token',
                                                                    'password': 'NewSecurePass@123'})
        assert response.status_code == 400
        assert response.json == {'message': 'Invalid or expired token.'}


def test_password_reset_weak_password(testing_client: FlaskClient) -> None:
    with patch('app.routes.auth.reset_password') as mock_reset_password:
        mock_reset_password.return_value = ({'message': 'Password does not meet security requirements.'}, 400)
        response = testing_client.put('/auth/password-reset', json={'token': 'valid_token',
                                                                    'password': 'weak'})
        assert response.status_code == 400
        assert response.json == {'message': 'Password does not meet security requirements.'}
