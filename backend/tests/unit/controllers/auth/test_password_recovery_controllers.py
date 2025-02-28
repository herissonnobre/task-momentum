"""
Unit tests for authentication routes using pytest.

Fixtures:
    - testing_app: Setup and teardown for Flask application.
    - client: Creates a Flask test client.

Tests:
    - test_register: Valid user registration.
    - test_register_missing_password: Registration with missing password.
    - test_register_missing_email: Registration with missing email.
    - test_register_existing_user: Registration with an existing user.
    - test_login: Valid user login.
    - test_login_invalid_password: Login with invalid password.
    - test_login_invalid_email: Login with an unregistered email.
"""

from unittest.mock import patch

import pytest
from flask import Flask

from app.controllers.auth_controller import login, request_password_reset, reset_password
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


def test_request_password_reset_success(testing_app) -> None:
    with patch('app.controllers.auth_controller.generate_password_reset_token') as mock_generate_password_reset_token:
        mock_generate_password_reset_token.return_value = ({"message": "Password reset email sent."}, 200)

        with testing_app.test_request_context("/auth/password-reset", method="POST",
                                              json={'email': 'test@example.com'},
                                              headers={"Content-Type": "application/json"}):
            response, status = request_password_reset()

        assert status == 200
        assert response.json == {'message': 'Password reset email sent.'}


def test_request_password_reset_missing_email(testing_app) -> None:
    with testing_app.test_request_context("/auth/password-reset", method="POST",
                                          json={}, headers={"Content-Type": "application/json"}):
        response, status = request_password_reset()

    assert status == 400
    assert response.json == {'message': "Email is required."}


def test_request_password_reset_invalid_email_format(testing_app) -> None:
    with patch('app.controllers.auth_controller.generate_password_reset_token') as mock_generate_password_reset_token:
        mock_generate_password_reset_token.return_value = ({"message": "Invalid email format."}, 400)

        with testing_app.test_request_context("/auth/password-reset", method="POST",
                                              json={'email': 'invalid-email'},
                                              headers={"Content-Type": "application/json"}):
            response, status = request_password_reset()

        assert status == 400
        assert response.json == {'message': 'Invalid email format.'}


def test_request_password_reset_non_existent_user(testing_app) -> None:
    with patch('app.controllers.auth_controller.generate_password_reset_token') as mock_generate_password_reset_token:
        mock_generate_password_reset_token.return_value = ({'message': 'Email not found.'}, 404)

        with testing_app.test_request_context("/auth/password-reset", method="POST",
                                              json={'email': 'nonexistent@example.com'},
                                              headers={"Content-Type": "application/json"}):
            response, status = request_password_reset()

        assert status == 404
        assert response.json == {'message': 'Email not found.'}


def test_reset_password_success(testing_app) -> None:
    with patch('app.controllers.auth_controller.reset_user_password') as mock_reset_user_password:
        mock_reset_user_password.return_value = ({"message": "Password reset successfully."}, 200)

        with testing_app.test_request_context("/auth/password-reset", method="PUT",
                                              json={'token': 'valid_token', 'new_password': 'NewSecurePassword@123'},
                                              headers={"Content-Type": "application/json"}):
            response, status = reset_password()

        assert status == 200
        assert response.json == {'message': 'Password reset successfully.'}


def test_reset_password_missing_fields(testing_app) -> None:
    with testing_app.test_request_context("/auth/password-reset", method="PUT",
                                          json={}, headers={"Content-Type": "application/json"}):
        response, status = reset_password()

    assert status == 400
    assert response.json == {
        'message': "Request must have a body with 'token' and 'new_password' fields as raw JSON data."}


def test_reset_password_invalid_token(testing_app) -> None:
    with patch('app.controllers.auth_controller.reset_user_password') as mock_reset_user_password:
        mock_reset_user_password.return_value = ({"message": "Invalid or expired token."}, 400)

        with testing_app.test_request_context("/auth/password-reset", method="PUT",
                                              json={'token': 'invalid_token', 'new_password': 'NewSecurePassword@123'},
                                              headers={"Content-Type": "application/json"}):
            response, status = reset_password()

        assert status == 400
        assert response.json == {'message': 'Invalid or expired token.'}


def test_reset_password_unsecure_password(testing_app) -> None:
    with patch('app.controllers.auth_controller.reset_user_password') as mock_reset_user_password:
        mock_reset_user_password.return_value = ({"message": "Password must meet security requirements."}, 400)

        with testing_app.test_request_context("/auth/password-reset", method="PUT",
                                              json={'token': 'valid_token', 'new_password': '123'},
                                              headers={"Content-Type": "application/json"}):
            response, status = reset_password()

        assert status == 400
        assert response.json == {'message': 'Password must meet security requirements.'}
