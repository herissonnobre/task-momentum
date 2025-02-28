from unittest.mock import patch

import pytest
from flask import Flask

from app.controllers.auth_controller import register
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


def test_register_success(testing_app) -> None:
    """
    Test valid user registration.
    """
    with patch('app.controllers.auth_controller.register_user') as mock_register_user:
        mock_register_user.return_value = ({"message": "User registered successfully."}, 201)

        with testing_app.test_request_context("/auth/register", method="POST",
                                              json={'email': 'test@example.com', 'password': 'SecurePassword@123'},
                                              headers={"Content-Type": "application/json"}):
            response, status = register()

        assert status == 201
        assert response.json == {'message': 'User registered successfully.'}


def test_register_missing_request_body(testing_app) -> None:
    with testing_app.test_request_context("/auth/register", method="POST"):
        response, status = register()

    assert status == 400
    assert response.json == {'message': "Request must have a body with 'email' and 'password' fields as raw JSON data."}


def test_register_missing_email_property(testing_app) -> None:
    with testing_app.test_request_context("/auth/register", method="POST", json={'password': ''},
                                          headers={"Content-Type": "application/json"}):
        response, status = register()

    assert status == 400
    assert response.json == {'message': "Request must have a body with 'email' and 'password' fields as raw JSON data."}


def test_register_missing_password_property(testing_app) -> None:
    with testing_app.test_request_context("/auth/register", method="POST", json={'email': ''},
                                          headers={"Content-Type": "application/json"}):
        response, status = register()

    assert status == 400
    assert response.json == {'message': "Request must have a body with 'email' and 'password' fields as raw JSON data."}


def test_register_missing_email_field(testing_app) -> None:
    with patch('app.controllers.auth_controller.register_user') as mock_register_user:
        mock_register_user.return_value = ({"message": "Email is required."}, 400)

        with testing_app.test_request_context("/auth/register", method="POST",
                                              json={'email': '', 'password': 'SecurePassword@123'},
                                              headers={"Content-Type": "application/json"}):
            response, status = register()

        assert status == 400
        assert response.json == {'message': 'Email is required.'}


def test_register_missing_password_field(testing_app) -> None:
    with patch('app.controllers.auth_controller.register_user') as mock_register_user:
        mock_register_user.return_value = ({"message": "Password is required."}, 400)

        with testing_app.test_request_context("/auth/register", method="POST",
                                              json={'email': 'test@example.com', 'password': ''},
                                              headers={"Content-Type": "application/json"}):
            response, status = register()

        assert status == 400
        assert response.json == {'message': 'Password is required.'}


def test_register_missing_fields(testing_app) -> None:
    with patch('app.controllers.auth_controller.register_user') as mock_register_user:
        mock_register_user.return_value = ({"message": "Email and password are required."}, 400)

        with testing_app.test_request_context("/auth/register", method="POST",
                                              json={'email': '', 'password': ''},
                                              headers={"Content-Type": "application/json"}):
            response, status = register()

        assert status == 400
        assert response.json == {'message': 'Email and password are required.'}


def test_register_incorrect_email_format(testing_app) -> None:
    with patch('app.controllers.auth_controller.register_user') as mock_register_user:
        mock_register_user.return_value = ({"message": "Invalid email format."}, 400)

        with testing_app.test_request_context("/auth/register", method="POST",
                                              json={'email': 'test@.com', 'password': 'SecurePassword@123'},
                                              headers={"Content-Type": "application/json"}):
            response, status = register()

        assert status == 400
        assert response.json == {'message': 'Invalid email format.'}


def test_register_already_registered(testing_app) -> None:
    with patch('app.controllers.auth_controller.register_user') as mock_register_user:
        mock_register_user.return_value = ({'message': 'Email already registered.'}, 400)

        with testing_app.test_request_context("/auth/register", method="POST",
                                              json={'email': 'test@example.com', 'password': 'SecurePassword@123'},
                                              headers={"Content-Type": "application/json"}):
            response, status = register()

        assert status == 400
        assert response.json == {'message': 'Email already registered.'}


def test_register_unsecure_password(testing_app) -> None:
    with patch('app.controllers.auth_controller.register_user') as mock_register_user:
        mock_register_user.return_value = ({
                                               'message': 'Password must contain, at least, one uppercase letter, one '
                                                          'lowercase letter, one number and one symbol and must be bigger '
                                                          'than 8 characters'},
                                           400)

        with testing_app.test_request_context("/auth/register", method="POST",
                                              json={'email': 'test@example.com', 'password': 'password'},
                                              headers={"Content-Type": "application/json"}):
            response, status = register()

        assert status == 400
        assert response.json == {'message': 'Password must contain, at least, one uppercase letter, one '
                                            'lowercase letter, one number and one symbol and must be bigger '
                                            'than 8 characters'}
