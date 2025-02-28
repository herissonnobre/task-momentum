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


def test_register_success(testing_client: FlaskClient) -> None:
    """
    Test valid user registration.
    """
    with patch('app.routes.auth.register') as mock_register:
        mock_register.return_value = ({'message': 'User registered successfully.'}, 201)
        response = testing_client.post('/auth/register', json={'email': 'test@example.com',
                                                               'password': 'SecurePassword@123'})
        assert response.status_code == 201
        assert response.json == {'message': 'User registered successfully.'}


def test_register_missing_request_body(testing_client: FlaskClient) -> None:
    with patch('app.routes.auth.register') as mock_register:
        mock_register.return_value = (
            {'message': "Request must have a body with 'email' and 'password' fields as raw JSON data."}, 400)
        response = testing_client.post('/auth/register')
        assert response.status_code == 400
        assert response.json == {
            'message': "Request must have a body with 'email' and 'password' fields as raw JSON data."}


def test_register_missing_email_property(testing_client: FlaskClient) -> None:
    with patch('app.routes.auth.register') as mock_register:
        mock_register.return_value = (
            {'message': "Request must have a body with 'email' and 'password' fields as raw JSON data."}, 400)
        response = testing_client.post('/auth/register', json={'password': 'SecurePassword@123'})
        assert response.status_code == 400
        assert response.json == {
            'message': "Request must have a body with 'email' and 'password' fields as raw JSON data."}


def test_register_missing_password_property(testing_client: FlaskClient) -> None:
    with patch('app.routes.auth.register') as mock_register:
        mock_register.return_value = (
            {'message': "Request must have a body with 'email' and 'password' fields as raw JSON data."}, 400)
        response = testing_client.post('/auth/register', json={'email': 'test@example.com'})
        assert response.status_code == 400
        assert response.json == {
            'message': "Request must have a body with 'email' and 'password' fields as raw JSON data."}


def test_register_missing_email_field(testing_client: FlaskClient) -> None:
    with patch('app.routes.auth.register') as mock_register:
        mock_register.return_value = ({'message': 'Email is required.'}, 400)
        response = testing_client.post('/auth/register', json={'email': '', 'password': 'SecurePassword@123'})
        assert response.status_code == 400
        assert response.json == {'message': 'Email is required.'}


def test_register_missing_password_field(testing_client: FlaskClient) -> None:
    with patch('app.routes.auth.register') as mock_register:
        mock_register.return_value = ({'message': 'Password is required.'}, 400)
        response = testing_client.post('/auth/register', json={'email': 'test@example.com', 'password': ''})
        assert response.status_code == 400
        assert response.json == {'message': 'Password is required.'}


def test_register_missing_fields(testing_client: FlaskClient) -> None:
    with patch('app.routes.auth.register') as mock_register:
        mock_register.return_value = ({'message': 'Email and password are required.'}, 400)
        response = testing_client.post('/auth/register', json={'email': '', 'password': ''})
        assert response.status_code == 400
        assert response.json == {'message': 'Email and password are required.'}


def test_register_incorrect_email_format(testing_client: FlaskClient) -> None:
    with patch('app.routes.auth.register') as mock_register:
        mock_register.return_value = ({'message': 'Invalid email format.'}, 400)
        response = testing_client.post('/auth/register', json={'email': 'test@.com',
                                                               'password': 'SecurePassword@123'})
        assert response.status_code == 400
        assert response.json == {'message': 'Invalid email format.'}


def test_register_already_registered(testing_client: FlaskClient) -> None:
    with patch('app.routes.auth.register') as mock_register:
        mock_register.return_value = ({'message': 'Email already registered.'}, 400)
        response = testing_client.post('/auth/register', json={'email': 'test@example.com',
                                                               'password': 'SecurePassword@123'})
        assert response.status_code == 400
        assert response.json == {'message': 'Email already registered.'}


def test_register_unsecure_password(testing_client: FlaskClient) -> None:
    with patch('app.routes.auth.register') as mock_register:
        mock_register.return_value = ({
                                          'message': 'Password must contain, at least, one uppercase letter, one '
                                                     'lowercase letter, one number and one symbol and must be bigger '
                                                     'than 8 characters'},
                                      400)
        response = testing_client.post('/auth/register', json={'email': 'test@example.com',
                                                               'password': 'password'})
        assert response.status_code == 400
        assert response.json == {'message': 'Password must contain, at least, one uppercase letter, one '
                                            'lowercase letter, one number and one symbol and must be bigger '
                                            'than 8 characters'}
