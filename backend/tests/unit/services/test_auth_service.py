"""
Unit tests for authentication routes using pytest.
"""
import uuid
from unittest.mock import patch, MagicMock

from app.models import User
from app.services.auth_service import authenticate_user, register_user


def test_register_success() -> None:
    data = {'email': 'test@example.com', 'password': 'SecurePassword@123'}

    with patch('app.services.auth_service.generate_password_hash') as mock_generate_password_hash:
        mock_generate_password_hash.return_value = "hashed_password"

        with patch('app.services.auth_service.db.session') as mock_session:
            mock_query = MagicMock()
            mock_filter = MagicMock()
            mock_query.filter_by.return_value = mock_filter
            mock_filter.first.return_value = None
            mock_session.query.return_value = mock_query

            mock_session.add = MagicMock()
            mock_session.commit = MagicMock()

            response, status = register_user(data['email'], data['password'])

            mock_generate_password_hash.assert_called_once_with(data['password'])
            mock_session.query.assert_called_once_with(User)
            mock_filter.first.assert_called_once()
            mock_session.add.assert_called_once()
            mock_session.commit.assert_called_once()
            assert status == 201
            assert response == {"message": "User registered successfully."}


def test_register_missing_email_field() -> None:
    data = {'email': '', 'password': 'SecurePassword@123'}

    response, status = register_user(data['email'], data['password'])

    assert status == 400
    assert response == {"message": "Email is required."}


def test_register_missing_password_field() -> None:
    data = {'email': 'test@example.com', 'password': ''}

    response, status = register_user(data['email'], data['password'])

    assert status == 400
    assert response == {"message": "Password is required."}


def test_register_missing_fields() -> None:
    data = {'email': '', 'password': ''}

    response, status = register_user(data['email'], data['password'])

    assert status == 400
    assert response == {"message": "Email and password are required."}


def test_register_incorrect_email_format() -> None:
    data = {'email': 'test@.com', 'password': 'SecurePassword@123'}

    response, status = register_user(data['email'], data['password'])

    assert status == 400
    assert response == {"message": "Invalid email format."}


def test_register_already_registered() -> None:
    data = {'email': 'test@example.com', 'password': 'SecurePassword@123'}

    with patch('app.services.auth_service.db.session') as mock_session:
        mock_query = MagicMock()
        mock_filter = MagicMock()
        mock_query.filter_by.return_value = mock_filter
        mock_filter.first.return_value = User(email='test@example.com')
        mock_session.query.return_value = mock_query

        response, status = register_user(data['email'], data['password'])

        mock_session.query.assert_called_once_with(User)
        mock_filter.first.assert_called_once()

        assert status == 400
        assert response == {"message": "Email already registered."}


def test_register_unsecure_password() -> None:
    data = {'email': 'test@example.com', 'password': 'password'}

    response, status = register_user(data['email'], data['password'])

    assert status == 400
    assert response == {"message": 'Password must contain, at least, one uppercase letter, one '
                                   'lowercase letter, one number and one symbol and must be bigger '
                                   'than 8 characters.'}


def test_login_success() -> None:
    """
    Test valid user login.
    """
    data = {'email': 'test@example.com', 'password': 'SecurePassword@123'}

    mock_user = MagicMock(spec=User)
    mock_user.id = uuid.uuid4()
    mock_user.password = 'hashed_password'

    with patch('app.services.auth_service.check_password_hash') as mock_check_password_hash:
        mock_check_password_hash.return_value = True

        with patch('app.services.auth_service.db.session') as mock_session:
            mock_query = mock_session.query.return_value
            mock_filter = mock_query.filter_by.return_value
            mock_filter.first.return_value = mock_user

            with patch('app.services.auth_service.generate_token') as mock_generate_token:
                mock_generate_token.return_value = 'test_token'

                response, status = authenticate_user(data['email'], data['password'])

                mock_session.query.assert_called_once_with(User)
                mock_query.filter_by.assert_called_once_with(email=data['email'])
                mock_filter.first.assert_called_once()
                mock_check_password_hash.assert_called_once_with('hashed_password', data['password'])
                mock_generate_token.assert_called_once_with(str(mock_user.id))

                assert status == 200
                assert response == {"token": "test_token"}


def test_login_missing_email_field() -> None:
    data = {'email': '', 'password': 'SecurePassword@123'}

    response, status = authenticate_user(data['email'], data['password'])

    assert status == 400
    assert response == {"message": "Email is required."}


def test_login_missing_password_field() -> None:
    data = {'email': 'test@example.com', 'password': ''}

    response, status = authenticate_user(data['email'], data['password'])

    assert status == 400
    assert response == {"message": "Password is required."}


def test_login_missing_fields() -> None:
    data = {'email': '', 'password': ''}

    response, status = authenticate_user(data['email'], data['password'])

    assert status == 400
    assert response == {"message": "Email and password are required."}


def test_login_incorrect_email_format() -> None:
    data = {'email': 'test@.com', 'password': 'SecurePassword@123'}

    response, status = authenticate_user(data['email'], data['password'])

    assert status == 400
    assert response == {"message": "Invalid email format."}


def test_login_not_found_user() -> None:
    data = {'email': 'test@example.com', 'password': 'SecurePassword@123'}

    with patch('app.services.auth_service.db.session') as mock_session:
        mock_query = mock_session.query.return_value
        mock_filter = mock_query.filter_by.return_value
        mock_filter.first.return_value = None

        response, status = authenticate_user(data['email'], data['password'])

        mock_session.query.assert_called_once_with(User)
        mock_query.filter_by.assert_called_once_with(email=data['email'])
        mock_filter.first.assert_called_once()

        assert status == 401
        assert response == {'message': 'Invalid credentials.'}


def test_login_incorrect_password() -> None:
    data = {'email': 'test@example.com', 'password': 'SecurePassword@123'}

    mock_user = MagicMock(spec=User)
    mock_user.id = uuid.uuid4()
    mock_user.password = 'hashed_password'

    with patch('app.services.auth_service.check_password_hash') as mock_check_password_hash:
        mock_check_password_hash.return_value = False

        with patch('app.services.auth_service.db.session') as mock_session:
            mock_query = mock_session.query.return_value
            mock_filter = mock_query.filter_by.return_value
            mock_filter.first.return_value = mock_user

            response, status = authenticate_user(data['email'], data['password'])

            mock_session.query.assert_called_once_with(User)
            mock_query.filter_by.assert_called_once_with(email=data['email'])
            mock_filter.first.assert_called_once()
            mock_check_password_hash.assert_called_once_with('hashed_password', data['password'])

            assert status == 401
            assert response == {'message': 'Invalid credentials.'}
