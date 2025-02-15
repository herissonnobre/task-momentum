"""
Unit tests for JWT token generation and verification using pytest.
"""

import uuid
from datetime import timedelta, datetime
from unittest.mock import patch

import jwt
import pytest

from app.utils.token import generate_token, verify_token


def test_generate_token() -> None:
    """
    Test JWT token generation.
    """
    user_id = uuid.uuid4().hex

    with patch('app.utils.token.SECRET_KEY', "secret"):
        token = generate_token(user_id)

        assert isinstance(token, str)

    payload = jwt.decode(token, "secret", algorithms=["HS256"])

    assert payload['sub'] == user_id
    assert 'exp' in payload
    assert 'iat' in payload


def test_verify_token() -> None:
    """
    Test valid JWT token verification.
    :return:
    """
    user_id = uuid.uuid4().hex

    payload = {
        'exp': datetime.now() + timedelta(days=1),
        'iat': datetime.now(),
        'sub': user_id,
    }

    token = jwt.encode(payload, "secret", algorithm="HS256")

    with patch('app.utils.token.SECRET_KEY', "secret"):
        decoded_user_id = verify_token(token)

        assert decoded_user_id == user_id


def test_verify_token_expired() -> None:
    """
    Test expired JWT token verification.
    """
    user_id = uuid.uuid4().hex

    payload = {
        'exp': datetime.now() - timedelta(seconds=1),
        'iat': datetime.now() - timedelta(days=1),
        'sub': user_id,
    }

    token = jwt.encode(payload, 'secret', algorithm="HS256")

    with patch('app.utils.token.SECRET_KEY', "secret"):
        with pytest.raises(jwt.ExpiredSignatureError):
            verify_token(token)


def test_verify_token_invalid() -> None:
    """
    Test invalid JWT token verification.
    """
    token = "it.is.not.a.token"

    with patch('app.utils.token.SECRET_KEY', "secret"):
        with pytest.raises(jwt.InvalidTokenError):
            verify_token(token)
