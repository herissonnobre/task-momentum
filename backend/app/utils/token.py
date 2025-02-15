"""
Functions to generate and verify JWT tokens.

Functions:
    - generate_token(user_id): Generates a JWT token.
    - verify_token(token): Verifies a JWT token.

Exceptions:
    - jwt.ExpiredTokenError: Token expired.
    - jwt.InvalidTokenError: Token invalid.
"""
import os
from datetime import datetime, timedelta

import jwt
from dotenv import load_dotenv

# Load env variables from .env file
load_dotenv()

# Gets secret key from env variables
SECRET_KEY = os.getenv('SECRET_KEY')


def generate_token(user_id: str) -> str:
    """
    Generates a JWT token for a specific user.

    Parameters:
    user_id (int): The ID of the user.

    Returns:
    str: The JWT token.

    Raises:
    Exception: if an error occurs while generating the token.

    :param user_id:str: the ID of the user.
    :return: str: the JWT token.
    """
    try:
        payload = {
            'exp': datetime.now() + timedelta(days=1),
            'iat': datetime.now(),
            'sub': user_id,
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        return token
    except Exception as e:
        raise Exception(f"An error occurred while generating the token: {e}")


def verify_token(token) -> str:
    """
    Verifies if a JWT token is valid and returns the user ID.

    Parameters:
    token (str): The JWT token.

    Returns:
    str: The ID of the user.

    Raises:
    jwt.ExpiredSignatureError: If the token is expired.
    jwt.InvalidTokenError: If the token is invalid.
    Exception: If an error occurs while verifying the token.

    :param token:str: The JWT token.
    :return: user_id (str): The ID of the user.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload['sub']
    except jwt.ExpiredSignatureError:
        raise jwt.ExpiredSignatureError("Token expired.")
    except jwt.InvalidTokenError:
        raise jwt.InvalidTokenError("Invalid token.")
    except Exception:
        raise Exception("Internal error.")
