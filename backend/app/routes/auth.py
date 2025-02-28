"""
Authentication endpoints for user registration and login.

Functions:
    - register_route(): Registers a new user.
    - login_route(): Logs in a user and returns a JWT token.

Decorators:
    - @auth_blueprint.route(): Defines routes for registration and login.
"""
from flask import Blueprint, Response

from app.controllers.auth_controller import register, login, request_password_reset, reset_password

auth_blueprint = Blueprint('auth', __name__)


@auth_blueprint.route('/register', methods=['POST'])
def register_route() -> tuple[Response, int]:
    """
    Handles user registration.

    Request body (JSON):
        - email (str): The email of the user.
        - password (str): The password of the user.

    Returns:
        - tuple[Response, int]: JSON response and status code.
    """
    return register()


@auth_blueprint.route('/login', methods=['POST'])
def login_route() -> tuple[Response, int]:
    """
    Handles user login.

    Request body (JSON):
        - email (str): The email of the user.
        - password (str): The password of the user.

    Returns:
        - tuple[Response, int]: JSON response with JWT token and status code.
    """
    return login()


@auth_blueprint.route('/password-reset', methods=['POST'])
def request_password_reset_route() -> tuple[Response, int]:
    """
    Initiates the password reset process by sending an email with a reset token.

    Request body (JSON):
        - email (str): The email of the user.

    Returns:
        - tuple[Response, int]: JSON response and status code.
    """
    return request_password_reset()


@auth_blueprint.route('/password-reset', methods=['PUT'])
def reset_password_route() -> tuple[Response, int]:
    """
    Completes the password reset process using the token provided via email.

    Request body (JSON):
        - token (str): The password reset token.
        - new_password (str): The new password.

    Returns:
        - tuple[Response, int]: JSON response and status code.
    """
    return reset_password()
