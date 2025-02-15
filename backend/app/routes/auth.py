"""
Authentication endpoints for user registration and login.

Functions:
    - register_route(): Registers a new user.
    - login_route(): Logs in a user and returns a JWT token.

Decorators:
    - @auth_blueprint.route(): Defines routes for registration and login.
"""
from flask import Blueprint, Response

from app.controllers.auth_controller import register, login

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
