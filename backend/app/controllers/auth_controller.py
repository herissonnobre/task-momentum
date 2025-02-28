"""
Authentication controllers for handling user registration and login.

Functions:
    - register(): Handles user registration by calling the service layer.
    - login(): Handles user login by calling the service layer.
"""
from flask import request, jsonify

from app.services.auth_service import register_user, authenticate_user, generate_password_reset_token, \
    reset_user_password


def register():
    """
    Handles user registration.

    Extracts the user data from the request, calls the service layer to register the user, and
    returns a JSON response with the result and the HTTP status code.

    Request body (JSON):
        - email (str): Email of the user.
        - password (str): Password of the user.

    Returns:
        - tuple: (JSON response, HTTP status code).
    """
    if not request.data or not request.is_json:
        return jsonify(
            {'message': "Request must have a body with 'email' and 'password' fields as raw JSON data."}), 400

    data = request.get_json()

    if 'email' not in data or 'password' not in data:
        return jsonify(
            {'message': "Request must have a body with 'email' and 'password' fields as raw JSON data."}), 400

    response, status = register_user(data['email'], data['password'])

    return jsonify(response), status


def login():
    """
    Handles user login.

    Extracts the user data from the request, calls the service layer to authenticate the user, and
    returns a JSON response with the result and the HTTP status code.

    Request body (JSON):
        - email (str): Email of the user.
        - password (str): Password of the user.

    Returns:
        - tuple: (JSON response, HTTP status code).
    """
    if not request.data or not request.is_json:
        return jsonify(
            {'message': "Request must have a body with 'email' and 'password' fields as raw JSON data."}), 400

    data = request.get_json()

    if 'email' not in data or 'password' not in data:
        return jsonify(
            {'message': "Request must have a body with 'email' and 'password' fields as raw JSON data."}), 400

    data = request.get_json()

    response, status = authenticate_user(data['email'], data['password'])

    return jsonify(response), status


def request_password_reset():
    """
    Initiates the password reset process.

    Request body (JSON):
        - email (str): Email of the user requesting password reset.

    Returns:
        - tuple: (JSON response, HTTP status code).
    """
    if not request.is_json:
        return jsonify({'message': "Request body must be in JSON format."}), 400

    data = request.get_json()

    if not data or 'email' not in data:
        return jsonify({'message': "Email is required."}), 400

    response, status = generate_password_reset_token(data['email'])

    return jsonify(response), status


def reset_password():
    """
    Handles password reset.

    Request body (JSON):
        - token (str): Token for password reset verification.
        - new_password (str): New password to be set.

    Returns:
        - tuple: (JSON response, HTTP status code).
    """
    if not request.is_json:
        return jsonify(
            {'message': "Request must have a body with 'token' and 'new_password' fields as raw JSON data."}), 400

    data = request.get_json()

    if not data or 'token' not in data or 'new_password' not in data:
        return jsonify(
            {'message': "Request must have a body with 'token' and 'new_password' fields as raw JSON data."}), 400

    response, status = reset_user_password(data['token'], data['new_password'])

    return jsonify(response), status
