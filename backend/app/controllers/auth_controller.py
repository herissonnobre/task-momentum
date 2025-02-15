"""
Authentication controllers for handling user registration and login.

Functions:
    - register(): Handles user registration by calling the service layer.
    - login(): Handles user login by calling the service layer.
"""
from flask import request, jsonify

from app.services.auth_service import register_user, authenticate_user


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
