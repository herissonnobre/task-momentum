"""
Authentication services for user registration and login.

Functions:
    - register_user(data): Registers a new user.
    - login_user(data): Authenticates a user and generates a JWT token.
"""
import traceback

from werkzeug.security import generate_password_hash, check_password_hash

from app.extensions import db
from app.models import User
from app.utils.token import generate_token
from app.utils.validations import is_valid_email, is_valid_password

# Error messages
ERROR_EMAIL_REQUIRED = {"message": "Email is required."}
ERROR_PASSWORD_REQUIRED = {"message": "Password is required."}
ERROR_EMAIL_PASSWORD_REQUIRED = {"message": "Email and password are required."}
ERROR_INVALID_EMAIL_FORMAT = {"message": "Invalid email format."}
ERROR_INVALID_PASSWORD_FORMAT = {
    "message": "Password must contain, at least, one uppercase letter, one lowercase letter, one number and one symbol and must be bigger than 8 characters."}
ERROR_EMAIL_ALREADY_REGISTERED = {"message": "Email already registered."}
ERROR_INVALID_CREDENTIALS = {"message": "Invalid credentials."}


def validate_email_password(email, password):
    """

    :param email:
    :param password:
    :return:
    """
    if not email and not password:
        return False, ERROR_EMAIL_PASSWORD_REQUIRED
    elif not email:
        return False, ERROR_EMAIL_REQUIRED
    elif not password:
        return False, ERROR_PASSWORD_REQUIRED

    if not is_valid_email(email):
        return False, ERROR_INVALID_EMAIL_FORMAT

    return True, None


def register_user(email, password):
    """
    Registers a new user.

    This function handles the registration of a new user by validating the provided data, hashing the user's password
    and saving the user to the database.

    :param email: str: Email address of the user.
    :param password: str: Password of the user.
    :return: tuple: (Response message, HTTP status code).
    """
    try:
        data_status, response_message = validate_email_password(email, password)

        if not data_status:
            return response_message, 400

        if not is_valid_password(password):
            return ERROR_INVALID_PASSWORD_FORMAT, 400

        if db.session.query(User).filter_by(email=email).first():
            return ERROR_EMAIL_ALREADY_REGISTERED, 400

        hashed_password = generate_password_hash(password)

        new_user = User(email=email, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()
        return {"message": "User registered successfully."}, 201

    except Exception as e:
        print(traceback.format_exc())
        return {"message": "An error occurred while registering a new user."}, 500


def authenticate_user(email, password):
    """
    Authenticates a user and generates a JWT token.

    This function handles the authentication of a user by validating the provided data, checking the user's password,
    and generating a JWT token if authentication is successful.

    :param email: str: Email address of the user.
    :param password: str: Password of the user.
    :return: tuple: (Response message, HTTP status code).
    """
    try:
        data_status, response_message = validate_email_password(email, password)

        if not data_status:
            return response_message, 400

        user = db.session.query(User).filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            return ERROR_INVALID_CREDENTIALS, 401

        token = generate_token(str(user.id))

        return {"token": token}, 200
    except Exception:
        print(traceback.format_exc())
        return {"message": "An error occurred while authenticating the user."}, 500
