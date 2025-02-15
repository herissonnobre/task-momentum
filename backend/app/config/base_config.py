"""
Base configuration settings for the application.

Classes:
    - BaseConfig: Base configuration.
"""

import os

from dotenv import load_dotenv

load_dotenv()


class BaseConfig:
    """
    Base configuration class.

    Attributes:
        - SECRET_KEY (str): Secret key for the application.
        - SQLALCHEMY_TRACK_MODIFICATIONS (bool): If True, SQLAlchemy tracks modifications.
        - SQLALCHEMY_ECHO (bool): If True, SQLAlchemy echoes messages.
    """
    SECRET_KEY: str = os.environ.get('SECRET_KEY') or 'hard-to-guess-string'
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    SQLALCHEMY_ECHO: bool = False
    DEBUG: bool = False
    TESTING: bool = False
