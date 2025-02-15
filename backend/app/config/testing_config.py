"""
Testing configuration settings for the application.

Classes:
    - TestingConfig: Testing configuration.
"""
import os

from dotenv import load_dotenv

from app.config import BaseConfig

load_dotenv()


class TestingConfig(BaseConfig):
    """
    Testing configuration class.

    Attributes:
        - SQLALCHEMY_DATABASE_URI (str): SQLAlchemy database URI.
    """
    SQLALCHEMY_DATABASE_URI: str = os.environ.get('TESTING_DATABASE_URL') or 'sqlite:///:memory:'
    TESTING: bool = True
