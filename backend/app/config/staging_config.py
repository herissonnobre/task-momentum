"""
Staging configuration settings for the application.

Classes:
    - StagingConfig: Staging configuration.
"""
import os

from dotenv import load_dotenv

from app.config import BaseConfig

load_dotenv()


class StagingConfig(BaseConfig):
    """
    Staging configuration class.

    Attributes:
        - SQLALCHEMY_DATABASE_URI (str): SQLAlchemy database URI.
    """
    SQLALCHEMY_DATABASE_URI: str = os.environ.get('STAGING_DATABASE_URL') or 'sqlite:///staging.db'
