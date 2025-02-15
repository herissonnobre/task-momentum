"""
Register Flask Blueprints for authentication and tasks routes.

Functions:
    - register_blueprints(app): Registers the authentication and tasks blueprints.
"""

from app.routes.auth import auth_blueprint
from app.routes.tasks import tasks_blueprint


def register_blueprints(app):
    """
    Register the authentication and tasks blueprints with URL prefixes.

    :param app:Flask: The Flask application instance.
    """
    app.register_blueprint(auth_blueprint, url_prefix='/auth')
    app.register_blueprint(tasks_blueprint)
