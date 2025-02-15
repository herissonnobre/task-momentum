"""
Task management routes using Flask and SQLAlchemy.

Functions:
    - create_task(): Creates a new task.
    - get_tasks(): Returns all tasks for the authenticated user.
    - get_task_by_id(task_id): Returns the task with the given ID.
    - update_task(): Updates the task with the given ID.
    - delete_task(): Deletes the task with the given ID.

Decorators:
    - before_request(): Verifies the JWT token before each request.
"""
import traceback
import uuid

import jwt
from flask import Blueprint, request, jsonify, g

from app.controllers.tasks_controller import create_task, get_tasks, get_task_by_id, update_task, delete_task
from app.utils.token import verify_token

tasks_blueprint = Blueprint('tasks', __name__)


@tasks_blueprint.before_request
def before_request():
    """
    Verify the JWT token before each request.

    Returns:
        - JSON: Error message if token is missing or invalid.
        - HTTP Status Code: 401 (Unauthorized).
    """
    if 'Authorization' not in request.headers:
        return jsonify({'message': 'Authorization header is missing.'}), 401

    token = request.headers['Authorization']

    if not token:
        return jsonify({"message": "Token is missing from the Authorization header."}), 401

    try:
        user_id = verify_token(token)

        user_id_uuid = uuid.UUID(user_id)

        if str(user_id_uuid) != user_id:
            return jsonify({"message": "An internal error occurred on user authorization."}), 401

        g.user_id = str(user_id_uuid)

    except jwt.ExpiredSignatureError:
        return jsonify({"message": "JWT token has expired."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid JWT token."}), 401
    except Exception:
        print(traceback.format_exc())
        return jsonify({"message": 'An internal error occurred on user authorization.'}), 500


@tasks_blueprint.route('/tasks', methods=['POST'])
def create_task_route():
    """
    Create a new task for the authenticated user.
    """

    return create_task()


@tasks_blueprint.route('/tasks', methods=['GET'])
def get_tasks_route():
    """
    Retrieve all tasks for the authenticated user.
    """
    return get_tasks()


@tasks_blueprint.route('/tasks/', defaults={'task_id': None}, methods=['GET'])
@tasks_blueprint.route('/tasks/<task_id>', methods=['GET'])
def get_task_by_id_route(task_id=None):
    """
    Retrieve a specific task by ID for the authenticated user.
    """
    return get_task_by_id(task_id)


@tasks_blueprint.route('/tasks/', defaults={'task_id': None}, methods=['PUT'])
@tasks_blueprint.route('/tasks/<task_id>', methods=['PUT'])
def update_task_route(task_id):
    """
    Update a specific task by ID for the authenticated user.

    Parameters:
        - task_id (str): The ID of the task to update.
    """
    return update_task(task_id)


@tasks_blueprint.route('/tasks/', defaults={'task_id': None}, methods=['DELETE'])
@tasks_blueprint.route('/tasks/<task_id>', methods=['DELETE'])
def delete_task_route(task_id):
    """
    Delete a specific task by ID for the authenticated user.

    Parameters:
        - task_id (str): The ID of the task to delete.
    """
    return delete_task(task_id)
