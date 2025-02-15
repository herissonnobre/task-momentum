"""
Task controllers for handling task management.

Functions:
    - create_task(): Creates a new task.
    - get_tasks(): Returns a list of tasks.
    - get_task_by_id(): Returns a task by id.
    - update_task(): Updates a task.
    - delete_task(): Deletes a task.
"""
from flask import request, jsonify, g

from app.services.tasks_service import create_task_service, get_tasks_service, get_task_by_id_service, \
    update_task_service, delete_task_service


def create_task():
    """
    Handles creating a new task.
    """
    if not request.data or not request.is_json:
        return jsonify(
            {'message': "Request must have a body with 'title' key."}), 400

    data = request.get_json()

    if 'title' not in data or 'description' not in data:
        return jsonify(
            {'message': "Request must have a body with 'title' key."}), 400

    response, status = create_task_service(data, g.user_id)

    return jsonify(response), status


def get_tasks():
    """
    Handles getting all tasks for the authenticated user.
    """
    response, status = get_tasks_service(g.user_id)
    return jsonify(response), status


def get_task_by_id(task_id):
    """
    Handles getting a task by its id.
    """
    response, status = get_task_by_id_service(task_id, g.user_id)
    return jsonify(response), status


def update_task(task_id):
    """
    Handles updating a task by its id.
    """
    data = request.get_json()
    response, status = update_task_service(task_id, g.user_id, data)
    return jsonify(response), status


def delete_task(task_id):
    """
    Handles deleting a task by its id.
    """
    response, status = delete_task_service(task_id, g.user_id)
    return jsonify(response), status
