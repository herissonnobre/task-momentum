"""
Tasks services for creating, reading, updating and deleting a task.

Functions:
    - create_task_service(data, user_id): Creates a new task.
    - get_tasks_service(user_id): Retrieves tasks associated with a user.
    - get_task_by_id_service(user_id): Retrieves tasks associated with a user.
    - update_tasks_service(user_id): Updates tasks associated with a user.
    - delete_tasks_service(user_id): Deletes tasks associated with a user.
"""
import uuid

from app.extensions import db
from app.models import Task


def create_task_service(data, user_id):
    """
    Creates a new task.

    :param data: dict: Task data.
    :param user_id: str: User ID.
    :return: tuple: Response message and status code.
    """
    new_task = Task(title=data['title'], description=data['description'], user_id=user_id)
    db.session.add(new_task)
    db.session.commit()
    return new_task.as_dict(), 201


def get_tasks_service(user_id):
    """
    Retrieves all tasks associated with a user.

    :param user_id: str: User ID.
    :return: tuple: Response message and status code.
    """
    tasks = Task.query.filter_by(user_id=user_id).all()
    return [task.as_dict() for task in tasks], 200


def get_task_by_id_service(task_id, user_id):
    """
    Retrieves a task by ID.

    :param task_id: str: Task ID.
    :param user_id: str: User ID.
    :return: tuple: Response message and status code.
    """
    task = Task.query.filter_by(id=uuid.UUID(task_id), user_id=user_id).first()
    if task is None:
        return [{"message": "Task not found"}], 404
    return task.as_dict(), 200


def update_task_service(task_id, user_id, data):
    """
    Updates a task.

    :param task_id: str: Task ID.
    :param user_id: str: User ID.
    :param data: dict: Task data.
    :return: tuple: Response message and status code.
    """
    task = Task.query.filter_by(id=uuid.UUID(task_id), user_id=user_id).first()

    if not task:
        return [{"message": "Task not found"}], 404

    task.title = data.get('title', task.title)
    task.description = data.get('description', task.description)
    task.completed = data.get('completed', task.completed)
    db.session.commit()
    return task.as_dict(), 200


def delete_task_service(task_id, user_id):
    """
    Deletes a task.

    :param task_id: str: Task ID.
    :param user_id: str: User ID.
    :return: tuple: Response message and status code.
    """
    task = Task.query.filter_by(id=uuid.UUID(task_id), user_id=user_id).first()

    if not task:
        return [{"message": "Task not found"}], 404

    db.session.delete(task)
    db.session.commit()
    return [{"message": "Task deleted"}], 200
