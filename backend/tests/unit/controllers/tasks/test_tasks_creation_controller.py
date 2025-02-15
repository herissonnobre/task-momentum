import uuid
from unittest.mock import patch

from flask import g

from app.controllers.tasks_controller import create_task


class TestTasksCreationController:
    def test_create_task_success(self, testing_app, testing_user_jwt):
        """
        Test creating a new task.
        """
        with patch('app.controllers.tasks_controller.create_task_service') as mock_create_task_service:
            mock_create_task_service.return_value = ({'message': 'Task created successfully.'}, 201)

            with testing_app.test_request_context('/tasks', method='POST', json={
                'title': 'Testing Task',
                'description': 'This is a test task',
            }, headers={'Content-Type': 'application/json', 'Authorization': testing_user_jwt}):
                g.user_id = str(uuid.uuid4())

                response, status = create_task()

                assert status == 201
                assert response.get_json() == {"message": "Task created successfully."}

    def test_create_task_missing_request_body(self, testing_app, testing_user_jwt):
        with testing_app.test_request_context('/tasks', method='POST', headers={'Authorization': testing_user_jwt}):
            g.user_id = str(uuid.uuid4())

            response, status = create_task()

            assert status == 400
            assert response.get_json() == {
                "message": "Request must have a body with 'title' key."}

    def test_create_task_missing_title_property(self, testing_app, testing_user_jwt):
        with testing_app.test_request_context('/tasks', method='POST', json={
            'description': 'This is a test task',
        }, headers={'Content-Type': 'application/json', 'Authorization': testing_user_jwt}):
            g.user_id = str(uuid.uuid4())

            response, status = create_task()

            assert status == 400
            assert response.get_json() == {"message": "Request must have a body with 'title' key."}

    def test_create_task_missing_title_field(self, testing_app, testing_user_jwt):
        with patch('app.controllers.tasks_controller.create_task_service') as mock_create_task_service:
            mock_create_task_service.return_value = ({'message': 'Title is required.'}, 400)

            with testing_app.test_request_context('/tasks', method='POST', json={
                'title': '',
                'description': 'This is a test task',
            }, headers={'Content-Type': 'application/json', 'Authorization': testing_user_jwt}):
                g.user_id = str(uuid.uuid4())

                response, status = create_task()

                assert status == 400
                assert response.get_json() == {"message": "Title is required."}

    def test_create_task_not_valid_title(self, testing_app, testing_user_jwt):
        with patch('app.controllers.tasks_controller.create_task_service') as mock_create_task_service:
            mock_create_task_service.return_value = ({'message': 'Title must be a valid string.'}, 400)

            with testing_app.test_request_context('/tasks', method='POST', json={
                'title': 123,
                'description': 'This is a test task',
            }, headers={'Content-Type': 'application/json', 'Authorization': testing_user_jwt}):
                g.user_id = str(uuid.uuid4())

                response, status = create_task()

                assert status == 400
                assert response.get_json() == {"message": 'Title must be a valid string.'}

    def test_create_task_missing_description_field(self, testing_app, testing_user_jwt):
        with patch('app.controllers.tasks_controller.create_task_service') as mock_create_task_service:
            mock_create_task_service.return_value = ({'message': 'Description is missing.'}, 400)

            with testing_app.test_request_context('/tasks', method='POST', json={
                'title': 'Testing Task',
                'description': '',
            }, headers={'Content-Type': 'application/json', 'Authorization': testing_user_jwt}):
                g.user_id = str(uuid.uuid4())

                response, status = create_task()

                assert status == 400
                assert response.get_json() == {"message": 'Description is missing.'}

    def test_create_task_not_valid_description(self, testing_app, testing_user_jwt):
        with patch('app.controllers.tasks_controller.create_task_service') as mock_create_task_service:
            mock_create_task_service.return_value = ({'message': 'Description must be a valid string.'}, 400)

            with testing_app.test_request_context('/tasks', method='POST', json={
                'title': 'Testing Task',
                'description': 123,
            }, headers={'Content-Type': 'application/json', 'Authorization': testing_user_jwt}):
                g.user_id = str(uuid.uuid4())

                response, status = create_task()

                assert status == 400
                assert response.get_json() == {"message": 'Description must be a valid string.'}

    def test_create_task_missing_completed_field(self, testing_app, testing_user_jwt):
        with patch('app.controllers.tasks_controller.create_task_service') as mock_create_task_service:
            mock_create_task_service.return_value = ({'message': 'Completed is missing.'}, 400)

            with testing_app.test_request_context('/tasks', method='POST', json={
                'title': 'Testing Task',
                'description': 'This is a test task',
                'completed': '',
            }, headers={'Content-Type': 'application/json', 'Authorization': testing_user_jwt}):
                g.user_id = str(uuid.uuid4())

                response, status = create_task()

                assert status == 400
                assert response.get_json() == {"message": 'Completed is missing.'}

    def test_create_task_not_valid_completed(self, testing_app, testing_user_jwt):
        with patch('app.controllers.tasks_controller.create_task_service') as mock_create_task_service:
            mock_create_task_service.return_value = ({'message': 'Completed must be either True or False.'}, 400)

            with testing_app.test_request_context('/tasks', method='POST', json={
                'title': 'Testing Task',
                'description': 'This is a test task',
                'completed': 123,
            }, headers={'Content-Type': 'application/json', 'Authorization': testing_user_jwt}):
                g.user_id = str(uuid.uuid4())

                response, status = create_task()

                assert status == 400
                assert response.get_json() == {"message": 'Completed must be either True or False.'}
