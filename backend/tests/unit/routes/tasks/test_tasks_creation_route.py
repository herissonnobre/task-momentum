from unittest.mock import patch

import jwt
from flask import g


class TestTasksCreationRoute:
    def test_create_task_success(self, testing_client):
        """
        Test creating a new task.
        """
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.create_task') as mock_create_task:
                mock_create_task.return_value = ({'message': 'Task created successfully.'}, 201)
                response = testing_client.post('/tasks', headers={'Authorization': "fake_token"}, json={
                    'title': 'Testing Task',
                    'description': 'This is a test task',
                })

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 201
                assert response.json == {"message": "Task created successfully."}

    def test_create_task_missing_authorization_header(self, testing_client):
        response = testing_client.post('/tasks', json={
            'title': 'Testing Task',
            'description': 'This is a test task',
        })

        assert response.status_code == 401
        assert response.json == {"message": "Authorization header is missing."}

    def test_create_task_missing_token(self, testing_client):
        response = testing_client.post('/tasks', headers={'Authorization': ''}, json={
            'title': 'Testing Task',
            'description': 'This is a test task',
        })

        assert response.status_code == 401
        assert response.json == {"message": "Token is missing from the Authorization header."}

    def test_create_task_not_valid_jwt(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.side_effect = jwt.InvalidTokenError

            response = testing_client.post('/tasks', headers={'Authorization': 'not-valid-jwt-token'}, json={
                'title': 'Testing Task',
                'description': 'This is a test task',
            })

            assert response.status_code == 401
            assert response.json == {"message": "Invalid JWT token."}

    def test_create_task_expired_jwt(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.side_effect = jwt.ExpiredSignatureError

            response = testing_client.post('/tasks', headers={'Authorization': 'expired-jwt-token'}, json={
                'title': 'Testing Task',
                'description': 'This is a test task',
            })

            assert response.status_code == 401
            assert response.json == {"message": "JWT token has expired."}

    def test_create_task_security_internal_error(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.side_effect = Exception

            response = testing_client.post('/tasks',
                                           headers={'Authorization': "fake_token"}, json={
                    'title': 'Testing Task',
                    'description': 'This is a test task',
                })

            mock_verify_token.assert_called_once_with('fake_token')

            assert response.status_code == 500
            assert response.json == {"message": "An internal error occurred on user authorization."}

    def test_create_task_missing_request_body(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.create_task') as mock_create_task:
                mock_create_task.return_value = ({'message': "Request must have a body with 'title' key."}, 400)

                response = testing_client.post('/tasks', headers={'Authorization': "fake_token"})

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get('user_id')) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 400
                assert response.json == {"message": "Request must have a body with 'title' key."}

    def test_create_task_missing_title_property(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.create_task') as mock_create_task:
                mock_create_task.return_value = ({'message': "Request must have a body with 'title' key."}, 400)
                response = testing_client.post('/tasks', headers={'Authorization': 'fake_token'}, json={
                    'description': 'This is a test task',
                })

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 400
                assert response.json == {"message": "Request must have a body with 'title' key."}

    def test_create_task_missing_title_field(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.create_task') as mock_create_task:
                mock_create_task.return_value = ({'message': 'Title is required.'}, 400)
                response = testing_client.post('/tasks', headers={'Authorization': 'fake_token'}, json={
                    'title': '',
                    'description': 'This is a test task',
                })

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 400
                assert response.json == {"message": "Title is required."}

    def test_create_task_not_valid_title(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.create_task') as mock_create_task:
                mock_create_task.return_value = ({'message': 'Title must be a valid string.'}, 400)
                response = testing_client.post('/tasks', headers={'Authorization': 'fake_token'}, json={
                    'title': 123,
                    'description': 'This is a test task',
                })

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 400
                assert response.json == {"message": "Title must be a valid string."}

    def test_create_task_missing_description_field(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.create_task') as mock_create_task:
                mock_create_task.return_value = ({'message': 'Description is missing.'}, 400)
                response = testing_client.post('/tasks', headers={'Authorization': 'fake_token'}, json={
                    'title': 'Testing Task',
                    'description': '',
                })

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 400
                assert response.json == {"message": "Description is missing."}

    def test_create_task_not_valid_description(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.create_task') as mock_create_task:
                mock_create_task.return_value = ({'message': 'Description must be a valid string.'}, 400)
                response = testing_client.post('/tasks', headers={'Authorization': 'fake_token'}, json={
                    'title': 'Testing Task',
                    'description': 123,
                })

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 400
                assert response.json == {"message": "Description must be a valid string."}

    def test_create_task_missing_completed_field(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.create_task') as mock_create_task:
                mock_create_task.return_value = ({'message': 'Completed is missing.'}, 400)
                response = testing_client.post('/tasks', headers={'Authorization': 'fake_token'}, json={
                    'title': 'Testing Task',
                    'description': 'This is a test task',
                    'completed': '',
                })

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 400
                assert response.json == {"message": "Completed is missing."}

    def test_create_task_not_valid_completed(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.create_task') as mock_create_task:
                mock_create_task.return_value = ({'message': 'Completed must be either True or False.'}, 400)
                response = testing_client.post('/tasks', headers={'Authorization': 'fake_token'}, json={
                    'title': 'Testing Task',
                    'description': 'This is a test task',
                    'completed': 'True',
                })

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 400
                assert response.json == {"message": "Completed must be either True or False."}
