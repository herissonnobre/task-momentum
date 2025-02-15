import uuid
from unittest.mock import patch

import jwt
from flask import g


class TestTasksDeleteRoute:
    def test_delete_task_success(self, testing_client):
        task_id = str(uuid.uuid4())

        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.delete_task') as mock_delete_task:
                mock_delete_task.return_value = ({"message": "Task successfully deleted."}, 200)
                response = testing_client.delete(f'/tasks/{task_id}', headers={'Authorization': 'fake_token'})

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 200
                assert response.json == {"message": "Task successfully deleted."}

    def test_delete_task_missing_authorization_header(self, testing_client):
        task_id = str(uuid.uuid4())

        response = testing_client.delete(f'/tasks/{task_id}')

        assert response.status_code == 401
        assert response.json == {"message": "Authorization header is missing."}

    def test_delete_task_missing_token(self, testing_client):
        task_id = str(uuid.uuid4())

        response = testing_client.delete(f'/tasks/{task_id}', headers={'Authorization': ''})

        assert response.status_code == 401
        assert response.json == {"message": "Token is missing from the Authorization header."}

    def test_delete_task_not_valid_jwt(self, testing_client):
        task_id = str(uuid.uuid4())

        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.side_effect = jwt.InvalidTokenError

            response = testing_client.delete(f'/tasks/{task_id}', headers={'Authorization': 'not-valid-jwt-token'})

            assert response.status_code == 401
            assert response.json == {"message": "Invalid JWT token."}

    def test_delete_task_expired_jwt(self, testing_client):
        task_id = str(uuid.uuid4())

        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.side_effect = jwt.ExpiredSignatureError

            response = testing_client.delete(f'/tasks/{task_id}', headers={'Authorization': 'expired-jwt-token'})

            assert response.status_code == 401
            assert response.json == {"message": "JWT token has expired."}

    def test_delete_task_security_internal_error(self, testing_client):
        task_id = str(uuid.uuid4())

        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.side_effect = Exception

            response = testing_client.delete(f'/tasks/{task_id}', headers={'Authorization': 'fake_token'})

            mock_verify_token.assert_called_once_with('fake_token')

            assert response.status_code == 500
            assert response.json == {"message": "An internal error occurred on user authorization."}

    def test_delete_task_missing_id(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.delete_task') as mock_delete_task:
                mock_delete_task.return_value = ({"message": 'Task ID is missing.'}, 400)

                response = testing_client.delete('/tasks/', headers={'Authorization': 'fake_token'})

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 400
                assert response.json == {"message": "Task ID is missing."}

    def test_delete_task_not_valid_id(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            invalid_task_id = 'not-a-valid-id'

            with patch('app.routes.tasks.delete_task') as mock_delete_task:
                mock_delete_task.return_value = ({"message": 'Task ID is not a valid UUID.'}, 400)
                response = testing_client.delete(f'/tasks/{invalid_task_id}',
                                                 headers={'Authorization': 'fake_token'})

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 400
                assert response.json == {"message": "Task ID is not a valid UUID."}

    def test_delete_task_not_found(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            non_existing_task_id = str(uuid.uuid4())

            with patch('app.routes.tasks.delete_task') as mock_delete_task:
                mock_delete_task.return_value = ({"message": 'Task not found.'}, 404)
                response = testing_client.delete(f'/tasks/{non_existing_task_id}',
                                                 headers={'Authorization': 'fake_token'})

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 404
                assert response.json == {"message": "Task not found."}

    def test_delete_task_unauthorized(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            not_owned_task_id = str(uuid.uuid4())

            with patch('app.routes.tasks.delete_task') as mock_delete_task:
                mock_delete_task.return_value = ({"message": 'Task belongs to another user.'}, 401)
                response = testing_client.delete(f'/tasks/{not_owned_task_id}',
                                                 headers={'Authorization': 'fake_token'})

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 401
                assert response.json == {"message": "Task belongs to another user."}

    def test_delete_task_internal_error(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            task_id = str(uuid.uuid4())

            with patch('app.routes.tasks.delete_task') as mock_delete_task:
                mock_delete_task.return_value = ({'message': 'An internal error occurred while deleting task.'}, 500)
                response = testing_client.delete(f'/tasks/{task_id}', headers={'Authorization': 'fake_token'})

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 500
                assert response.json == {"message": "An internal error occurred while deleting task."}
