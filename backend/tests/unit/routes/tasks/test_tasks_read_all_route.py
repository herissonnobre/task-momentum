import uuid
from datetime import datetime
from unittest.mock import patch

import jwt
from flask import g


class TestTasksReadAllRoute:
    def test_read_tasks_success_empty(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.get_tasks') as mock_get_tasks:
                mock_get_tasks.return_value = ({'tasks': []}, 200)
                response = testing_client.get('/tasks', headers={'Authorization': 'fake_token'})

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 200
                assert 'tasks' in response.json
                assert response.json['tasks'] == []

    def test_read_tasks_success(self, testing_client):
        mock_tasks = [
            {
                'id': str(uuid.uuid4()),
                'title': 'Testing Task 1',
                'description': 'This is the first test task',
                'completed': False,
                'created_at': datetime.now().isoformat()
            },
            {
                'id': str(uuid.uuid4()),
                'title': 'Testing Task 2',
                'description': 'This is the second test task',
                'completed': True,
                'created_at': datetime.now().isoformat()
            }
        ]

        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.get_tasks') as mock_get_tasks:
                mock_get_tasks.return_value = ({'tasks': mock_tasks}, 200)
                response = testing_client.get('/tasks', headers={'Authorization': 'fake_token'})

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 200
                assert 'tasks' in response.json
                assert isinstance(response.json['tasks'], list)
                assert len(response.json['tasks']) == len(mock_tasks)
                assert response.json['tasks'] == mock_tasks

    def test_read_tasks_missing_authorization_header(self, testing_client):
        response = testing_client.get('/tasks')

        assert response.status_code == 401
        assert response.json == {"message": "Authorization header is missing."}

    def test_read_tasks_missing_token(self, testing_client):
        response = testing_client.get('/tasks', headers={'Authorization': ''})

        assert response.status_code == 401
        assert response.json == {"message": "Token is missing from the Authorization header."}

    def test_read_tasks_not_valid_jwt(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.side_effect = jwt.InvalidTokenError

            response = testing_client.get('/tasks', headers={'Authorization': 'not-valid-jwt-token'})

            assert response.status_code == 401
            assert response.json == {"message": "Invalid JWT token."}

    def test_read_tasks_expired_jwt(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.side_effect = jwt.ExpiredSignatureError

            response = testing_client.get('/tasks', headers={'Authorization': 'expired-jwt-token'})

            assert response.status_code == 401
            assert response.json == {"message": "JWT token has expired."}

    def test_read_tasks_security_internal_error(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.side_effect = Exception

            response = testing_client.get('/tasks', headers={'Authorization': 'fake_token'})

            mock_verify_token.assert_called_once_with('fake_token')

            assert response.status_code == 500
            assert response.json == {"message": "An internal error occurred on user authorization."}

    def test_read_tasks_internal_error(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.get_tasks') as mock_get_tasks:
                mock_get_tasks.return_value = ({'message': 'An internal error occurred while getting tasks.'}, 500)
                response = testing_client.get('/tasks', headers={'Authorization': 'fake_token'})

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 500
                assert response.json == {"message": "An internal error occurred while getting tasks."}
