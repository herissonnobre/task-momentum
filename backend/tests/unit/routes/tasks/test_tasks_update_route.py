import uuid
from datetime import datetime
from unittest.mock import patch

import jwt
from flask import g


class TestTaskUpdateRoute:
    def test_update_task_success(self, testing_client):
        task_id = str(uuid.uuid4())

        updated_task_data = {
            'title': 'Updated Task Title',
            'description': 'Updated Task Description',
            'completed': True,
        }

        mock_task = {
            'id': task_id,
            'title': 'Original Task Title',
            'description': 'Original Task Description',
            'completed': False,
            'user_id': str(uuid.uuid4()),
            'created_at': datetime.now().isoformat(),
        }

        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.update_task') as mock_update_task:
                mock_update_task.return_value = ({**mock_task, **updated_task_data}, 200)
                response = testing_client.put(f'/tasks/{task_id}', headers={'Authorization': 'fake_token'},
                                              json=updated_task_data)

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 200
                assert 'id' in response.json
                assert response.json['id'] == task_id
                assert response.json['title'] == updated_task_data['title']
                assert response.json['description'] == updated_task_data['description']
                assert response.json['completed'] == updated_task_data['completed']
                assert 'created_at' in response.json
                assert response.json['created_at'] == mock_task['created_at']

    def test_update_task_missing_authorization_header(self, testing_client):
        task_id = str(uuid.uuid4())

        response = testing_client.put(f'/tasks/{task_id}')

        assert response.status_code == 401
        assert response.json == {"message": "Authorization header is missing."}

    def test_update_task_missing_token(self, testing_client):
        task_id = str(uuid.uuid4())

        response = testing_client.put(f'/tasks/{task_id}', headers={'Authorization': ''})

        assert response.status_code == 401
        assert response.json == {"message": "Token is missing from the Authorization header."}

    def test_update_task_not_valid_jwt(self, testing_client):
        task_id = str(uuid.uuid4())

        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.side_effect = jwt.InvalidTokenError

            response = testing_client.put(f'/tasks/{task_id}', headers={'Authorization': 'not-valid-jwt-token'})

            assert response.status_code == 401
            assert response.json == {"message": "Invalid JWT token."}

    def test_update_task_expired_jwt(self, testing_client):
        task_id = str(uuid.uuid4())

        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.side_effect = jwt.ExpiredSignatureError

            response = testing_client.put(f'/tasks/{task_id}', headers={'Authorization': 'expired-jwt-token'})

            assert response.status_code == 401
            assert response.json == {"message": "JWT token has expired."}

    def test_update_task_security_internal_error(self, testing_client):
        task_id = str(uuid.uuid4())

        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.side_effect = Exception

            response = testing_client.put(f'/tasks/{task_id}', headers={'Authorization': 'fake_token'})

            assert response.status_code == 500
            assert response.json == {"message": "An internal error occurred on user authorization."}

    def test_update_task_missing_id(self, testing_client):
        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.update_task') as mock_update_task:
                mock_update_task.return_value = ({"message": 'Task ID is missing.'}, 400)

                response = testing_client.put('/tasks/', headers={'Authorization': 'fake_token'})

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 400
                assert response.json == {"message": "Task ID is missing."}

    def test_update_task_not_valid_id(self, testing_client):
        invalid_task_id = 'not-a-valid-id'

        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.update_task') as mock_update_task:
                mock_update_task.return_value = ({"message": 'Task ID is not a valid UUID.'}, 400)
                response = testing_client.put(f'/tasks/{invalid_task_id}', headers={'Authorization': 'fake_token'})

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 400
                assert response.json == {"message": "Task ID is not a valid UUID."}

    def test_update_task_not_found(self, testing_client):
        non_existing_task_id = str(uuid.uuid4())

        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.update_task') as mock_update_task:
                mock_update_task.return_value = ({"message": 'Task not found.'}, 404)
                response = testing_client.put(f'/tasks/{non_existing_task_id}',
                                              headers={'Authorization': 'fake_token'})

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 404
                assert response.json == {"message": "Task not found."}

    def test_update_task_unauthorized(self, testing_client):
        not_owned_task_id = str(uuid.uuid4())

        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.update_task') as mock_update_task:
                mock_update_task.return_value = ({"message": 'Task belongs to another user.'}, 401)
                response = testing_client.put(f'/tasks/{not_owned_task_id}',
                                              headers={'Authorization': 'fake_token'})

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 401
                assert response.json == {"message": "Task belongs to another user."}

    def test_update_task_missing_title_field(self, testing_client):
        task_id = str(uuid.uuid4())

        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.update_task') as mock_update_task:
                mock_update_task.return_value = ({'message': 'Title is missing.'}, 400)
                response = testing_client.put(f'/tasks/{task_id}', headers={'Authorization': 'fake_token'}, json={
                    'title': '',
                })

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 400
                assert response.json == {"message": "Title is missing."}

    def test_update_task_not_valid_title(self, testing_client):
        task_id = str(uuid.uuid4())

        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.update_task') as mock_update_task:
                mock_update_task.return_value = ({'message': 'Title must be a valid string.'}, 400)
                response = testing_client.put(f'/tasks/{task_id}', headers={'Authorization': 'fake_token'}, json={
                    'title': 123,
                })

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 400
                assert response.json == {"message": "Title must be a valid string."}

    def test_update_task_missing_description_field(self, testing_client):
        task_id = str(uuid.uuid4())

        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.update_task') as mock_update_task:
                mock_update_task.return_value = ({'message': 'Description is missing.'}, 400)
                response = testing_client.put(f'/tasks/{task_id}', headers={'Authorization': 'fake_token'}, json={
                    'description': '',
                })

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 400
                assert response.json == {"message": "Description is missing."}

    def test_update_task_not_valid_description(self, testing_client):
        task_id = str(uuid.uuid4())

        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.update_task') as mock_update_task:
                mock_update_task.return_value = ({'message': 'Description must be a valid string.'}, 400)
                response = testing_client.put(f'/tasks/{task_id}', headers={'Authorization': 'fake_token'}, json={
                    'description': 123,
                })

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 400
                assert response.json == {"message": "Description must be a valid string."}

    def test_update_task_missing_completed_field(self, testing_client):
        task_id = str(uuid.uuid4())

        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.update_task') as mock_update_task:
                mock_update_task.return_value = ({'message': 'Completed is missing.'}, 400)
                response = testing_client.put(f'/tasks/{task_id}', headers={'Authorization': 'fake_token'}, json={
                    'completed': '',
                })

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 400
                assert response.json == {"message": "Completed is missing."}

    def test_update_task_not_valid_completed(self, testing_client):
        task_id = str(uuid.uuid4())

        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.update_task') as mock_update_task:
                mock_update_task.return_value = ({'message': 'Completed must be either True or False.'}, 400)
                response = testing_client.put(f'/tasks/{task_id}', headers={'Authorization': 'fake_token'}, json={
                    'completed': 'True',
                })

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 400
                assert response.json == {"message": "Completed must be either True or False."}

    def test_update_task_internal_error(self, testing_client):
        task_id = str(uuid.uuid4())

        updated_task_data = {
            'title': 'Updated Task Title',
            'description': 'Updated Task Description',
            'completed': True,
        }

        with patch('app.routes.tasks.verify_token') as mock_verify_token:
            mock_verify_token.return_value = "123e4567-e89b-12d3-a456-426614174000"

            with patch('app.routes.tasks.update_task') as mock_update_task:
                mock_update_task.return_value = ({'message': 'An internal error occurred while getting task.'}, 500)
                response = testing_client.put(f'/tasks/{task_id}', headers={'Authorization': 'fake_token'},
                                              json=updated_task_data)

                mock_verify_token.assert_called_once_with('fake_token')

                assert str(g.get("user_id")) == "123e4567-e89b-12d3-a456-426614174000"

                assert response.status_code == 500
                assert response.json == {"message": "An internal error occurred while getting task."}
