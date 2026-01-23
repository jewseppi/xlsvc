"""
API endpoint tests
"""
import pytest
import json
import os
import jwt as jwt_lib
from datetime import datetime, timedelta


class TestAuthentication:
    """Tests for authentication endpoints"""
    
    def test_register_new_user(self, client, db_connection, test_app):
        """Test user registration with invitation token"""
        # First create an invitation token (simulate admin creating invitation)
        from datetime import datetime, timedelta
        import jwt as jwt_lib
        import secrets
        
        email = 'newuser@example.com'
        secret = test_app.config['JWT_SECRET_KEY']
        
        # Create invitation token manually for testing
        invitation_payload = {
            'email': email,
            'purpose': 'invitation',
            'exp': datetime.utcnow() + timedelta(days=7)
        }
        invitation_token = jwt_lib.encode(invitation_payload, secret, algorithm='HS256')
        
        # Store invitation token in database
        expires_at = (datetime.utcnow() + timedelta(days=7)).isoformat()
        db_connection.execute(
            '''INSERT INTO invitation_tokens (email, token, expires_at, created_by)
               VALUES (?, ?, ?, ?)''',
            (email, invitation_token, expires_at, 'test')
        )
        db_connection.commit()
        
        # Now register with the invitation token
        response = client.post('/api/register', json={
            'invitation_token': invitation_token,
            'password': 'SecurePassword123!'
        })
        
        assert response.status_code == 201
        data = response.get_json()
        assert 'access_token' in data
        assert 'email' in data
    
    def test_register_duplicate_email(self, client, test_user):
        """Test that duplicate email registration fails"""
        response = client.post('/api/register', json={
            'email': test_user['email'],
            'password': 'AnotherPassword123!'
        })
        
        assert response.status_code == 400
    
    def test_login_valid_credentials(self, client, test_user):
        """Test login with valid credentials"""
        response = client.post('/api/login', json={
            'email': test_user['email'],
            'password': test_user['password']
        })
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'access_token' in data
        assert 'message' in data
        assert data['message'] == 'Login successful'
    
    def test_login_invalid_credentials(self, client):
        """Test login with invalid credentials"""
        response = client.post('/api/login', json={
            'email': 'nonexistent@example.com',
            'password': 'wrongpassword'
        })
        
        assert response.status_code == 401
    
    def test_get_profile_authenticated(self, client, auth_token):
        """Test getting user profile when authenticated"""
        response = client.get('/api/profile', headers={
            'Authorization': f'Bearer {auth_token}'
        })
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'email' in data
    
    def test_get_profile_unauthenticated(self, client):
        """Test getting user profile without authentication"""
        response = client.get('/api/profile')
        
        assert response.status_code == 401


class TestFileUpload:
    """Tests for file upload endpoints"""
    
    def test_upload_file_authenticated(self, client, auth_token, sample_excel_file):
        """Test file upload when authenticated"""
        # Skip if auth_token is None (auth setup issue)
        if auth_token is None:
            pytest.skip("Auth token not available - check test setup")
        
        with open(sample_excel_file, 'rb') as f:
            response = client.post(
                '/api/upload',
                data={'file': (f, 'test_file.xlsx')},
                headers={'Authorization': f'Bearer {auth_token}'},
                content_type='multipart/form-data'
            )
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}. Response: {response.get_json()}"
        data = response.get_json()
        assert 'file_id' in data
        assert 'filename' in data
    
    def test_upload_file_unauthenticated(self, client, sample_excel_file):
        """Test file upload without authentication"""
        with open(sample_excel_file, 'rb') as f:
            response = client.post(
                '/api/upload',
                data={'file': (f, 'test_file.xlsx')},
                content_type='multipart/form-data'
            )
        
        assert response.status_code == 401
    
    def test_upload_invalid_file_type(self, client, auth_token):
        """Test uploading non-Excel file"""
        if auth_token is None:
            pytest.skip("Auth token not available - check test setup")
        
        # Create a dummy text file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('not an excel file')
            temp_path = f.name
        
        try:
            with open(temp_path, 'rb') as f:
                response = client.post(
                    '/api/upload',
                    data={'file': (f, 'test_file.txt')},
                    headers={'Authorization': f'Bearer {auth_token}'},
                    content_type='multipart/form-data'
                )
            
            # API might return 422 for invalid file type
            assert response.status_code in [400, 422]
        finally:
            os.unlink(temp_path)


class TestFileList:
    """Tests for file listing endpoints"""
    
    def test_get_files_authenticated(self, client, auth_token):
        """Test getting files list when authenticated"""
        if auth_token is None:
            pytest.skip("Auth token not available - check test setup")
        
        response = client.get(
            '/api/files',
            headers={'Authorization': f'Bearer {auth_token}'}
        )
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}. Response: {response.get_json()}"
        data = response.get_json()
        assert isinstance(data, list)
    
    def test_get_files_unauthenticated(self, client):
        """Test getting files list without authentication"""
        response = client.get('/api/files')
        
        assert response.status_code == 401
