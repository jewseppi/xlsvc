"""
Tests for main.py API routes (download, cleanup-files, admin, health, etc.).
"""
import pytest
import os
import jwt as jwt_lib
from datetime import datetime, timedelta


class TestHealthAndProfile:
    """Health and profile endpoints."""

    def test_health_check(self, client):
        """GET /api/health returns 200."""
        r = client.get("/api/health")
        assert r.status_code == 200
        data = r.get_json()
        assert data.get("status") == "ok"

    def test_profile_authenticated(self, client, auth_token):
        """GET /api/profile with valid token returns email."""
        if auth_token is None:
            pytest.skip("Auth token not available")
        r = client.get("/api/profile", headers={"Authorization": f"Bearer {auth_token}"})
        assert r.status_code == 200
        assert "email" in r.get_json()


class TestDownloadWithToken:
    """GET /api/download-with-token/<file_id> (no JWT, uses query token)."""

    def test_download_with_token_no_token(self, client):
        """No token returns 401."""
        r = client.get("/api/download-with-token/1")
        assert r.status_code == 401

    def test_download_with_token_invalid_token(self, client, test_app):
        """Invalid token returns 401."""
        token = "invalid"
        r = client.get(f"/api/download-with-token/1?token={token}")
        assert r.status_code == 401

    def test_download_with_token_valid_but_wrong_file(self, client, test_app, test_user, db_connection):
        """Valid token for different file_id returns 403."""
        import main
        token = main.generate_download_token(file_id=999, user_id=test_user["id"], expires_in_minutes=30)
        r = client.get(f"/api/download-with-token/1?token={token}")
        assert r.status_code == 403


class TestDownloadAuthenticated:
    """GET /api/download/<file_id> (JWT required)."""

    def test_download_file_not_found(self, client, auth_token):
        """Non-existent file_id returns 404."""
        if auth_token is None:
            pytest.skip("Auth token not available")
        r = client.get("/api/download/99999", headers={"Authorization": f"Bearer {auth_token}"})
        assert r.status_code == 404


class TestCleanupFilesRoute:
    """POST /api/cleanup-files (remove DB entries for missing files)."""

    def test_cleanup_files_authenticated(self, client, auth_token):
        """Authenticated cleanup-files returns 200 and removed_count."""
        if auth_token is None:
            pytest.skip("Auth token not available")
        r = client.post("/api/cleanup-files", headers={"Authorization": f"Bearer {auth_token}"})
        assert r.status_code == 200
        data = r.get_json()
        assert "removed_count" in data


class TestValidateInvitationRoute:
    """POST /api/validate-invitation."""

    def test_validate_invitation_missing_body(self, client):
        """Missing token returns 400."""
        r = client.post("/api/validate-invitation", json={})
        assert r.status_code in [400, 422]

    def test_validate_invitation_invalid_token(self, client):
        """Invalid token returns error."""
        r = client.post("/api/validate-invitation", json={"token": "invalid"})
        assert r.status_code in [400, 401, 422]


class TestGetMacroAndGeneratedFiles:
    """GET /api/get-macro/<file_id>, GET /api/files/<file_id>/generated."""

    def test_get_macro_for_file_not_found(self, client, auth_token):
        """Non-existent file_id returns 404."""
        if auth_token is None:
            pytest.skip("Auth token not available")
        r = client.get("/api/get-macro/99999", headers={"Authorization": f"Bearer {auth_token}"})
        assert r.status_code == 404

    def test_get_generated_files_not_found(self, client, auth_token):
        """Non-existent file_id returns 404."""
        if auth_token is None:
            pytest.skip("Auth token not available")
        r = client.get("/api/files/99999/generated", headers={"Authorization": f"Bearer {auth_token}"})
        assert r.status_code == 404


class TestAdminRoutes:
    """Admin endpoints (require admin user)."""

    def test_create_invitation_unauthenticated(self, client):
        """No token returns 401."""
        r = client.post("/api/admin/create-invitation", json={"email": "new@example.com"})
        assert r.status_code == 401

    def test_create_invitation_non_admin(self, client, auth_token):
        """Non-admin user returns 403."""
        if auth_token is None:
            pytest.skip("Auth token not available")
        r = client.post(
            "/api/admin/create-invitation",
            json={"email": "new@example.com"},
            headers={"Authorization": f"Bearer {auth_token}"},
        )
        assert r.status_code in [403, 404]

    def test_list_invitations_unauthenticated(self, client):
        """No token returns 401."""
        r = client.get("/api/admin/invitations")
        assert r.status_code == 401

    def test_list_users_unauthenticated(self, client):
        """No token returns 401."""
        r = client.get("/api/admin/users")
        assert r.status_code == 401

    def test_admin_create_invitation_as_admin(self, client, test_admin_user, test_app):
        """Admin can create invitation."""
        login = client.post(
            "/api/login",
            json={"email": test_admin_user["email"], "password": test_admin_user["password"]},
        )
        if login.status_code != 200:
            pytest.skip("Admin login failed")
        token = login.get_json().get("access_token")
        r = client.post(
            "/api/admin/create-invitation",
            json={"email": "invited@example.com"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code in [200, 201]
        data = r.get_json()
        assert "token" in data or "invitation" in data or "email" in data

    def test_list_invitations_as_admin(self, client, test_admin_user):
        """Admin can list invitations."""
        login = client.post(
            "/api/login",
            json={"email": test_admin_user["email"], "password": test_admin_user["password"]},
        )
        if login.status_code != 200:
            pytest.skip("Admin login failed")
        token = login.get_json().get("access_token")
        r = client.get("/api/admin/invitations", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

    def test_list_users_as_admin(self, client, test_admin_user):
        """Admin can list users."""
        login = client.post(
            "/api/login",
            json={"email": test_admin_user["email"], "password": test_admin_user["password"]},
        )
        if login.status_code != 200:
            pytest.skip("Admin login failed")
        token = login.get_json().get("access_token")
        r = client.get("/api/admin/users", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200


class TestFileHistoryAndJobStatus:
    """GET /api/files/<id>/history, DELETE, GET /api/job-status/<job_id>."""

    def test_get_file_history_not_found(self, client, auth_token):
        """Non-existent file_id returns 404."""
        if auth_token is None:
            pytest.skip("Auth token not available")
        r = client.get("/api/files/99999/history", headers={"Authorization": f"Bearer {auth_token}"})
        assert r.status_code == 404

    def test_get_job_status_not_found(self, client, auth_token):
        """Non-existent job_id returns 404."""
        if auth_token is None:
            pytest.skip("Auth token not available")
        r = client.get("/api/job-status/nonexistent-job-id", headers={"Authorization": f"Bearer {auth_token}"})
        assert r.status_code == 404
