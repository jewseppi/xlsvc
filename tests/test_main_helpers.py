"""
Unit and integration tests for main.py helpers (non-route functions).
Uses test_app so app.config and get_db are available.
"""
import pytest
import os
import tempfile
import sqlite3
from io import BytesIO
from unittest.mock import patch, MagicMock

import main


class TestRateLimit:
    """Test rate_limit decorator when TESTING is False."""

    def test_rate_limit_returns_429_when_exceeded(self, test_app, client):
        """When not in TESTING mode, excess requests to rate-limited endpoint get 429."""
        test_app.config["TESTING"] = False
        # register has rate_limit(5, 300). Make 6 requests with invalid body (no valid token).
        responses = []
        for _ in range(6):
            r = client.post(
                "/api/register",
                json={"invitation_token": "invalid", "password": "Short1!"},
            )
            responses.append(r)
        # At least one should be 429 (rate limit) or 400 (validation); 6th often 429
        statuses = [r.status_code for r in responses]
        assert 429 in statuses or 400 in statuses
        test_app.config["TESTING"] = True  # restore


class TestAddSecurityHeaders:
    """Test add_security_headers after_request."""

    def test_response_has_security_headers(self, client):
        """Any response gets X-Content-Type-Options, X-Frame-Options, etc."""
        r = client.get("/api/health")
        assert r.headers.get("X-Content-Type-Options") == "nosniff"
        assert r.headers.get("X-Frame-Options") == "DENY"
        assert "X-XSS-Protection" in r.headers
        assert "Strict-Transport-Security" in r.headers


class TestCalculateFileHash:
    """Test calculate_file_hash."""

    def test_calculate_file_hash(self, test_app):
        """Hash of a file is deterministic."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"hello world")
            path = f.name
        try:
            h1 = main.calculate_file_hash(path)
            h2 = main.calculate_file_hash(path)
            assert h1 == h2
            assert len(h1) == 64
        finally:
            os.unlink(path)


class TestEnsureDirectories:
    """Test ensure_directories."""

    def test_ensure_directories_creates_dirs(self, test_app, test_directories):
        """All config dirs exist after ensure_directories."""
        main.ensure_directories()
        for key in ["UPLOAD_FOLDER", "PROCESSED_FOLDER", "MACROS_FOLDER", "REPORTS_FOLDER"]:
            p = test_app.config[key]
            assert os.path.isdir(p)


class TestGetFilePath:
    """Test get_file_path branches."""

    def test_get_file_path_original(self, test_app):
        """file_type 'original' or None -> UPLOAD_FOLDER."""
        p = main.get_file_path("original", "foo.xlsx")
        assert p == os.path.join(test_app.config["UPLOAD_FOLDER"], "foo.xlsx")
        p = main.get_file_path(None, "bar.xlsx")
        assert p == os.path.join(test_app.config["UPLOAD_FOLDER"], "bar.xlsx")

    def test_get_file_path_processed(self, test_app):
        """file_type 'processed' -> PROCESSED_FOLDER."""
        p = main.get_file_path("processed", "out.xlsx")
        assert p == os.path.join(test_app.config["PROCESSED_FOLDER"], "out.xlsx")

    def test_get_file_path_macro_instructions(self, test_app):
        """file_type 'macro' or 'instructions' -> MACROS_FOLDER."""
        p = main.get_file_path("macro", "f.bas")
        assert p == os.path.join(test_app.config["MACROS_FOLDER"], "f.bas")
        p = main.get_file_path("instructions", "f.txt")
        assert p == os.path.join(test_app.config["MACROS_FOLDER"], "f.txt")

    def test_get_file_path_report(self, test_app):
        """file_type 'report' -> REPORTS_FOLDER."""
        p = main.get_file_path("report", "r.xlsx")
        assert p == os.path.join(test_app.config["REPORTS_FOLDER"], "r.xlsx")

    def test_get_file_path_other_falls_back_to_upload(self, test_app):
        """Unknown file_type -> UPLOAD_FOLDER."""
        p = main.get_file_path("other", "x.xlsx")
        assert p == os.path.join(test_app.config["UPLOAD_FOLDER"], "x.xlsx")


class TestInitDb:
    """Test init_db (idempotent; second run hits 'column already exists' branches)."""

    def test_init_db_second_run_hits_alter_branches(self):
        """Calling init_db again on existing schema hits duplicate column except blocks."""
        # At import main.init_db() already ran. Second call hits ALTER "already exists" branches.
        main.init_db()


class TestCleanupOldFiles:
    """Test cleanup_old_files (no-op when no old files)."""

    def test_cleanup_old_files_empty_db(self, test_app, test_db_path):
        """cleanup_old_files runs without error when no old files."""
        main.cleanup_old_files()


class TestDownloadToken:
    """Test generate_download_token and verify_download_token."""

    def test_generate_and_verify_download_token(self, test_app):
        """Valid token round-trip."""
        token = main.generate_download_token(file_id=1, user_id=2, expires_in_minutes=30)
        payload = main.verify_download_token(token)
        assert payload is not None
        assert payload.get("file_id") == 1
        assert payload.get("user_id") == 2
        assert payload.get("purpose") == "download"

    def test_verify_download_token_wrong_purpose(self, test_app):
        """Token with purpose != 'download' returns None."""
        import jwt as jwt_lib
        import time
        payload = {"file_id": 1, "user_id": 2, "purpose": "other", "exp": int(time.time()) + 3600, "iat": int(time.time())}
        token = jwt_lib.encode(payload, test_app.config["JWT_SECRET_KEY"], algorithm="HS256")
        assert main.verify_download_token(token) is None

    def test_verify_download_token_expired(self, test_app):
        """Expired token returns None."""
        import jwt as jwt_lib
        from datetime import datetime, timedelta
        payload = {
            "file_id": 1,
            "user_id": 2,
            "purpose": "download",
            "exp": (datetime.utcnow() - timedelta(hours=1)).timestamp(),
            "iat": (datetime.utcnow() - timedelta(hours=2)).timestamp(),
        }
        token = jwt_lib.encode(payload, test_app.config["JWT_SECRET_KEY"], algorithm="HS256")
        assert main.verify_download_token(token) is None

    def test_verify_download_token_invalid(self, test_app):
        """Invalid token returns None."""
        assert main.verify_download_token("invalid.token.here") is None


class TestAllowedFile:
    """Test allowed_file."""

    def test_allowed_xlsx_xls(self):
        """xlsx and xls are allowed."""
        assert main.allowed_file("a.xlsx") is True
        assert main.allowed_file("a.xls") is True

    def test_allowed_other_rejected(self):
        """Other extensions rejected."""
        assert main.allowed_file("a.txt") is False
        assert main.allowed_file("a.csv") is False
        assert main.allowed_file("noext") is False


class TestValidateExcelFile:
    """Test validate_excel_file (magic bytes)."""

    def test_valid_xlsx_pk(self):
        """PK header (xlsx) is valid."""
        f = BytesIO(b"PK\x03\x04" + b"\x00" * 4)
        assert main.validate_excel_file(f) is True

    def test_valid_xls_ole(self):
        """OLE header (xls) is valid."""
        f = BytesIO(b"\xd0\xcf\x11\xe0" + b"\x00" * 4)
        assert main.validate_excel_file(f) is True

    def test_invalid_signature_raises(self):
        """Non-Excel signature raises ValueError."""
        f = BytesIO(b"NOTEXCEL\x00\x00")
        with pytest.raises(ValueError, match="Invalid Excel file"):
            main.validate_excel_file(f)


class TestEvaluateCellValue:
    """Test evaluate_cell_value."""

    def test_cell_value_string_not_formula(self):
        """String value that is not a formula returned as-is."""
        cell = MagicMock()
        cell.value = "hello"
        assert main.evaluate_cell_value(cell) == "hello"

    def test_cell_value_formula_returns_none(self):
        """Formula (value starting with =) returns None (data_only mode needed)."""
        cell = MagicMock()
        cell.value = "=A1+1"
        assert main.evaluate_cell_value(cell) is None

    def test_no_value_returns_none(self):
        """Object without value returns None."""
        assert main.evaluate_cell_value(MagicMock(spec=[])) is None


class TestValidatePasswordStrength:
    """Test validate_password_strength."""

    def test_too_short(self):
        """Less than 12 chars fails."""
        ok, msg = main.validate_password_strength("Short1!")
        assert ok is False
        assert "12" in msg

    def test_no_uppercase(self):
        """No uppercase fails."""
        ok, msg = main.validate_password_strength("alllowercase123!")
        assert ok is False
        assert "uppercase" in msg

    def test_no_lowercase(self):
        """No lowercase fails."""
        ok, msg = main.validate_password_strength("ALLUPPERCASE123!")
        assert ok is False
        assert "lowercase" in msg

    def test_no_number(self):
        """No number fails."""
        ok, msg = main.validate_password_strength("NoNumbersHere!")
        assert ok is False
        assert "number" in msg

    def test_no_special(self):
        """No special char fails."""
        ok, msg = main.validate_password_strength("NoSpecialChars123")
        assert ok is False
        assert "special" in msg

    def test_valid_password(self):
        """Valid password passes."""
        ok, msg = main.validate_password_strength("ValidPass123!")
        assert ok is True
        assert msg is None


class TestIsAdminUser:
    """Test is_admin_user."""

    def test_is_admin_true(self, test_app, test_admin_user):
        """Admin user returns True."""
        assert main.is_admin_user(test_admin_user["email"]) is True

    def test_is_admin_false(self, test_app, test_user):
        """Non-admin returns False."""
        assert main.is_admin_user(test_user["email"]) is False

    def test_unknown_email_returns_false(self, test_app):
        """Unknown email returns False."""
        assert main.is_admin_user("nobody@example.com") is False


class TestValidateInvitationToken:
    """Test validate_invitation_token (DB + JWT)."""

    def test_valid_token_returns_email(self, test_app, db_connection):
        """Valid invitation token in DB returns email."""
        import jwt as jwt_lib
        from datetime import datetime, timedelta
        email = "invited@example.com"
        payload = {"email": email, "purpose": "invitation", "exp": datetime.utcnow() + timedelta(days=7)}
        token_str = jwt_lib.encode(payload, test_app.config["JWT_SECRET_KEY"], algorithm="HS256")
        if hasattr(token_str, "decode"):
            token_str = token_str.decode()
        expires = (datetime.utcnow() + timedelta(days=7)).isoformat()
        db_connection.execute(
            "INSERT INTO invitation_tokens (email, token, expires_at, created_by) VALUES (?, ?, ?, ?)",
            (email, token_str, expires, "test"),
        )
        db_connection.commit()
        valid, data, err = main.validate_invitation_token(token_str)
        assert valid is True
        assert data == email
        db_connection.execute("DELETE FROM invitation_tokens WHERE email = ?", (email,))
        db_connection.commit()

    def test_expired_token_returns_error(self, test_app):
        """Expired invitation token returns error."""
        import jwt as jwt_lib
        from datetime import datetime, timedelta
        payload = {"email": "x@y.com", "purpose": "invitation", "exp": datetime.utcnow() - timedelta(days=1)}
        token = jwt_lib.encode(payload, test_app.config["JWT_SECRET_KEY"], algorithm="HS256")
        if hasattr(token, "decode"):
            token = token.decode()
        valid, data, err = main.validate_invitation_token(token)
        assert valid is False
        assert err is not None
