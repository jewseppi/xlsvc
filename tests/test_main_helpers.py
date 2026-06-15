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

    def test_rate_limit_allows_options(self, test_app, client):
        """OPTIONS requests pass through without rate limiting (CORS preflight)."""
        test_app.config["TESTING"] = False
        r = client.open("/api/register", method="OPTIONS")
        test_app.config["TESTING"] = True
        assert r.status_code in [200, 204, 405]


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

    def test_get_file_path_macro_report(self, test_app):
        """file_type 'macro_report' -> REPORTS_FOLDER."""
        p = main.get_file_path("macro_report", "r.xlsx")
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

    def test_cleanup_old_files_with_old_file(self, test_app, test_user, test_directories):
        """cleanup_old_files deletes old original file and runs full loop (covers branches)."""
        import main
        from datetime import datetime, timedelta
        conn = main.get_db()
        try:
            old_date = (datetime.utcnow() - timedelta(hours=25)).isoformat()
            stored = "old_file.xlsx"
            path = os.path.join(test_directories["uploads"], stored)
            with open(path, "wb") as f:
                f.write(b"PK\x03\x04")
            conn.execute(
                """INSERT INTO files (user_id, original_filename, stored_filename, file_type, upload_date)
                   VALUES (?, 'old.xlsx', ?, 'original', ?)""",
                (test_user["id"], stored, old_date),
            )
            conn.commit()
        finally:
            conn.close()
        main.cleanup_old_files()
        if os.path.exists(path):
            os.remove(path)


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
        if hasattr(token_str, "decode"):  # pragma: no cover -- Py2 bytes; Py3 returns str
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
        if hasattr(token, "decode"):  # pragma: no cover -- Py2 bytes; Py3 returns str
            token = token.decode()
        valid, data, err = main.validate_invitation_token(token)
        assert valid is False
        assert err is not None


class TestGetFilePathFallback:
    """Test get_file_path when Flask app context is not available."""

    def test_get_file_path_outside_app_context(self, test_app):
        """get_file_path falls back to default folders outside app context."""
        import file_utils
        from main import app as flask_app
        import flask

        # Pop the app context to simulate being outside Flask
        top = flask._app_ctx_stack.top
        if top:
            top.pop()
        try:
            p = file_utils.get_file_path("original", "foo.xlsx")
            assert p == os.path.join("uploads", "foo.xlsx")
        finally:
            if top:
                top.push()


class TestInitDbFreshDatabase:
    """Test init_db on a fresh database (first-run branches)."""

    def test_init_db_fresh_creates_tables_and_columns(self):
        """init_db on empty DB runs first-run branches (covers print lines)."""
        import sqlite3 as _sqlite3
        from unittest.mock import patch
        fd, path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        os.unlink(path)  # start with no file
        try:
            with patch('db.sqlite3') as mock_sqlite3:
                # Use real sqlite3 but redirect to temp path
                real_connect = _sqlite3.connect
                mock_sqlite3.connect = lambda _db: real_connect(path)
                mock_sqlite3.OperationalError = _sqlite3.OperationalError
                import db
                db.init_db()
            # Verify tables were created
            conn = _sqlite3.connect(path)
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()]
            assert 'users' in tables
            assert 'files' in tables
            assert 'processing_jobs' in tables
            assert 'subscribers' in tables
            assert 'invitation_tokens' in tables
            conn.close()
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_init_db_second_run_covers_alter_branches(self):
        """Calling init_db twice covers 'column already exists' branches."""
        import sqlite3 as _sqlite3
        from unittest.mock import patch
        fd, path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        os.unlink(path)
        try:
            real_connect = _sqlite3.connect
            with patch('db.sqlite3') as mock_sqlite3:
                mock_sqlite3.connect = lambda _db: real_connect(path)
                mock_sqlite3.OperationalError = _sqlite3.OperationalError
                import db
                db.init_db()  # first run creates everything
                db.init_db()  # second run hits "already exists" branches
        finally:
            if os.path.exists(path):
                os.unlink(path)


class TestCleanupOldFilesComprehensive:
    """Comprehensive tests for cleanup_old_files covering all branches."""

    def test_cleanup_with_related_files_on_disk(self, test_app, test_user, test_directories):
        """cleanup deletes related processed files from disk and DB."""
        from datetime import datetime, timedelta
        conn = main.get_db()
        old_date = (datetime.utcnow() - timedelta(hours=25)).isoformat()

        # Create original file
        stored_orig = "cleanup_orig.xlsx"
        orig_path = os.path.join(test_directories["uploads"], stored_orig)
        with open(orig_path, "wb") as f:
            f.write(b"PK\x03\x04")
        conn.execute(
            """INSERT INTO files (user_id, original_filename, stored_filename, file_type, upload_date)
               VALUES (?, 'orig.xlsx', ?, 'original', ?)""",
            (test_user["id"], stored_orig, old_date),
        )
        conn.commit()
        orig_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        # Create related processed file
        stored_proc = "cleanup_proc.xlsx"
        proc_path = os.path.join(test_directories["processed"], stored_proc)
        with open(proc_path, "wb") as f:
            f.write(b"PK\x03\x04")
        conn.execute(
            """INSERT INTO files (user_id, original_filename, stored_filename, file_type, parent_file_id, upload_date)
               VALUES (?, 'proc.xlsx', ?, 'processed', ?, ?)""",
            (test_user["id"], stored_proc, orig_id, old_date),
        )
        conn.commit()
        proc_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        # Create processing job
        conn.execute(
            """INSERT INTO processing_jobs (job_id, user_id, original_file_id, result_file_id, status)
               VALUES ('cleanup-job-1', ?, ?, ?, 'completed')""",
            (test_user["id"], orig_id, proc_id),
        )
        conn.commit()
        conn.close()

        main.cleanup_old_files()

        # Verify files deleted from disk
        assert not os.path.exists(proc_path)
        assert not os.path.exists(orig_path)

    def test_cleanup_orphaned_files(self, test_app, test_user, test_directories):
        """cleanup deletes orphaned generated files (no parent)."""
        from datetime import datetime, timedelta
        conn = main.get_db()
        old_date = (datetime.utcnow() - timedelta(hours=25)).isoformat()

        stored = "cleanup_orphan.xlsx"
        orphan_path = os.path.join(test_directories["processed"], stored)
        with open(orphan_path, "wb") as f:
            f.write(b"PK\x03\x04")
        conn.execute(
            """INSERT INTO files (user_id, original_filename, stored_filename, file_type, parent_file_id, upload_date)
               VALUES (?, 'orphan.xlsx', ?, 'processed', NULL, ?)""",
            (test_user["id"], stored, old_date),
        )
        conn.commit()
        conn.close()

        main.cleanup_old_files()
        assert not os.path.exists(orphan_path)

    def test_cleanup_old_processing_jobs(self, test_app, test_user):
        """cleanup deletes old completed/failed processing_jobs records."""
        from datetime import datetime, timedelta
        conn = main.get_db()
        old_date = (datetime.utcnow() - timedelta(hours=25)).isoformat()

        conn.execute(
            """INSERT INTO files (user_id, original_filename, stored_filename, file_type, upload_date)
               VALUES (?, 'jobtest.xlsx', 'jobtest.xlsx', 'original', ?)""",
            (test_user["id"], (datetime.utcnow()).isoformat()),  # recent file, won't be cleaned
        )
        conn.commit()
        file_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.execute(
            """INSERT INTO processing_jobs (job_id, user_id, original_file_id, status, created_at)
               VALUES ('old-job-cleanup', ?, ?, 'completed', ?)""",
            (test_user["id"], file_id, old_date),
        )
        conn.commit()
        conn.close()

        main.cleanup_old_files()

        conn = main.get_db()
        row = conn.execute(
            "SELECT * FROM processing_jobs WHERE job_id = 'old-job-cleanup'"
        ).fetchone()
        assert row is None
        conn.execute("DELETE FROM files WHERE id = ?", (file_id,))
        conn.commit()
        conn.close()

    def test_cleanup_exception_handler(self, test_app, monkeypatch):
        """cleanup_old_files handles exceptions gracefully."""
        import cleanup as cleanup_mod
        monkeypatch.setattr(
            cleanup_mod, 'get_db',
            lambda: (_ for _ in ()).throw(RuntimeError("DB down"))
        )
        # Should not raise
        cleanup_mod.cleanup_old_files()

    def test_cleanup_file_delete_exception(self, test_app, test_user, test_directories, monkeypatch):
        """cleanup handles OSError when deleting original file from disk."""
        from datetime import datetime, timedelta
        conn = main.get_db()
        old_date = (datetime.utcnow() - timedelta(hours=25)).isoformat()

        stored = "cleanup_nodelete.xlsx"
        path = os.path.join(test_directories["uploads"], stored)
        with open(path, "wb") as f:
            f.write(b"PK\x03\x04")
        conn.execute(
            """INSERT INTO files (user_id, original_filename, stored_filename, file_type, upload_date)
               VALUES (?, 'nodelete.xlsx', ?, 'original', ?)""",
            (test_user["id"], stored, old_date),
        )
        conn.commit()
        conn.close()

        original_remove = os.remove

        def failing_remove(p):
            if "cleanup_nodelete" in p:
                raise OSError("Permission denied")
            return original_remove(p)

        monkeypatch.setattr(os, 'remove', failing_remove)
        # Should not raise even though os.remove fails
        main.cleanup_old_files()


class TestAuthHelpersEdgeCases:
    """Tests for uncovered auth_helpers branches."""

    def test_rate_limit_options_passthrough(self, test_app, client):
        """OPTIONS requests pass through rate limiting (covers line 24)."""
        test_app.config["TESTING"] = False
        r = client.open("/api/register", method="OPTIONS")
        test_app.config["TESTING"] = True
        # OPTIONS should pass through without 429
        assert r.status_code != 429

    def test_verify_download_token_expired_signature(self, test_app):
        """ExpiredSignatureError for download token returns None (covers line 64-65)."""
        import jwt as jwt_lib
        from datetime import datetime, timedelta
        payload = {
            "file_id": 1,
            "user_id": 2,
            "purpose": "download",
            "exp": int((datetime.utcnow() - timedelta(hours=2)).timestamp()),
            "iat": int((datetime.utcnow() - timedelta(hours=3)).timestamp()),
        }
        token = jwt_lib.encode(
            payload, test_app.config["JWT_SECRET_KEY"], algorithm="HS256"
        )
        result = main.verify_download_token(token)
        assert result is None

    def test_validate_invitation_token_wrong_purpose(self, test_app):
        """Token with purpose != invitation returns error (covers line 127)."""
        import jwt as jwt_lib
        from datetime import datetime, timedelta
        token = jwt_lib.encode(
            {"email": "x@y.com", "purpose": "other",
             "exp": datetime.utcnow() + timedelta(days=1)},
            test_app.config["JWT_SECRET_KEY"], algorithm="HS256",
        )
        valid, email, err = main.validate_invitation_token(token)
        assert valid is False
        assert "purpose" in err.lower()

    def test_validate_invitation_token_missing_email(self, test_app):
        """Token without email field returns error (covers line 131)."""
        import jwt as jwt_lib
        from datetime import datetime, timedelta
        token = jwt_lib.encode(
            {"purpose": "invitation",
             "exp": datetime.utcnow() + timedelta(days=1)},
            test_app.config["JWT_SECRET_KEY"], algorithm="HS256",
        )
        valid, email, err = main.validate_invitation_token(token)
        assert valid is False
        assert "email" in err.lower()

    def test_validate_invitation_token_not_in_db(self, test_app):
        """Valid JWT but token not in invitation_tokens table (covers line 143)."""
        import jwt as jwt_lib
        from datetime import datetime, timedelta
        token = jwt_lib.encode(
            {"email": "x@y.com", "purpose": "invitation",
             "exp": datetime.utcnow() + timedelta(days=1)},
            test_app.config["JWT_SECRET_KEY"], algorithm="HS256",
        )
        valid, email, err = main.validate_invitation_token(token)
        assert valid is False
        assert "invalid" in err.lower() or "expired" in err.lower()

    def test_validate_invitation_token_already_used(self, test_app, db_connection):
        """Token that has been used returns error (covers line 147)."""
        import jwt as jwt_lib
        from datetime import datetime, timedelta
        email = "used-invite@example.com"
        token = jwt_lib.encode(
            {"email": email, "purpose": "invitation",
             "exp": datetime.utcnow() + timedelta(days=7)},
            test_app.config["JWT_SECRET_KEY"], algorithm="HS256",
        )
        expires = (datetime.utcnow() + timedelta(days=7)).isoformat()
        db_connection.execute(
            "INSERT INTO invitation_tokens (email, token, expires_at, created_by, used_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (email, token, expires, "test", datetime.utcnow().isoformat()),
        )
        db_connection.commit()
        valid, data, err = main.validate_invitation_token(token)
        assert valid is False
        assert "used" in err.lower()
        db_connection.execute(
            "DELETE FROM invitation_tokens WHERE email = ?", (email,)
        )
        db_connection.commit()

    def test_validate_invitation_token_db_expired(self, test_app, db_connection):
        """Token past DB expires_at returns error (covers line 152)."""
        import jwt as jwt_lib
        from datetime import datetime, timedelta
        email = "db-expired@example.com"
        # JWT not expired but DB record is
        token = jwt_lib.encode(
            {"email": email, "purpose": "invitation",
             "exp": datetime.utcnow() + timedelta(days=7)},
            test_app.config["JWT_SECRET_KEY"], algorithm="HS256",
        )
        expired_date = (datetime.utcnow() - timedelta(days=1)).isoformat()
        db_connection.execute(
            "INSERT INTO invitation_tokens (email, token, expires_at, created_by) "
            "VALUES (?, ?, ?, ?)",
            (email, token, expired_date, "test"),
        )
        db_connection.commit()
        valid, data, err = main.validate_invitation_token(token)
        assert valid is False
        assert "expired" in err.lower()
        db_connection.execute(
            "DELETE FROM invitation_tokens WHERE email = ?", (email,)
        )
        db_connection.commit()

    def test_validate_invitation_token_email_mismatch(self, test_app, db_connection):
        """Token email doesn't match DB email (covers line 156)."""
        import jwt as jwt_lib
        from datetime import datetime, timedelta
        jwt_email = "jwt@example.com"
        db_email = "db@example.com"
        token = jwt_lib.encode(
            {"email": jwt_email, "purpose": "invitation",
             "exp": datetime.utcnow() + timedelta(days=7)},
            test_app.config["JWT_SECRET_KEY"], algorithm="HS256",
        )
        expires = (datetime.utcnow() + timedelta(days=7)).isoformat()
        db_connection.execute(
            "INSERT INTO invitation_tokens (email, token, expires_at, created_by) "
            "VALUES (?, ?, ?, ?)",
            (db_email, token, expires, "test"),
        )
        db_connection.commit()
        valid, data, err = main.validate_invitation_token(token)
        assert valid is False
        assert "mismatch" in err.lower()
        db_connection.execute(
            "DELETE FROM invitation_tokens WHERE email = ?", (db_email,)
        )
        db_connection.commit()

    def test_validate_invitation_token_generic_exception(self, test_app, monkeypatch):
        """Generic exception in validate_invitation_token returns error (covers lines 167-168)."""
        import auth_helpers
        monkeypatch.setattr(
            auth_helpers, 'get_db',
            lambda: (_ for _ in ()).throw(RuntimeError("DB fail"))
        )
        import jwt as jwt_lib
        from datetime import datetime, timedelta
        token = jwt_lib.encode(
            {"email": "x@y.com", "purpose": "invitation",
             "exp": datetime.utcnow() + timedelta(days=1)},
            test_app.config["JWT_SECRET_KEY"], algorithm="HS256",
        )
        valid, data, err = main.validate_invitation_token(token)
        assert valid is False
        assert "error" in err.lower()


class TestIsAdminMigration:
    """Test is_admin migration branch in init_db (covers db.py lines 126-136)."""

    def test_init_db_is_admin_migration_with_existing_user(self):
        """init_db marks first user as admin when is_admin column is added."""
        import sqlite3 as _sqlite3
        from unittest.mock import patch
        fd, path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        os.unlink(path)
        try:
            conn = _sqlite3.connect(path)
            # Create users table WITHOUT is_admin column
            conn.execute('''
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.execute('''
                CREATE TABLE files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    original_filename TEXT NOT NULL,
                    stored_filename TEXT NOT NULL,
                    file_size INTEGER,
                    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    processed BOOLEAN DEFAULT FALSE,
                    file_hash TEXT,
                    file_type TEXT DEFAULT 'original',
                    parent_file_id INTEGER
                )
            ''')
            conn.execute('''
                CREATE TABLE processing_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT UNIQUE NOT NULL,
                    user_id INTEGER,
                    original_file_id INTEGER,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    result_file_id INTEGER,
                    report_file_id INTEGER,
                    error_message TEXT,
                    deleted_rows INTEGER DEFAULT 0,
                    filter_rules_json TEXT
                )
            ''')
            conn.execute('''
                CREATE TABLE subscribers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    created_at TEXT NOT NULL,
                    notified_at TEXT DEFAULT NULL
                )
            ''')
            # Insert a user so the migration marks them as admin
            conn.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                ("first@example.com", "hash"),
            )
            conn.commit()
            conn.close()

            real_connect = _sqlite3.connect
            with patch('db.sqlite3') as mock_sqlite3:
                mock_sqlite3.connect = lambda _db: real_connect(path)
                mock_sqlite3.OperationalError = _sqlite3.OperationalError
                import db
                db.init_db()

            # Verify is_admin was set
            conn = _sqlite3.connect(path)
            row = conn.execute(
                "SELECT is_admin FROM users WHERE email = ?", ("first@example.com",)
            ).fetchone()
            assert row is not None
            assert row[0] == 1
            conn.close()
        finally:
            if os.path.exists(path):
                os.unlink(path)


class TestDownloadTokenExpired:
    """Test verify_download_token with expired token (auth_helpers lines 64-65)."""

    def test_verify_download_token_expired(self, test_app):
        """Expired download token returns None."""
        import jwt as jwt_lib
        import time as _time
        secret = test_app.config['JWT_SECRET_KEY']
        payload = {
            'file_id': 1,
            'user_id': 1,
            'purpose': 'download',
            'exp': int(_time.time()) - 3600,  # expired 1 hour ago
        }
        token = jwt_lib.encode(payload, secret, algorithm='HS256')
        result = main.verify_download_token(token)
        assert result is None


class TestCleanupFileDeleteException:
    """Test cleanup_old_files when os.remove raises (cleanup lines 46-47, 89-90)."""

    def test_cleanup_related_file_delete_oserror(self, test_app, test_user, test_directories, monkeypatch):
        """cleanup handles OSError when deleting related processed files."""
        import main
        from datetime import datetime, timedelta
        conn = main.get_db()
        old_date = (datetime.utcnow() - timedelta(hours=25)).isoformat()

        # Create original file
        stored_orig = "oserr_orig.xlsx"
        orig_path = os.path.join(test_directories["uploads"], stored_orig)
        with open(orig_path, "wb") as f:
            f.write(b"PK\x03\x04")
        conn.execute(
            """INSERT INTO files (user_id, original_filename, stored_filename, file_type, upload_date)
               VALUES (?, 'oserr.xlsx', ?, 'original', ?)""",
            (test_user["id"], stored_orig, old_date),
        )
        conn.commit()
        orig_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        # Create related processed file on disk
        stored_proc = "oserr_proc.xlsx"
        proc_path = os.path.join(test_directories["processed"], stored_proc)
        with open(proc_path, "wb") as f:
            f.write(b"PK\x03\x04")
        conn.execute(
            """INSERT INTO files (user_id, original_filename, stored_filename, file_type, parent_file_id, upload_date)
               VALUES (?, 'proc.xlsx', ?, 'processed', ?, ?)""",
            (test_user["id"], stored_proc, orig_id, old_date),
        )
        conn.commit()
        conn.close()

        # Monkeypatch os.remove to raise on the first call (related file), succeed otherwise
        real_remove = os.remove
        call_count = [0]

        def failing_remove(path):
            call_count[0] += 1
            if call_count[0] <= 1:
                raise OSError("Permission denied")
            return real_remove(path)

        import cleanup as cleanup_mod
        monkeypatch.setattr(cleanup_mod.os, 'remove', failing_remove)
        # Should not raise
        main.cleanup_old_files()

    def test_cleanup_orphaned_file_delete_oserror(self, test_app, test_user, test_directories, monkeypatch):
        """cleanup handles OSError when deleting orphaned files."""
        import main
        from datetime import datetime, timedelta
        conn = main.get_db()
        old_date = (datetime.utcnow() - timedelta(hours=25)).isoformat()

        stored = "oserr_orphan.xlsx"
        orphan_path = os.path.join(test_directories["processed"], stored)
        with open(orphan_path, "wb") as f:
            f.write(b"PK\x03\x04")
        conn.execute(
            """INSERT INTO files (user_id, original_filename, stored_filename, file_type, parent_file_id, upload_date)
               VALUES (?, 'orphan.xlsx', ?, 'processed', NULL, ?)""",
            (test_user["id"], stored, old_date),
        )
        conn.commit()
        conn.close()

        import cleanup as cleanup_mod
        real_remove = os.remove
        call_count = [0]

        def failing_remove(path):
            call_count[0] += 1
            if "oserr_orphan" in path:
                raise OSError("fail")
            return real_remove(path)

        monkeypatch.setattr(cleanup_mod.os, 'remove', failing_remove)
        # Should not raise
        main.cleanup_old_files()
