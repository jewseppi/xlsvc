"""
Tests for chunked upload endpoints (/api/upload/init|chunk|complete|abort),
the shared finalizer, and the large/.xls processing guard.
"""
import os
import uuid
from io import BytesIO
from datetime import datetime, timedelta

import pytest

import main


@pytest.fixture
def token(client, test_user):
    """A real auth token (non-parametrized, unlike the shared auth_token fixture)."""
    r = client.post('/api/login', json={
        'email': test_user['email'],
        'password': test_user['password'],
    })
    assert r.status_code == 200
    return r.get_json()['access_token']


def _auth(token):
    return {'Authorization': f'Bearer {token}'}


def _init(client, token, filename='big.xlsx', total_size=1000, total_chunks=2):
    return client.post('/api/upload/init', json={
        'filename': filename,
        'total_size': total_size,
        'total_chunks': total_chunks,
    }, headers=_auth(token))


def _send_chunk(client, token, upload_id, index, data):
    return client.post(
        f'/api/upload/chunk/{upload_id}',
        data={'chunk': (BytesIO(data), 'blob'), 'index': str(index)},
        headers=_auth(token),
        content_type='multipart/form-data',
    )


class TestUploadInit:
    def test_init_happy(self, client, token, test_user):
        r = _init(client, token)
        assert r.status_code == 201
        body = r.get_json()
        assert 'upload_id' in body and body['chunk_size'] == main.CHUNK_SIZE
        # session row + temp dir created
        assert os.path.isdir(main._chunk_dir(body['upload_id']))

    def test_init_requires_auth(self, client):
        assert client.post('/api/upload/init', json={}).status_code == 401

    def test_init_rejects_bad_extension(self, client, token):
        r = _init(client, token, filename='notes.txt')
        assert r.status_code == 400
        assert 'allowed' in r.get_json()['error'].lower()

    def test_init_rejects_oversize(self, client, token):
        r = _init(client, token, total_size=main.MAX_UPLOAD_SIZE + 1)
        assert r.status_code == 400
        assert 'too large' in r.get_json()['error'].lower()

    def test_init_rejects_bad_total_chunks(self, client, token):
        r = _init(client, token, total_chunks=0)
        assert r.status_code == 400
        assert 'total_chunks' in r.get_json()['error']

    def test_init_user_not_found(self, client, token, test_user, db_connection):
        """Valid JWT but the user row is gone -> _require_user aborts 404."""
        db_connection.execute('DELETE FROM users WHERE id = ?', (test_user['id'],))
        db_connection.commit()
        r = _init(client, token)
        assert r.status_code == 404
        assert r.get_json()['error'] == 'User not found'


class TestUploadChunk:
    def test_chunk_happy(self, client, token):
        uid = _init(client, token).get_json()['upload_id']
        r = _send_chunk(client, token, uid, 0, b'hello-bytes')
        assert r.status_code == 200
        assert r.get_json()['received_bytes'] == len(b'hello-bytes')
        assert os.path.exists(os.path.join(main._chunk_dir(uid), '0.part'))

    def test_chunk_session_not_found(self, client, token):
        r = _send_chunk(client, token, 'does-not-exist', 0, b'x')
        assert r.status_code == 404

    def test_chunk_missing_file(self, client, token):
        uid = _init(client, token).get_json()['upload_id']
        r = client.post(f'/api/upload/chunk/{uid}', data={'index': '0'},
                        headers=_auth(token), content_type='multipart/form-data')
        assert r.status_code == 400
        assert 'No chunk' in r.get_json()['error']

    def test_chunk_invalid_index(self, client, token):
        uid = _init(client, token).get_json()['upload_id']
        r = client.post(
            f'/api/upload/chunk/{uid}',
            data={'chunk': (BytesIO(b'x'), 'blob'), 'index': 'abc'},
            headers=_auth(token), content_type='multipart/form-data',
        )
        assert r.status_code == 400
        assert 'index' in r.get_json()['error'].lower()

    def test_chunk_index_out_of_range(self, client, token):
        uid = _init(client, token, total_chunks=2).get_json()['upload_id']
        r = _send_chunk(client, token, uid, 5, b'x')
        assert r.status_code == 400
        assert 'range' in r.get_json()['error'].lower()

    def test_chunk_exceeds_max_size(self, client, token, monkeypatch):
        """A chunk pushing the running total past MAX aborts the session."""
        uid = _init(client, token).get_json()['upload_id']
        monkeypatch.setattr(main, 'MAX_UPLOAD_SIZE', 4)
        r = _send_chunk(client, token, uid, 0, b'too-many-bytes')
        assert r.status_code == 400
        assert 'maximum size' in r.get_json()['error'].lower()
        # session + temp dir removed
        assert not os.path.isdir(main._chunk_dir(uid))


class TestUploadComplete:
    def test_complete_happy(self, client, token, sample_excel_file, db_connection):
        with open(sample_excel_file, 'rb') as f:
            content = f.read()
        mid = len(content) // 2
        parts = [content[:mid], content[mid:]]
        uid = _init(client, token, filename='assembled.xlsx',
                    total_size=len(content), total_chunks=2).get_json()['upload_id']
        for i, part in enumerate(parts):
            assert _send_chunk(client, token, uid, i, part).status_code == 200
        r = client.post(f'/api/upload/complete/{uid}', headers=_auth(token))
        assert r.status_code == 201, r.get_json()
        body = r.get_json()
        assert body['duplicate'] is False and body['size'] == len(content)
        # registered in DB and assembled on disk; temp dir gone
        rec = db_connection.execute(
            'SELECT stored_filename, file_type FROM files WHERE id = ?', (body['file_id'],)
        ).fetchone()
        assert rec['file_type'] == 'original'
        assert os.path.exists(os.path.join(main.app.config['UPLOAD_FOLDER'], rec['stored_filename']))
        assert not os.path.isdir(main._chunk_dir(uid))

    def test_complete_missing_chunks(self, client, token):
        uid = _init(client, token, total_chunks=3).get_json()['upload_id']
        _send_chunk(client, token, uid, 0, b'PK\x03\x04partial')
        r = client.post(f'/api/upload/complete/{uid}', headers=_auth(token))
        assert r.status_code == 400
        assert 'Missing chunks' in r.get_json()['error']

    def test_complete_session_not_found(self, client, token):
        r = client.post('/api/upload/complete/nope', headers=_auth(token))
        assert r.status_code == 404

    def test_complete_invalid_excel(self, client, token):
        """Assembled bytes that are not a valid Excel file are rejected by the finalizer."""
        data = b'this is definitely not an excel file'
        uid = _init(client, token, filename='fake.xlsx',
                    total_size=len(data), total_chunks=1).get_json()['upload_id']
        _send_chunk(client, token, uid, 0, data)
        r = client.post(f'/api/upload/complete/{uid}', headers=_auth(token))
        assert r.status_code == 400
        assert 'Invalid Excel' in r.get_json()['error']

    def test_complete_duplicate(self, client, token, sample_excel_file):
        """Uploading the same content+filename twice yields a duplicate response."""
        with open(sample_excel_file, 'rb') as f:
            content = f.read()

        def do_upload():
            uid = _init(client, token, filename='dup.xlsx',
                        total_size=len(content), total_chunks=1).get_json()['upload_id']
            _send_chunk(client, token, uid, 0, content)
            return client.post(f'/api/upload/complete/{uid}', headers=_auth(token))

        first = do_upload()
        assert first.status_code == 201
        second = do_upload()
        assert second.status_code == 200
        assert second.get_json()['duplicate'] is True


class TestUploadAbort:
    def test_abort_existing(self, client, token):
        uid = _init(client, token).get_json()['upload_id']
        _send_chunk(client, token, uid, 0, b'data')
        assert os.path.isdir(main._chunk_dir(uid))
        r = client.post(f'/api/upload/abort/{uid}', headers=_auth(token))
        assert r.status_code == 200
        assert not os.path.isdir(main._chunk_dir(uid))

    def test_abort_nonexistent_is_ok(self, client, token):
        r = client.post('/api/upload/abort/never-existed', headers=_auth(token))
        assert r.status_code == 200


class TestProcessGuard:
    def test_large_file_routed_to_automated(self, client, token, sample_excel_file, monkeypatch):
        # upload a normal file, then shrink the inline threshold so it counts as "large"
        with open(sample_excel_file, 'rb') as f:
            up = client.post('/api/upload', data={'file': (f, 'big.xlsx')},
                             headers=_auth(token), content_type='multipart/form-data')
        file_id = up.get_json()['file_id']
        monkeypatch.setattr(main, 'INLINE_PROCESS_MAX_SIZE', 5)
        r = client.post(f'/api/process/{file_id}',
                        json={'filter_rules': [{'column': 'F', 'value': '0'}]},
                        headers=_auth(token))
        assert r.status_code == 413
        assert r.get_json()['use_automated'] is True

    def test_xls_routed_to_automated(self, client, token, test_user, db_connection, test_directories):
        # an .xls file record with a real file on disk -> guard fires on extension
        stored = f'{uuid.uuid4()}.xls'
        path = os.path.join(test_directories['uploads'], stored)
        with open(path, 'wb') as fh:
            fh.write(b'\xd0\xcf\x11\xe0legacy-xls')
        db_connection.execute(
            '''INSERT INTO files (user_id, original_filename, stored_filename, file_type)
               VALUES (?, ?, ?, ?)''',
            (test_user['id'], 'legacy.xls', stored, 'original'),
        )
        db_connection.commit()
        file_id = db_connection.execute('SELECT last_insert_rowid()').fetchone()[0]
        r = client.post(f'/api/process/{file_id}',
                        json={'filter_rules': [{'column': 'F', 'value': '0'}]},
                        headers=_auth(token))
        assert r.status_code == 413
        assert r.get_json()['use_automated'] is True


class TestCleanupStaleSessions:
    def test_cleanup_removes_stale_chunk_sessions(self, test_app, test_user, test_directories):
        """cleanup_old_files removes upload_sessions + temp dirs older than 6h."""
        from main import get_db
        upload_id = uuid.uuid4().hex
        chunk_dir = os.path.join(test_directories['uploads'], '.chunks', upload_id)
        os.makedirs(chunk_dir, exist_ok=True)
        with open(os.path.join(chunk_dir, '0.part'), 'wb') as f:
            f.write(b'stale')
        old = (datetime.utcnow() - timedelta(hours=7)).isoformat()
        conn = get_db()
        conn.execute(
            '''INSERT INTO upload_sessions
               (upload_id, user_id, filename, total_size, total_chunks, created_at)
               VALUES (?, ?, ?, ?, ?, ?)''',
            (upload_id, test_user['id'], 'old.xlsx', 100, 1, old),
        )
        conn.commit()
        conn.close()

        main.cleanup_old_files()

        assert not os.path.isdir(chunk_dir)
        conn = get_db()
        gone = conn.execute(
            'SELECT upload_id FROM upload_sessions WHERE upload_id = ?', (upload_id,)
        ).fetchone()
        conn.close()
        assert gone is None
