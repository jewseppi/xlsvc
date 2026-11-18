"""Tests for admin-generated password reset links."""
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs

import jwt as jwt_lib

NEW_PASSWORD = 'BrandNewPassw0rd!'


def _login(client, email, password):
    return client.post('/api/login', json={'email': email, 'password': password})


def _admin_headers(client, admin):
    r = _login(client, admin['email'], admin['password'])
    assert r.status_code == 200
    return {'Authorization': f"Bearer {r.get_json()['access_token']}"}


def _make_link(client, admin, user_id):
    return client.post(f'/api/admin/users/{user_id}/reset-link', headers=_admin_headers(client, admin))


def _token_from(resp):
    url = resp.get_json()['reset_url']
    qs = parse_qs(urlparse(url).query)
    assert qs['reset'] == ['1']
    return qs['token'][0]


class TestCreateResetLink:
    def test_requires_auth(self, client, test_user):
        assert client.post(f"/api/admin/users/{test_user['id']}/reset-link").status_code == 401

    def test_non_admin_forbidden(self, client, test_user):
        r = _login(client, test_user['email'], test_user['password'])
        headers = {'Authorization': f"Bearer {r.get_json()['access_token']}"}
        r = client.post(f"/api/admin/users/{test_user['id']}/reset-link", headers=headers)
        assert r.status_code == 403

    def test_unknown_user(self, client, test_admin_user):
        assert _make_link(client, test_admin_user, 99999).status_code == 404

    def test_admin_gets_link(self, client, test_admin_user, test_user):
        r = _make_link(client, test_admin_user, test_user['id'])
        assert r.status_code == 201
        data = r.get_json()
        assert data['email'] == test_user['email']
        assert '/app?reset=1&token=' in data['reset_url']

    def test_new_link_invalidates_old(self, client, test_admin_user, test_user):
        first = _token_from(_make_link(client, test_admin_user, test_user['id']))
        second = _token_from(_make_link(client, test_admin_user, test_user['id']))
        assert client.post('/api/validate-reset-token', json={'token': first}).status_code == 400
        assert client.post('/api/validate-reset-token', json={'token': second}).status_code == 200


class TestResetFlow:
    def test_validate_returns_email(self, client, test_admin_user, test_user):
        token = _token_from(_make_link(client, test_admin_user, test_user['id']))
        r = client.post('/api/validate-reset-token', json={'token': token})
        assert r.status_code == 200
        assert r.get_json() == {'valid': True, 'email': test_user['email']}

    def test_validate_missing_token(self, client):
        assert client.post('/api/validate-reset-token', json={}).status_code == 400

    def test_full_reset(self, client, test_admin_user, test_user):
        token = _token_from(_make_link(client, test_admin_user, test_user['id']))
        r = client.post('/api/reset-password', json={'token': token, 'password': NEW_PASSWORD})
        assert r.status_code == 200
        assert 'access_token' in r.get_json()

        assert _login(client, test_user['email'], test_user['password']).status_code == 401
        assert _login(client, test_user['email'], NEW_PASSWORD).status_code == 200

    def test_token_single_use(self, client, test_admin_user, test_user):
        token = _token_from(_make_link(client, test_admin_user, test_user['id']))
        assert client.post('/api/reset-password', json={'token': token, 'password': NEW_PASSWORD}).status_code == 200
        r = client.post('/api/reset-password', json={'token': token, 'password': 'AnotherPassw0rd!!'})
        assert r.status_code == 400
        assert 'already been used' in r.get_json()['error']

    def test_weak_password_rejected_and_token_kept(self, client, test_admin_user, test_user):
        token = _token_from(_make_link(client, test_admin_user, test_user['id']))
        r = client.post('/api/reset-password', json={'token': token, 'password': 'short'})
        assert r.status_code == 400
        # Token still usable after a failed attempt
        assert client.post('/api/reset-password', json={'token': token, 'password': NEW_PASSWORD}).status_code == 200

    def test_missing_fields(self, client):
        assert client.post('/api/reset-password', json={'token': 'x'}).status_code == 400
        assert client.post('/api/reset-password', json={'password': NEW_PASSWORD}).status_code == 400

    def test_garbage_token(self, client):
        r = client.post('/api/reset-password', json={'token': 'not-a-jwt', 'password': NEW_PASSWORD})
        assert r.status_code == 400

    def test_invitation_token_not_accepted(self, client, test_app, test_user):
        token = jwt_lib.encode(
            {'email': test_user['email'], 'purpose': 'invitation',
             'exp': datetime.utcnow() + timedelta(days=1)},
            test_app.config['JWT_SECRET_KEY'], algorithm='HS256')
        r = client.post('/api/reset-password', json={'token': token, 'password': NEW_PASSWORD})
        assert r.status_code == 400

    def test_expired_in_db(self, client, test_admin_user, test_user, db_connection):
        token = _token_from(_make_link(client, test_admin_user, test_user['id']))
        db_connection.execute(
            'UPDATE password_reset_tokens SET expires_at = ? WHERE token = ?',
            ((datetime.utcnow() - timedelta(hours=1)).isoformat(), token))
        db_connection.commit()
        assert client.post('/api/validate-reset-token', json={'token': token}).status_code == 400

    def test_deleted_user_token_invalid(self, client, test_admin_user, test_user, db_connection):
        token = _token_from(_make_link(client, test_admin_user, test_user['id']))
        db_connection.execute('DELETE FROM users WHERE id = ?', (test_user['id'],))
        db_connection.commit()
        assert client.post('/api/validate-reset-token', json={'token': token}).status_code == 400


class TestResetEdgeCases:
    def test_token_without_email(self, client, test_app):
        token = jwt_lib.encode(
            {'purpose': 'password_reset', 'exp': datetime.utcnow() + timedelta(hours=1)},
            test_app.config['JWT_SECRET_KEY'], algorithm='HS256')
        assert client.post('/api/validate-reset-token', json={'token': token}).status_code == 400

    def test_validator_db_error(self, client, test_app, monkeypatch):
        import auth_helpers
        token = jwt_lib.encode(
            {'email': 'a@b.com', 'purpose': 'password_reset', 'exp': datetime.utcnow() + timedelta(hours=1)},
            test_app.config['JWT_SECRET_KEY'], algorithm='HS256')
        monkeypatch.setattr(auth_helpers, 'get_db', lambda: (_ for _ in ()).throw(RuntimeError('boom')))
        r = client.post('/api/validate-reset-token', json={'token': token})
        assert r.status_code == 400
        assert 'boom' in r.get_json()['error']

    def test_create_link_exception(self, client, test_admin_user, monkeypatch):
        import main
        headers = _admin_headers(client, test_admin_user)
        monkeypatch.setattr(main, 'get_db', lambda: (_ for _ in ()).throw(RuntimeError('boom')))
        assert client.post('/api/admin/users/1/reset-link', headers=headers).status_code == 500

    def test_validate_endpoint_exception(self, client, monkeypatch):
        import main
        monkeypatch.setattr(main, 'validate_reset_token', lambda t: (_ for _ in ()).throw(RuntimeError('boom')))
        assert client.post('/api/validate-reset-token', json={'token': 'x'}).status_code == 500

    def test_reset_endpoint_exception(self, client, monkeypatch):
        import main
        monkeypatch.setattr(main, 'validate_reset_token', lambda t: (_ for _ in ()).throw(RuntimeError('boom')))
        assert client.post('/api/reset-password', json={'token': 'x', 'password': NEW_PASSWORD}).status_code == 500

    def test_localhost_frontend_url(self, client, test_admin_user, test_user):
        headers = _admin_headers(client, test_admin_user)
        r = client.post(f"/api/admin/users/{test_user['id']}/reset-link",
                        headers=headers, base_url='http://localhost:5000')
        assert r.get_json()['reset_url'].startswith('http://localhost:5173/app?reset=1')

    def test_delete_user_removes_reset_tokens(self, client, test_admin_user, test_user, db_connection):
        _make_link(client, test_admin_user, test_user['id'])
        r = client.delete(f"/api/admin/users/{test_user['id']}", headers=_admin_headers(client, test_admin_user))
        assert r.status_code == 200
        count = db_connection.execute(
            'SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = ?', (test_user['id'],)).fetchone()[0]
        assert count == 0
