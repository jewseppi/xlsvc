"""
Tests for filter profile CRUD endpoints.
"""
import pytest
import json
from unittest.mock import patch, MagicMock


class TestListFilterProfiles:
    """GET /api/filter-profiles"""

    def test_list_requires_auth(self, client):
        """Unauthenticated request returns 401."""
        r = client.get("/api/filter-profiles")
        assert r.status_code == 401

    def test_list_returns_system_templates(self, client, test_user, db_connection):
        """Authenticated user sees system templates."""
        # Seed a system template
        db_connection.execute(
            """INSERT INTO filter_profiles
               (user_id, name, description, filter_rules_json, columns_to_remove, is_system_template)
               VALUES (NULL, 'TestTemplate', 'desc', '[]', '[]', 1)"""
        )
        db_connection.commit()

        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.get("/api/filter-profiles", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        profiles = r.get_json()["profiles"]
        assert any(p["name"] == "TestTemplate" and p["is_system_template"] for p in profiles)

        # Cleanup
        db_connection.execute("DELETE FROM filter_profiles")
        db_connection.commit()

    def test_list_returns_own_profiles_only(self, client, test_user, db_connection):
        """User sees own profiles but not other users' profiles."""
        # Insert profile for user
        db_connection.execute(
            """INSERT INTO filter_profiles
               (user_id, name, filter_rules_json, is_system_template)
               VALUES (?, 'MyProfile', '[]', 0)""",
            (test_user["id"],)
        )
        # Insert profile for another user (id=99999)
        db_connection.execute(
            """INSERT INTO filter_profiles
               (user_id, name, filter_rules_json, is_system_template)
               VALUES (99999, 'OtherProfile', '[]', 0)"""
        )
        db_connection.commit()

        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.get("/api/filter-profiles", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        profiles = r.get_json()["profiles"]
        names = [p["name"] for p in profiles]
        assert "MyProfile" in names
        assert "OtherProfile" not in names

        # Cleanup
        db_connection.execute("DELETE FROM filter_profiles")
        db_connection.commit()


class TestCreateFilterProfile:
    """POST /api/filter-profiles"""

    def test_create_requires_auth(self, client):
        """Unauthenticated request returns 401."""
        r = client.post("/api/filter-profiles", json={"name": "Test"})
        assert r.status_code == 401

    def test_create_user_profile(self, client, test_user, db_connection):
        """User creates a personal profile."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.post("/api/filter-profiles", json={
            "name": "My Filter",
            "description": "Test filter",
            "filter_rules": [{"column": "A", "value": "0"}],
            "columns_to_remove": ["B", "c"]
        }, headers={"Authorization": f"Bearer {token}"})

        assert r.status_code == 201
        data = r.get_json()
        assert data["name"] == "My Filter"
        assert data["is_system_template"] is False
        assert data["filter_rules"] == [{"column": "A", "value": "0"}]
        # columns_to_remove should be uppercased and deduped
        assert data["columns_to_remove"] == ["B", "C"]

        # Cleanup
        db_connection.execute("DELETE FROM filter_profiles")
        db_connection.commit()

    def test_create_missing_name(self, client, test_user):
        """Missing name returns 400."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.post("/api/filter-profiles", json={
            "name": "",
            "filter_rules": []
        }, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 400
        assert "name" in r.get_json()["error"].lower()

    def test_create_no_body(self, client, test_user):
        """No request body returns 400."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.post("/api/filter-profiles",
                         data=b'',
                         headers={"Authorization": f"Bearer {token}",
                                  "Content-Type": "application/json"})
        assert r.status_code == 400

    def test_create_name_too_long(self, client, test_user):
        """Name exceeding max length returns 400."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.post("/api/filter-profiles", json={
            "name": "A" * 101,
            "filter_rules": []
        }, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 400

    def test_create_description_too_long(self, client, test_user):
        """Description exceeding max length returns 400."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.post("/api/filter-profiles", json={
            "name": "Valid",
            "description": "D" * 501,
            "filter_rules": []
        }, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 400

    def test_create_invalid_filter_rules(self, client, test_user):
        """Invalid filter_rules shape returns 400."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.post("/api/filter-profiles", json={
            "name": "Bad Rules",
            "filter_rules": "not-a-list"
        }, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 400

    def test_create_invalid_columns_to_remove(self, client, test_user):
        """Invalid columns_to_remove returns 400."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.post("/api/filter-profiles", json={
            "name": "Bad Cols",
            "filter_rules": [],
            "columns_to_remove": ["123"]
        }, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 400

    def test_create_system_template_requires_admin(self, client, test_user):
        """Non-admin cannot create system templates."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.post("/api/filter-profiles", json={
            "name": "System",
            "filter_rules": [],
            "is_system_template": True
        }, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

    def test_create_system_template_admin(self, client, test_admin_user, db_connection):
        """Admin can create system templates."""
        login = client.post("/api/login", json={
            "email": test_admin_user["email"], "password": test_admin_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.post("/api/filter-profiles", json={
            "name": "Admin Template",
            "filter_rules": [{"column": "F", "value": "0"}],
            "is_system_template": True
        }, headers={"Authorization": f"Bearer {token}"})

        assert r.status_code == 201
        assert r.get_json()["is_system_template"] is True

        # Cleanup
        db_connection.execute("DELETE FROM filter_profiles")
        db_connection.commit()

    def test_create_invalid_filter_rules_missing_keys(self, client, test_user):
        """filter_rules with dicts missing column/value returns 400."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.post("/api/filter-profiles", json={
            "name": "Bad",
            "filter_rules": [{"column": "A"}]
        }, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 400

    def test_create_invalid_filter_rules_non_dict_items(self, client, test_user):
        """filter_rules with non-dict items returns 400."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.post("/api/filter-profiles", json={
            "name": "Bad",
            "filter_rules": ["not-a-dict"]
        }, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 400


class TestUpdateFilterProfile:
    """PUT /api/filter-profiles/<id>"""

    def test_update_requires_auth(self, client):
        """Unauthenticated request returns 401."""
        r = client.put("/api/filter-profiles/1", json={"name": "X"})
        assert r.status_code == 401

    def test_update_own_profile(self, client, test_user, db_connection):
        """User updates their own profile."""
        db_connection.execute(
            """INSERT INTO filter_profiles
               (id, user_id, name, filter_rules_json, is_system_template)
               VALUES (1, ?, 'Old Name', '[]', 0)""",
            (test_user["id"],)
        )
        db_connection.commit()

        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.put("/api/filter-profiles/1", json={
            "name": "New Name",
            "description": "Updated desc",
            "filter_rules": [{"column": "A", "value": "1"}],
            "columns_to_remove": ["Z"]
        }, headers={"Authorization": f"Bearer {token}"})

        assert r.status_code == 200
        data = r.get_json()
        assert data["name"] == "New Name"
        assert data["description"] == "Updated desc"
        assert data["filter_rules"] == [{"column": "A", "value": "1"}]
        assert data["columns_to_remove"] == ["Z"]

        # Cleanup
        db_connection.execute("DELETE FROM filter_profiles")
        db_connection.commit()

    def test_update_profile_not_found(self, client, test_user):
        """Non-existent profile returns 404."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.put("/api/filter-profiles/99999", json={"name": "X"},
                        headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 404

    def test_update_other_users_profile_forbidden(self, client, test_user, db_connection):
        """Cannot update another user's profile."""
        db_connection.execute(
            """INSERT INTO filter_profiles
               (id, user_id, name, filter_rules_json, is_system_template)
               VALUES (2, 99999, 'Other', '[]', 0)"""
        )
        db_connection.commit()

        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.put("/api/filter-profiles/2", json={"name": "Hacked"},
                        headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

        # Cleanup
        db_connection.execute("DELETE FROM filter_profiles")
        db_connection.commit()

    def test_update_system_template_requires_admin(self, client, test_user, db_connection):
        """Non-admin cannot update system templates."""
        db_connection.execute(
            """INSERT INTO filter_profiles
               (id, user_id, name, filter_rules_json, is_system_template)
               VALUES (3, NULL, 'SystemTmpl', '[]', 1)"""
        )
        db_connection.commit()

        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.put("/api/filter-profiles/3", json={"name": "Hacked"},
                        headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

        # Cleanup
        db_connection.execute("DELETE FROM filter_profiles")
        db_connection.commit()

    def test_update_system_template_admin(self, client, test_admin_user, db_connection):
        """Admin can update system templates."""
        db_connection.execute(
            """INSERT INTO filter_profiles
               (id, user_id, name, filter_rules_json, is_system_template)
               VALUES (4, NULL, 'AdminTmpl', '[]', 1)"""
        )
        db_connection.commit()

        login = client.post("/api/login", json={
            "email": test_admin_user["email"], "password": test_admin_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.put("/api/filter-profiles/4", json={"name": "Renamed"},
                        headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.get_json()["name"] == "Renamed"

        # Cleanup
        db_connection.execute("DELETE FROM filter_profiles")
        db_connection.commit()

    def test_update_no_body(self, client, test_user, db_connection):
        """No request body returns 400."""
        db_connection.execute(
            """INSERT INTO filter_profiles
               (id, user_id, name, filter_rules_json, is_system_template)
               VALUES (5, ?, 'Test', '[]', 0)""",
            (test_user["id"],)
        )
        db_connection.commit()

        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.put("/api/filter-profiles/5",
                        data=b'',
                        headers={"Authorization": f"Bearer {token}",
                                 "Content-Type": "application/json"})
        assert r.status_code == 400

        # Cleanup
        db_connection.execute("DELETE FROM filter_profiles")
        db_connection.commit()

    def test_update_empty_name(self, client, test_user, db_connection):
        """Empty name returns 400."""
        db_connection.execute(
            """INSERT INTO filter_profiles
               (id, user_id, name, filter_rules_json, is_system_template)
               VALUES (6, ?, 'Test', '[]', 0)""",
            (test_user["id"],)
        )
        db_connection.commit()

        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.put("/api/filter-profiles/6", json={"name": ""},
                        headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 400

        # Cleanup
        db_connection.execute("DELETE FROM filter_profiles")
        db_connection.commit()

    def test_update_name_too_long(self, client, test_user, db_connection):
        """Name exceeding max length returns 400."""
        db_connection.execute(
            """INSERT INTO filter_profiles
               (id, user_id, name, filter_rules_json, is_system_template)
               VALUES (7, ?, 'Test', '[]', 0)""",
            (test_user["id"],)
        )
        db_connection.commit()

        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.put("/api/filter-profiles/7", json={"name": "A" * 101},
                        headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 400

        # Cleanup
        db_connection.execute("DELETE FROM filter_profiles")
        db_connection.commit()

    def test_update_description_too_long(self, client, test_user, db_connection):
        """Description exceeding max length returns 400."""
        db_connection.execute(
            """INSERT INTO filter_profiles
               (id, user_id, name, filter_rules_json, is_system_template)
               VALUES (8, ?, 'Test', '[]', 0)""",
            (test_user["id"],)
        )
        db_connection.commit()

        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.put("/api/filter-profiles/8", json={"description": "D" * 501},
                        headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 400

        # Cleanup
        db_connection.execute("DELETE FROM filter_profiles")
        db_connection.commit()

    def test_update_invalid_filter_rules(self, client, test_user, db_connection):
        """Invalid filter_rules returns 400."""
        db_connection.execute(
            """INSERT INTO filter_profiles
               (id, user_id, name, filter_rules_json, is_system_template)
               VALUES (9, ?, 'Test', '[]', 0)""",
            (test_user["id"],)
        )
        db_connection.commit()

        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.put("/api/filter-profiles/9", json={"filter_rules": "bad"},
                        headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 400

        # Cleanup
        db_connection.execute("DELETE FROM filter_profiles")
        db_connection.commit()

    def test_update_invalid_columns_to_remove(self, client, test_user, db_connection):
        """Invalid columns_to_remove returns 400."""
        db_connection.execute(
            """INSERT INTO filter_profiles
               (id, user_id, name, filter_rules_json, is_system_template)
               VALUES (10, ?, 'Test', '[]', 0)""",
            (test_user["id"],)
        )
        db_connection.commit()

        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.put("/api/filter-profiles/10", json={"columns_to_remove": ["123"]},
                        headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 400

        # Cleanup
        db_connection.execute("DELETE FROM filter_profiles")
        db_connection.commit()

    def test_update_partial_fields(self, client, test_user, db_connection):
        """Partial update only changes provided fields."""
        db_connection.execute(
            """INSERT INTO filter_profiles
               (id, user_id, name, description, filter_rules_json, columns_to_remove, is_system_template)
               VALUES (11, ?, 'OrigName', 'OrigDesc', '[{"column":"A","value":"0"}]', '["B"]', 0)""",
            (test_user["id"],)
        )
        db_connection.commit()

        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        # Only update description
        r = client.put("/api/filter-profiles/11", json={"description": "NewDesc"},
                        headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["name"] == "OrigName"  # unchanged
        assert data["description"] == "NewDesc"  # updated
        assert data["filter_rules"] == [{"column": "A", "value": "0"}]  # unchanged
        assert data["columns_to_remove"] == ["B"]  # unchanged

        # Cleanup
        db_connection.execute("DELETE FROM filter_profiles")
        db_connection.commit()


class TestDeleteFilterProfile:
    """DELETE /api/filter-profiles/<id>"""

    def test_delete_requires_auth(self, client):
        """Unauthenticated request returns 401."""
        r = client.delete("/api/filter-profiles/1")
        assert r.status_code == 401

    def test_delete_own_profile(self, client, test_user, db_connection):
        """User deletes their own profile."""
        db_connection.execute(
            """INSERT INTO filter_profiles
               (id, user_id, name, filter_rules_json, is_system_template)
               VALUES (20, ?, 'ToDelete', '[]', 0)""",
            (test_user["id"],)
        )
        db_connection.commit()

        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.delete("/api/filter-profiles/20",
                           headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200

        # Verify deleted
        row = db_connection.execute("SELECT id FROM filter_profiles WHERE id = 20").fetchone()
        assert row is None

    def test_delete_not_found(self, client, test_user):
        """Non-existent profile returns 404."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.delete("/api/filter-profiles/99999",
                           headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 404

    def test_delete_other_users_profile_forbidden(self, client, test_user, db_connection):
        """Cannot delete another user's profile."""
        db_connection.execute(
            """INSERT INTO filter_profiles
               (id, user_id, name, filter_rules_json, is_system_template)
               VALUES (21, 99999, 'OtherDelete', '[]', 0)"""
        )
        db_connection.commit()

        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.delete("/api/filter-profiles/21",
                           headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

        # Cleanup
        db_connection.execute("DELETE FROM filter_profiles")
        db_connection.commit()

    def test_delete_system_template_requires_admin(self, client, test_user, db_connection):
        """Non-admin cannot delete system templates."""
        db_connection.execute(
            """INSERT INTO filter_profiles
               (id, user_id, name, filter_rules_json, is_system_template)
               VALUES (22, NULL, 'SysTmplDel', '[]', 1)"""
        )
        db_connection.commit()

        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.delete("/api/filter-profiles/22",
                           headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403

        # Cleanup
        db_connection.execute("DELETE FROM filter_profiles")
        db_connection.commit()

    def test_delete_system_template_admin(self, client, test_admin_user, db_connection):
        """Admin can delete system templates."""
        db_connection.execute(
            """INSERT INTO filter_profiles
               (id, user_id, name, filter_rules_json, is_system_template)
               VALUES (23, NULL, 'AdminDel', '[]', 1)"""
        )
        db_connection.commit()

        login = client.post("/api/login", json={
            "email": test_admin_user["email"], "password": test_admin_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.delete("/api/filter-profiles/23",
                           headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200


class TestCloneFilterProfile:
    """POST /api/filter-profiles/<id>/clone"""

    def test_clone_requires_auth(self, client):
        """Unauthenticated request returns 401."""
        r = client.post("/api/filter-profiles/1/clone")
        assert r.status_code == 401

    def test_clone_system_template(self, client, test_user, db_connection):
        """User clones a system template into their own profiles."""
        db_connection.execute(
            """INSERT INTO filter_profiles
               (id, user_id, name, description, filter_rules_json, columns_to_remove, is_system_template)
               VALUES (30, NULL, 'Silver', 'Default', '[{"column":"F","value":"0"}]', '[]', 1)"""
        )
        db_connection.commit()

        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.post("/api/filter-profiles/30/clone",
                         json={"name": "My Silver"},
                         headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 201
        data = r.get_json()
        assert data["name"] == "My Silver"
        assert data["is_system_template"] is False
        assert data["filter_rules"] == [{"column": "F", "value": "0"}]

        # Cleanup
        db_connection.execute("DELETE FROM filter_profiles")
        db_connection.commit()

    def test_clone_default_name(self, client, test_user, db_connection):
        """Clone without name gets default '(Copy)' suffix."""
        db_connection.execute(
            """INSERT INTO filter_profiles
               (id, user_id, name, filter_rules_json, is_system_template)
               VALUES (31, NULL, 'Template', '[]', 1)"""
        )
        db_connection.commit()

        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.post("/api/filter-profiles/31/clone",
                         json={},
                         headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 201
        assert r.get_json()["name"] == "Template (Copy)"

        # Cleanup
        db_connection.execute("DELETE FROM filter_profiles")
        db_connection.commit()

    def test_clone_not_found(self, client, test_user):
        """Non-existent profile returns 404."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.post("/api/filter-profiles/99999/clone",
                         headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 404

    def test_clone_non_template_forbidden(self, client, test_user, db_connection):
        """Cannot clone a non-system-template profile."""
        db_connection.execute(
            """INSERT INTO filter_profiles
               (id, user_id, name, filter_rules_json, is_system_template)
               VALUES (32, ?, 'UserProfile', '[]', 0)""",
            (test_user["id"],)
        )
        db_connection.commit()

        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.post("/api/filter-profiles/32/clone",
                         headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 400

        # Cleanup
        db_connection.execute("DELETE FROM filter_profiles")
        db_connection.commit()

    def test_clone_name_too_long(self, client, test_user, db_connection):
        """Clone name exceeding max length returns 400."""
        db_connection.execute(
            """INSERT INTO filter_profiles
               (id, user_id, name, filter_rules_json, is_system_template)
               VALUES (33, NULL, 'Tmpl', '[]', 1)"""
        )
        db_connection.commit()

        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        r = client.post("/api/filter-profiles/33/clone",
                         json={"name": "A" * 101},
                         headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 400

        # Cleanup
        db_connection.execute("DELETE FROM filter_profiles")
        db_connection.commit()


class TestFilterProfileEdgeCases:
    """Edge cases for coverage: user-not-found, exception handlers, validator edges."""

    def test_list_user_not_found(self, client, test_user, db_connection):
        """User deleted after login -> list returns 404."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]
        # Delete user from DB
        db_connection.execute("DELETE FROM users WHERE email = ?", (test_user["email"],))
        db_connection.commit()

        r = client.get("/api/filter-profiles",
                        headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 404

    def test_create_user_not_found(self, client, test_user, db_connection):
        """User deleted after login -> create returns 404."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]
        db_connection.execute("DELETE FROM users WHERE email = ?", (test_user["email"],))
        db_connection.commit()

        r = client.post("/api/filter-profiles", json={
            "name": "Test", "filter_rules": []
        }, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 404

    def test_update_user_not_found(self, client, test_user, db_connection):
        """User deleted after login -> update returns 404."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]
        db_connection.execute("DELETE FROM users WHERE email = ?", (test_user["email"],))
        db_connection.commit()

        r = client.put("/api/filter-profiles/1", json={"name": "X"},
                        headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 404

    def test_delete_user_not_found(self, client, test_user, db_connection):
        """User deleted after login -> delete returns 404."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]
        db_connection.execute("DELETE FROM users WHERE email = ?", (test_user["email"],))
        db_connection.commit()

        r = client.delete("/api/filter-profiles/1",
                           headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 404

    def test_clone_user_not_found(self, client, test_user, db_connection):
        """User deleted after login -> clone returns 404."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]
        db_connection.execute("DELETE FROM users WHERE email = ?", (test_user["email"],))
        db_connection.commit()

        r = client.post("/api/filter-profiles/1/clone", json={},
                         headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 404

    def test_list_exception_handler(self, client, test_user):
        """Internal error in list returns 500."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        with patch("main.get_db", side_effect=Exception("db boom")):
            r = client.get("/api/filter-profiles",
                            headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 500

    def test_create_exception_handler(self, client, test_user):
        """Internal error in create returns 500."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        with patch("main.get_db", side_effect=Exception("db boom")):
            r = client.post("/api/filter-profiles", json={
                "name": "Test", "filter_rules": []
            }, headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 500

    def test_update_exception_handler(self, client, test_user):
        """Internal error in update returns 500."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        with patch("main.get_db", side_effect=Exception("db boom")):
            r = client.put("/api/filter-profiles/1", json={"name": "X"},
                            headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 500

    def test_delete_exception_handler(self, client, test_user):
        """Internal error in delete returns 500."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        with patch("main.get_db", side_effect=Exception("db boom")):
            r = client.delete("/api/filter-profiles/1",
                               headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 500

    def test_clone_exception_handler(self, client, test_user):
        """Internal error in clone returns 500."""
        login = client.post("/api/login", json={
            "email": test_user["email"], "password": test_user["password"]
        })
        token = login.get_json()["access_token"]

        with patch("main.get_db", side_effect=Exception("db boom")):
            r = client.post("/api/filter-profiles/1/clone", json={},
                             headers={"Authorization": f"Bearer {token}"})
            assert r.status_code == 500

    def test_validate_columns_to_remove_non_list(self):
        """_validate_columns_to_remove returns False for non-list input."""
        from main import _validate_columns_to_remove
        assert _validate_columns_to_remove("not-a-list") is False
        assert _validate_columns_to_remove(123) is False

    def test_validate_filter_rules_non_list(self):
        """_validate_filter_rules returns False for non-list input."""
        from main import _validate_filter_rules
        assert _validate_filter_rules("not-a-list") is False
        assert _validate_filter_rules(123) is False
