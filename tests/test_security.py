"""Automated functional & security test suite (T01-T20 mandatory + T21-T26 original)."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIR = PROJECT_ROOT / "source"
if str(SOURCE_DIR) not in sys.path:
    sys.path.insert(0, str(SOURCE_DIR))

import database  # noqa: E402
from main import create_app  # noqa: E402


@pytest.fixture()
def test_env(tmp_path: Path):
    """Provide an isolated seeded SQLite DB and FastAPI TestClient per test."""
    db_file = tmp_path / "test_university.db"
    database.init_db(db_file, seed=True)
    app = create_app(db_path=db_file)
    client = TestClient(app)
    return client, db_file


def login_as(client: TestClient, username: str, password: str = "Password@123"):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )


# ---------------------------------------------------------------------------
# Authentication Tests (T01 - T05)
# ---------------------------------------------------------------------------

def test_t01_correct_username_and_password(test_env):
    """T01: Valid credentials succeed and issue HttpOnly session cookie."""
    client, _ = test_env
    resp = login_as(client, "student1", "Password@123")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard"
    assert "urs_session" in resp.cookies


def test_t02_incorrect_password_generic_message(test_env):
    """T02: Wrong password and unknown username return the same generic error."""
    client, _ = test_env
    resp_wrong_pw = login_as(client, "student1", "WrongPassword!")
    resp_unknown = login_as(client, "nonexistent_user", "WrongPassword!")

    assert resp_wrong_pw.status_code == 401
    assert resp_unknown.status_code == 401
    assert "Invalid username or password." in resp_wrong_pw.text
    assert "Invalid username or password." in resp_unknown.text


def test_t03_disabled_account_cannot_login(test_env):
    """T03: Disabled account login attempt is rejected."""
    client, _ = test_env
    resp = login_as(client, "disabled_user", "Password@123")
    assert resp.status_code == 401
    assert "urs_session" not in resp.cookies


def test_t04_reuse_session_after_logout_rejected(test_env):
    """T04: Session token becomes invalid immediately after logout."""
    client, _ = test_env
    login_resp = login_as(client, "student1")
    old_token = login_resp.cookies["urs_session"]

    logout_resp = client.post("/logout", follow_redirects=False)
    assert logout_resp.status_code == 303

    # Replay the old session token directly
    reuse_resp = client.get(
        "/students/1",
        cookies={"urs_session": old_token},
        headers={"Accept": "application/json"},
    )
    assert reuse_resp.status_code == 401


def test_t05_user_table_no_plaintext_passwords(test_env):
    """T05: Inspect users table to confirm all passwords are Argon2id-hashed."""
    _, db_file = test_env
    conn = database.get_connection(db_file)
    try:
        rows = conn.execute("SELECT username, password_hash FROM users").fetchall()
        assert len(rows) >= 8
        for row in rows:
            assert row["password_hash"].startswith("$argon2id$")
            assert "Password@123" not in row["password_hash"]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Authorization Tests (T06 - T17)
# ---------------------------------------------------------------------------

def test_t06_student_views_own_grade(test_env):
    """T06: Student can view their own profile, enrollments, and grades."""
    client, _ = test_env
    login_as(client, "student1")
    resp = client.get("/students/1", headers={"Accept": "application/json"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["student"]["student_code"] == "SV001"
    assert any(e["score"] == 8.5 for e in data["enrollments"])


def test_t07_student_idor_another_student_rejected(test_env):
    """T07: Student changing record ID to another student is rejected (IDOR)."""
    client, _ = test_env
    login_as(client, "student1")
    resp = client.get("/students/2", headers={"Accept": "application/json"})
    assert resp.status_code == 403


def test_t08_student_submits_grade_modification_rejected(test_env):
    """T08: Student submitting a grade modification request directly is rejected."""
    client, _ = test_env
    login_as(client, "student1")
    resp = client.post(
        "/grades",
        data={"enrollment_id": 1, "score": "10.0", "remarks": "Hacked"},
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 403


def test_t09_lecturer_views_assigned_course_roster(test_env):
    """T09: Lecturer can view roster for courses assigned to them."""
    client, _ = test_env
    login_as(client, "lecturer1")
    resp = client.get("/courses/1/roster", headers={"Accept": "application/json"})
    assert resp.status_code == 200
    assert len(resp.json()["roster"]) == 2


def test_t10_lecturer_modifies_grade_in_assigned_course(test_env):
    """T10: Lecturer modifies grade in assigned course -> allowed and logged."""
    client, db_file = test_env
    login_as(client, "lecturer1")
    resp = client.post(
        "/grades",
        data={"enrollment_id": 2, "score": "9.25", "remarks": "Great work"},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    conn = database.get_connection(db_file)
    try:
        grade = conn.execute("SELECT score FROM grades WHERE enrollment_id = 2").fetchone()
        assert grade is not None and grade["score"] == 9.25
        log = conn.execute(
            "SELECT * FROM audit_logs WHERE event_type = 'GRADE_MODIFIED' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert log is not None and log["acting_user"] == "lecturer1"
    finally:
        conn.close()


def test_t11_lecturer_modifies_grade_in_unassigned_course_rejected(test_env):
    """T11: Lecturer modifying grade in unassigned course -> rejected and unchanged."""
    client, db_file = test_env
    login_as(client, "lecturer1")  # lecturer1 is assigned to course 1, NOT course 2 (enrollment 3)
    resp = client.post(
        "/grades",
        data={"enrollment_id": 3, "score": "1.0", "remarks": "Unauthorized"},
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 403

    conn = database.get_connection(db_file)
    try:
        grade = conn.execute("SELECT score FROM grades WHERE enrollment_id = 3").fetchone()
        assert grade["score"] == 9.0
    finally:
        conn.close()


def test_t12_registrar_creates_enrollment(test_env):
    """T12: Registrar can enroll a student in a course."""
    client, db_file = test_env
    login_as(client, "registrar1")
    resp = client.post(
        "/registrar/enrollments",
        data={"student_id": 2, "course_id": 2},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    conn = database.get_connection(db_file)
    try:
        row = conn.execute(
            "SELECT * FROM enrollments WHERE student_id = 2 AND course_id = 2"
        ).fetchone()
        assert row is not None
    finally:
        conn.close()


def test_t13_registrar_modifies_grade_rejected(test_env):
    """T13: Registrar can view grades but cannot modify them."""
    client, _ = test_env
    login_as(client, "registrar1")
    view_resp = client.get("/grades", headers={"Accept": "application/json"})
    assert view_resp.status_code == 200

    mod_resp = client.post(
        "/grades",
        data={"enrollment_id": 1, "score": "10.0", "remarks": "Registrar edit"},
        headers={"Accept": "application/json"},
    )
    assert mod_resp.status_code == 403


def test_t14_auditor_reads_logs(test_env):
    """T14: Security Auditor can read audit logs and access-control configuration."""
    client, _ = test_env
    login_as(client, "auditor1")
    resp = client.get("/audit-logs", headers={"Accept": "application/json"})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["audit_logs"]) >= 1
    assert len(data["access_control_matrix"]) >= 5


def test_t15_auditor_modifies_student_record_rejected(test_env):
    """T15: Security Auditor has read-only access and cannot modify academic data."""
    client, _ = test_env
    login_as(client, "auditor1")
    resp = client.post(
        "/registrar/students/1/update",
        data={
            "full_name": "Tampered Name",
            "email": "hacked@uni.edu",
            "phone": "0909999999",
            "address": "Nowhere",
        },
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 403


def test_t16_admin_assigns_role(test_env):
    """T16: System Administrator can assign a role and it is logged."""
    client, db_file = test_env
    login_as(client, "admin1")
    resp = client.post(
        "/admin/users/2/roles",
        data={"role_name": "Security Auditor", "action": "assign"},
        follow_redirects=False,
    )
    assert resp.status_code == 303

    conn = database.get_connection(db_file)
    try:
        roles = database.get_user_roles(conn, 2)
        assert "Security Auditor" in roles
        log = conn.execute(
            "SELECT * FROM audit_logs WHERE event_type = 'ROLE_ASSIGNED' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert log is not None and log["acting_user"] == "admin1"
    finally:
        conn.close()


def test_t17_admin_views_grades_without_academic_role_rejected(test_env):
    """T17: System Administrator cannot view grades unless separately authorized."""
    client, _ = test_env
    login_as(client, "admin1")
    resp = client.get("/grades", headers={"Accept": "application/json"})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Injection & Input-Validation Tests (T18 - T19 + T21)
# ---------------------------------------------------------------------------

def test_t18_sql_injection_in_login_and_search(test_env):
    """T18: SQL injection payloads do not bypass login or cause database errors."""
    client, _ = test_env
    sqli_resp = login_as(client, "admin1' OR '1'='1", "' OR '1'='1")
    assert sqli_resp.status_code == 401
    assert "urs_session" not in sqli_resp.cookies

    login_as(client, "registrar1")
    search_resp = client.get("/dashboard?search=' OR 1=1 --")
    assert search_resp.status_code == 200
    assert "sqlite" not in search_resp.text.lower()


def test_t19_xss_script_input_stored_and_escaped(test_env):
    """T19: Script tags stored in fields are safely HTML-escaped when rendered."""
    client, _ = test_env
    login_as(client, "student1")
    payload = "<script>alert('xss')</script>"
    upd = client.post(
        "/students/1/contact",
        data={"email": "alice@university.edu", "phone": "0901000001", "address": payload},
        follow_redirects=False,
    )
    assert upd.status_code == 303

    dash = client.get("/dashboard")
    assert dash.status_code == 200
    assert payload not in dash.text
    assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;" in dash.text


def test_t21_invalid_grade_score_rejected(test_env):
    """T21 (Original): Out-of-range grade score is rejected by server validation."""
    client, _ = test_env
    login_as(client, "lecturer1")
    resp = client.post(
        "/grades",
        data={"enrollment_id": 1, "score": "15.5", "remarks": "Invalid"},
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Audit-Log & Additional Security Tests (T20 + T22 - T26)
# ---------------------------------------------------------------------------

def test_t20_rejected_privileged_action_appears_in_audit_log(test_env):
    """T20: Rejected privileged action is recorded in the audit log."""
    client, db_file = test_env
    login_as(client, "student1")
    client.post(
        "/admin/users/2/roles",
        data={"role_name": "System Administrator", "action": "assign"},
        headers={"Accept": "application/json"},
    )

    conn = database.get_connection(db_file)
    try:
        log = conn.execute(
            """
            SELECT * FROM audit_logs
            WHERE acting_user = 'student1'
              AND event_type = 'ACCESS_DENIED'
              AND result = 'REJECTED'
            ORDER BY id DESC LIMIT 1
            """
        ).fetchone()
        assert log is not None
        assert "admin/users/2/roles" in log["target_resource"]
    finally:
        conn.close()


def test_t22_audit_logs_never_contain_passwords_or_tokens(test_env):
    """T22 (Original): Sensitive secrets (passwords, session tokens) never appear in logs."""
    client, db_file = test_env
    secret_pw = "Password@123"
    login_resp = login_as(client, "student1", secret_pw)
    token = login_resp.cookies["urs_session"]
    login_as(client, "student1", "WrongSecretPass999")

    conn = database.get_connection(db_file)
    try:
        rows = conn.execute("SELECT acting_user, event_type, target_resource, result, details FROM audit_logs").fetchall()
        for row in rows:
            joined = " ".join(str(v) for v in dict(row).values())
            assert secret_pw not in joined
            assert "WrongSecretPass999" not in joined
            assert token not in joined
    finally:
        conn.close()


def test_t23_audit_logs_are_append_only_in_database(test_env):
    """T23 (Original): Database triggers prevent updating or deleting audit_logs."""
    _, db_file = test_env
    conn = database.get_connection(db_file)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("UPDATE audit_logs SET result = 'TAMPERED' WHERE id = 1")
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("DELETE FROM audit_logs WHERE id = 1")
    finally:
        conn.close()


def test_t24_multi_role_user_combines_authorized_permissions(test_env):
    """T24 (Original): User with multiple roles gains only explicitly authorized permissions."""
    client, _ = test_env
    # Admin assigns Registrar role to themselves, then can view grades, then removes it
    login_as(client, "admin1")
    assert client.get("/grades", headers={"Accept": "application/json"}).status_code == 403

    client.post("/admin/users/7/roles", data={"role_name": "Registrar", "action": "assign"})
    assert client.get("/grades", headers={"Accept": "application/json"}).status_code == 200
    # Still cannot modify grades because they do not have Lecturer role
    assert (
        client.post(
            "/grades",
            data={"enrollment_id": 1, "score": "5.0", "remarks": "Test"},
            headers={"Accept": "application/json"},
        ).status_code
        == 403
    )


def test_t25_unauthenticated_access_rejected(test_env):
    """T25 (Original): Unauthenticated requests to protected endpoints are rejected."""
    client, _ = test_env
    assert client.get("/grades", headers={"Accept": "application/json"}).status_code == 401
    assert client.get("/audit-logs", headers={"Accept": "application/json"}).status_code == 401


def test_t26_non_auditor_cannot_read_audit_logs(test_env):
    """T26 (Original): Non-auditor roles cannot access /audit-logs."""
    client, _ = test_env
    login_as(client, "registrar1")
    resp = client.get("/audit-logs", headers={"Accept": "application/json"})
    assert resp.status_code == 403
