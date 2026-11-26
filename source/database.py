"""Database connection and parameterized query helpers for University Records System."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
SCHEMA_PATH = PROJECT_ROOT / "database" / "schema.sql"
SEED_PATH = PROJECT_ROOT / "database" / "seed-data.sql"

load_dotenv(BASE_DIR / ".env")


def get_database_path() -> Path:
    """Resolve the configured SQLite database path."""
    raw_path = os.getenv("DATABASE_PATH", "../database/university_records.db")
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = (BASE_DIR / candidate).resolve()
    return candidate


def get_connection(db_path: Path | str | None = None) -> sqlite3.Connection:
    """Open a SQLite connection with foreign keys and dict-like rows enabled."""
    target = Path(db_path) if db_path is not None else get_database_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Path | str | None = None, seed: bool = False) -> None:
    """Initialize database schema and optionally load seed data."""
    conn = get_connection(db_path)
    try:
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        if seed and SEED_PATH.exists():
            seed_sql = SEED_PATH.read_text(encoding="utf-8").strip()
            if seed_sql:
                conn.executescript(seed_sql)
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Users & Roles
# ---------------------------------------------------------------------------

def get_user_by_username(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, username, password_hash, full_name, is_active, created_at "
        "FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def get_user_by_id(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, username, password_hash, full_name, is_active, created_at "
        "FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def get_user_roles(conn: sqlite3.Connection, user_id: int) -> list[str]:
    rows = conn.execute(
        """
        SELECT r.name
        FROM roles r
        JOIN user_roles ur ON ur.role_id = r.id
        WHERE ur.user_id = ?
        ORDER BY r.id
        """,
        (user_id,),
    ).fetchall()
    return [row["name"] for row in rows]


def list_roles(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute("SELECT id, name, description FROM roles ORDER BY id").fetchall()


def list_users_with_roles(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    users = conn.execute(
        "SELECT id, username, full_name, is_active, created_at FROM users ORDER BY id"
    ).fetchall()
    result: list[dict[str, Any]] = []
    for u in users:
        roles = get_user_roles(conn, u["id"])
        result.append(
            {
                "id": u["id"],
                "username": u["username"],
                "full_name": u["full_name"],
                "is_active": bool(u["is_active"]),
                "created_at": u["created_at"],
                "roles": roles,
            }
        )
    return result


def create_user(
    conn: sqlite3.Connection,
    username: str,
    password_hash: str,
    full_name: str,
    is_active: int = 1,
) -> int:
    cur = conn.execute(
        "INSERT INTO users (username, password_hash, full_name, is_active) VALUES (?, ?, ?, ?)",
        (username, password_hash, full_name, is_active),
    )
    conn.commit()
    return int(cur.lastrowid)


def set_user_active(conn: sqlite3.Connection, user_id: int, is_active: int) -> None:
    conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (is_active, user_id))
    conn.commit()


def assign_role_to_user(conn: sqlite3.Connection, user_id: int, role_name: str) -> bool:
    role = conn.execute("SELECT id FROM roles WHERE name = ?", (role_name,)).fetchone()
    if role is None:
        return False
    conn.execute(
        "INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES (?, ?)",
        (user_id, role["id"]),
    )
    conn.commit()
    return True


def remove_role_from_user(conn: sqlite3.Connection, user_id: int, role_name: str) -> bool:
    role = conn.execute("SELECT id FROM roles WHERE name = ?", (role_name,)).fetchone()
    if role is None:
        return False
    conn.execute(
        "DELETE FROM user_roles WHERE user_id = ? AND role_id = ?",
        (user_id, role["id"]),
    )
    conn.commit()
    return True


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def create_session(conn: sqlite3.Connection, token: str, user_id: int, expires_at: str) -> None:
    conn.execute(
        "INSERT INTO sessions (token, user_id, expires_at, is_revoked) VALUES (?, ?, ?, 0)",
        (token, user_id, expires_at),
    )
    conn.commit()


def get_active_session(conn: sqlite3.Connection, token: str) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT s.token, s.user_id, s.expires_at, s.is_revoked,
               u.username, u.full_name, u.is_active
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token = ?
          AND s.is_revoked = 0
          AND u.is_active = 1
          AND s.expires_at > datetime('now')
        """,
        (token,),
    ).fetchone()


def revoke_session(conn: sqlite3.Connection, token: str) -> None:
    conn.execute("UPDATE sessions SET is_revoked = 1 WHERE token = ?", (token,))
    conn.commit()


# ---------------------------------------------------------------------------
# Students, Courses, Enrollments & Grades
# ---------------------------------------------------------------------------

def get_student_by_user_id(conn: sqlite3.Connection, user_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, user_id, student_code, full_name, email, phone, address, updated_at "
        "FROM students WHERE user_id = ?",
        (user_id,),
    ).fetchone()


def get_student_by_id(conn: sqlite3.Connection, student_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, user_id, student_code, full_name, email, phone, address, updated_at "
        "FROM students WHERE id = ?",
        (student_id,),
    ).fetchone()


def list_students(conn: sqlite3.Connection, search: str = "") -> list[sqlite3.Row]:
    if search:
        pattern = f"%{search}%"
        return conn.execute(
            """
            SELECT id, user_id, student_code, full_name, email, phone, address, updated_at
            FROM students
            WHERE student_code LIKE ? OR full_name LIKE ? OR email LIKE ?
            ORDER BY id
            """,
            (pattern, pattern, pattern),
        ).fetchall()
    return conn.execute(
        "SELECT id, user_id, student_code, full_name, email, phone, address, updated_at "
        "FROM students ORDER BY id"
    ).fetchall()


def create_student_record(
    conn: sqlite3.Connection,
    user_id: int,
    student_code: str,
    full_name: str,
    email: str,
    phone: str,
    address: str = "",
) -> int:
    cur = conn.execute(
        """
        INSERT INTO students (user_id, student_code, full_name, email, phone, address)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (user_id, student_code, full_name, email, phone, address),
    )
    conn.commit()
    return int(cur.lastrowid)


def update_student_contact(
    conn: sqlite3.Connection,
    student_id: int,
    email: str,
    phone: str,
    address: str,
) -> None:
    conn.execute(
        """
        UPDATE students
        SET email = ?, phone = ?, address = ?, updated_at = datetime('now')
        WHERE id = ?
        """,
        (email, phone, address, student_id),
    )
    conn.commit()


def update_student_record(
    conn: sqlite3.Connection,
    student_id: int,
    full_name: str,
    email: str,
    phone: str,
    address: str,
) -> None:
    conn.execute(
        """
        UPDATE students
        SET full_name = ?, email = ?, phone = ?, address = ?, updated_at = datetime('now')
        WHERE id = ?
        """,
        (full_name, email, phone, address, student_id),
    )
    conn.commit()


def list_courses(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT c.id, c.course_code, c.course_name, c.lecturer_id,
               u.full_name AS lecturer_name
        FROM courses c
        LEFT JOIN users u ON u.id = c.lecturer_id
        ORDER BY c.id
        """
    ).fetchall()


def list_courses_for_lecturer(conn: sqlite3.Connection, lecturer_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT id, course_code, course_name, lecturer_id
        FROM courses
        WHERE lecturer_id = ?
        ORDER BY id
        """,
        (lecturer_id,),
    ).fetchall()


def get_course_by_id(conn: sqlite3.Connection, course_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, course_code, course_name, lecturer_id FROM courses WHERE id = ?",
        (course_id,),
    ).fetchone()


def list_enrollments_for_student(conn: sqlite3.Connection, student_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT e.id AS enrollment_id, c.id AS course_id, c.course_code, c.course_name,
               u.full_name AS lecturer_name, e.enrolled_at,
               g.id AS grade_id, g.score, g.remarks, g.updated_at AS grade_updated_at
        FROM enrollments e
        JOIN courses c ON c.id = e.course_id
        LEFT JOIN users u ON u.id = c.lecturer_id
        LEFT JOIN grades g ON g.enrollment_id = e.id
        WHERE e.student_id = ?
        ORDER BY c.course_code
        """,
        (student_id,),
    ).fetchall()


def list_enrollments_for_course(conn: sqlite3.Connection, course_id: int) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT e.id AS enrollment_id, s.id AS student_id, s.student_code, s.full_name AS student_name,
               c.id AS course_id, c.course_code, c.course_name, c.lecturer_id,
               g.id AS grade_id, g.score, g.remarks, g.updated_at AS grade_updated_at
        FROM enrollments e
        JOIN students s ON s.id = e.student_id
        JOIN courses c ON c.id = e.course_id
        LEFT JOIN grades g ON g.enrollment_id = e.id
        WHERE e.course_id = ?
        ORDER BY s.student_code
        """,
        (course_id,),
    ).fetchall()


def get_enrollment_by_id(conn: sqlite3.Connection, enrollment_id: int) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT e.id AS enrollment_id, e.student_id, e.course_id,
               c.course_code, c.course_name, c.lecturer_id,
               s.student_code, s.user_id AS student_user_id
        FROM enrollments e
        JOIN courses c ON c.id = e.course_id
        JOIN students s ON s.id = e.student_id
        WHERE e.id = ?
        """,
        (enrollment_id,),
    ).fetchone()


def create_enrollment(conn: sqlite3.Connection, student_id: int, course_id: int) -> int:
    cur = conn.execute(
        "INSERT INTO enrollments (student_id, course_id) VALUES (?, ?)",
        (student_id, course_id),
    )
    conn.commit()
    return int(cur.lastrowid)


def list_all_grades(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT e.id AS enrollment_id, s.id AS student_id, s.student_code, s.full_name AS student_name,
               c.id AS course_id, c.course_code, c.course_name,
               g.id AS grade_id, g.score, g.remarks, g.updated_at AS grade_updated_at
        FROM enrollments e
        JOIN students s ON s.id = e.student_id
        JOIN courses c ON c.id = e.course_id
        LEFT JOIN grades g ON g.enrollment_id = e.id
        ORDER BY c.course_code, s.student_code
        """
    ).fetchall()


def upsert_grade(
    conn: sqlite3.Connection,
    enrollment_id: int,
    score: float,
    remarks: str,
    updated_by: int,
) -> None:
    conn.execute(
        """
        INSERT INTO grades (enrollment_id, score, remarks, updated_by, updated_at)
        VALUES (?, ?, ?, ?, datetime('now'))
        ON CONFLICT(enrollment_id) DO UPDATE SET
            score = excluded.score,
            remarks = excluded.remarks,
            updated_by = excluded.updated_by,
            updated_at = datetime('now')
        """,
        (enrollment_id, score, remarks, updated_by),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Append-only Audit Logs
# ---------------------------------------------------------------------------

def insert_audit_log(
    conn: sqlite3.Connection,
    acting_user: str,
    event_type: str,
    target_resource: str,
    result: str,
    details: str = "",
) -> None:
    conn.execute(
        """
        INSERT INTO audit_logs (acting_user, event_type, target_resource, result, details)
        VALUES (?, ?, ?, ?, ?)
        """,
        (acting_user, event_type, target_resource, result, details),
    )
    conn.commit()


def list_audit_logs(conn: sqlite3.Connection, limit: int = 200) -> list[sqlite3.Row]:
    return conn.execute(
        """
        SELECT id, timestamp, acting_user, event_type, target_resource, result, details
        FROM audit_logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
