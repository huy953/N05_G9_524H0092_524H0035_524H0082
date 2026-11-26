"""Authentication, session management, RBAC/record-level authorization, validation, and audit logging."""

from __future__ import annotations

import math
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

import database

ROLE_STUDENT = "Student"
ROLE_LECTURER = "Lecturer"
ROLE_REGISTRAR = "Registrar"
ROLE_AUDITOR = "Security Auditor"
ROLE_ADMIN = "System Administrator"

VALID_ROLES = {
    ROLE_STUDENT,
    ROLE_LECTURER,
    ROLE_REGISTRAR,
    ROLE_AUDITOR,
    ROLE_ADMIN,
}

SESSION_COOKIE_NAME = "urs_session"
GENERIC_LOGIN_ERROR = "Invalid username or password."

_password_hasher = PasswordHasher()

# Access-control configuration exposed (read-only) to Security Auditors
ACCESS_CONTROL_MATRIX: list[dict[str, str]] = [
    {
        "resource_operation": "View own profile, enrollment, and grades",
        "Student": "Allow (own records only)",
        "Lecturer": "N/A",
        "Registrar": "Allow",
        "Security Auditor": "Deny",
        "System Administrator": "Deny",
    },
    {
        "resource_operation": "Update own contact information",
        "Student": "Allow (own record only)",
        "Lecturer": "Deny",
        "Registrar": "Allow",
        "Security Auditor": "Deny",
        "System Administrator": "Deny",
    },
    {
        "resource_operation": "View another student's record / grades",
        "Student": "Deny",
        "Lecturer": "Allow (assigned courses only)",
        "Registrar": "Allow",
        "Security Auditor": "Deny",
        "System Administrator": "Deny",
    },
    {
        "resource_operation": "Create or update grades",
        "Student": "Deny",
        "Lecturer": "Allow (assigned courses only)",
        "Registrar": "Deny",
        "Security Auditor": "Deny",
        "System Administrator": "Deny",
    },
    {
        "resource_operation": "Create/update student records & manage enrollment",
        "Student": "Deny",
        "Lecturer": "Deny",
        "Registrar": "Allow",
        "Security Auditor": "Deny",
        "System Administrator": "Deny",
    },
    {
        "resource_operation": "Read audit logs & access-control configuration",
        "Student": "Deny",
        "Lecturer": "Deny",
        "Registrar": "Deny",
        "Security Auditor": "Allow (read-only)",
        "System Administrator": "Deny",
    },
    {
        "resource_operation": "Manage user accounts & assign/remove roles",
        "Student": "Deny",
        "Lecturer": "Deny",
        "Registrar": "Deny",
        "Security Auditor": "Deny",
        "System Administrator": "Allow",
    },
]


# ---------------------------------------------------------------------------
# Password Hashing & Verification
# ---------------------------------------------------------------------------

def hash_password(plain_password: str) -> str:
    """Hash a plaintext password using Argon2id."""
    return _password_hasher.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Verify a plaintext password against an Argon2id hash."""
    if not plain_password or not password_hash:
        return False
    try:
        return _password_hasher.verify(password_hash, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


# ---------------------------------------------------------------------------
# Session Helpers
# ---------------------------------------------------------------------------

def get_session_expire_minutes() -> int:
    try:
        return max(5, int(os.getenv("SESSION_EXPIRE_MINUTES", "60")))
    except ValueError:
        return 60


def generate_session_token() -> str:
    return secrets.token_urlsafe(32)


def session_expiry_iso(minutes: int | None = None) -> str:
    ttl = minutes if minutes is not None else get_session_expire_minutes()
    expires = datetime.now(timezone.utc) + timedelta(minutes=ttl)
    return expires.strftime("%Y-%m-%d %H:%M:%S")


def get_authenticated_user(conn: sqlite3.Connection, token: str | None) -> dict[str, Any] | None:
    """Resolve an active server-side session token into a user dict with roles."""
    if not token:
        return None
    sess = database.get_active_session(conn, token)
    if sess is None:
        return None
    roles = database.get_user_roles(conn, sess["user_id"])
    return {
        "id": sess["user_id"],
        "username": sess["username"],
        "full_name": sess["full_name"],
        "is_active": bool(sess["is_active"]),
        "roles": roles,
        "token": sess["token"],
    }


# ---------------------------------------------------------------------------
# Server-side Input Validation
# ---------------------------------------------------------------------------

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")
_STUDENT_CODE_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^[0-9+\-\s]{7,20}$")


def validate_username(value: str) -> str:
    cleaned = (value or "").strip()
    if not _USERNAME_RE.match(cleaned):
        raise ValueError("Username must be 3-32 characters (letters, digits, _, ., -).")
    return cleaned


def validate_password_strength(value: str) -> str:
    if not value or len(value) < 8 or len(value) > 128:
        raise ValueError("Password must be between 8 and 128 characters.")
    return value


def validate_student_code(value: str) -> str:
    cleaned = (value or "").strip()
    if not _STUDENT_CODE_RE.match(cleaned):
        raise ValueError("Student code must be 3-20 alphanumeric characters.")
    return cleaned


def validate_email(value: str) -> str:
    cleaned = (value or "").strip()
    if len(cleaned) > 120 or not _EMAIL_RE.match(cleaned):
        raise ValueError("Invalid email format.")
    return cleaned


def validate_phone(value: str) -> str:
    cleaned = (value or "").strip()
    if not _PHONE_RE.match(cleaned):
        raise ValueError("Invalid phone number format.")
    return cleaned


def validate_score(raw_value: str | float | int) -> float:
    try:
        score = float(raw_value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Score must be a valid number.") from exc
    if math.isnan(score) or math.isinf(score) or score < 0.0 or score > 10.0:
        raise ValueError("Score must be between 0.0 and 10.0.")
    return round(score, 2)


def sanitize_text(value: str, field_name: str = "Input", max_len: int = 200, required: bool = False) -> str:
    cleaned = (value or "").strip()
    if required and not cleaned:
        raise ValueError(f"{field_name} is required.")
    if len(cleaned) > max_len:
        raise ValueError(f"{field_name} must not exceed {max_len} characters.")
    return cleaned


# ---------------------------------------------------------------------------
# Authorization (Default-Deny, RBAC + Record-Level Ownership)
# ---------------------------------------------------------------------------

def has_role(user: dict[str, Any] | None, *allowed_roles: str) -> bool:
    """Default-deny check: returns True only if user has at least one allowed role."""
    if not user or not user.get("is_active"):
        return False
    user_roles = set(user.get("roles", []))
    return any(role in user_roles for role in allowed_roles)


def can_view_student_record(user: dict[str, Any] | None, student_row: sqlite3.Row) -> bool:
    if not user or not user.get("is_active"):
        return False
    roles = set(user.get("roles", []))
    if ROLE_REGISTRAR in roles:
        return True
    if ROLE_STUDENT in roles and student_row["user_id"] == user["id"]:
        return True
    return False


def can_update_student_contact(user: dict[str, Any] | None, student_row: sqlite3.Row) -> bool:
    if not user or not user.get("is_active"):
        return False
    roles = set(user.get("roles", []))
    if ROLE_REGISTRAR in roles:
        return True
    if ROLE_STUDENT in roles and student_row["user_id"] == user["id"]:
        return True
    return False


def can_view_course_roster(user: dict[str, Any] | None, course_row: sqlite3.Row) -> bool:
    if not user or not user.get("is_active"):
        return False
    roles = set(user.get("roles", []))
    if ROLE_REGISTRAR in roles:
        return True
    if ROLE_LECTURER in roles and course_row["lecturer_id"] == user["id"]:
        return True
    return False


def can_modify_grade(user: dict[str, Any] | None, enrollment_row: sqlite3.Row) -> bool:
    """Only an assigned Lecturer may create or update grades for their course."""
    if not user or not user.get("is_active"):
        return False
    roles = set(user.get("roles", []))
    return ROLE_LECTURER in roles and enrollment_row["lecturer_id"] == user["id"]


# ---------------------------------------------------------------------------
# Audit Logging Helper
# ---------------------------------------------------------------------------

def log_security_event(
    conn: sqlite3.Connection,
    acting_user: str,
    event_type: str,
    target_resource: str,
    result: str,
    details: str = "",
) -> None:
    """Record a security-relevant event into the append-only audit log."""
    database.insert_audit_log(
        conn=conn,
        acting_user=acting_user or "anonymous",
        event_type=event_type,
        target_resource=target_resource,
        result=result,
        details=details,
    )
