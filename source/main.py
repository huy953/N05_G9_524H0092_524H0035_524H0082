"""FastAPI web application for the University Records System."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

import database
import security

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def create_app(db_path: Path | str | None = None) -> FastAPI:
    """Application factory allowing isolated DB paths for testing."""
    app = FastAPI(title="University Records System", docs_url=None, redoc_url=None)
    app.state.db_path = db_path

    @app.on_event("startup")
    def on_startup() -> None:
        target = app.state.db_path or database.get_database_path()
        if not Path(target).exists():
            database.init_db(target, seed=True)

    def get_db():
        conn = database.get_connection(app.state.db_path)
        try:
            yield conn
        finally:
            conn.close()

    def get_current_user(
        request: Request, conn: sqlite3.Connection = Depends(get_db)
    ) -> dict[str, Any]:
        token = request.cookies.get(security.SESSION_COOKIE_NAME)
        user = security.get_authenticated_user(conn, token)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required.",
            )
        return user

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        accept = request.headers.get("accept", "")
        if "application/json" in accept:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
        if exc.status_code == status.HTTP_401_UNAUTHORIZED and not request.cookies.get(
            security.SESSION_COOKIE_NAME
        ):
            return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
        return HTMLResponse(
            content=f"<h2>Error {exc.status_code}</h2><p>{exc.detail}</p>"
            f"<p><a href='/dashboard'>Back to Dashboard</a> | <a href='/login'>Login</a></p>",
            status_code=exc.status_code,
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        # Never expose stack traces, SQL statements, or database configuration
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An internal server error occurred."},
        )

    # -----------------------------------------------------------------------
    # Authentication Routes
    # -----------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    def root(request: Request, conn: sqlite3.Connection = Depends(get_db)):
        token = request.cookies.get(security.SESSION_COOKIE_NAME)
        if security.get_authenticated_user(conn, token):
            return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": None, "message": request.query_params.get("msg")},
        )

    @app.post("/login", response_class=HTMLResponse)
    def login_submit(
        request: Request,
        username: str = Form(""),
        password: str = Form(""),
        conn: sqlite3.Connection = Depends(get_db),
    ):
        cleaned_username = username.strip()
        user_row = database.get_user_by_username(conn, cleaned_username)

        if user_row is None or not security.verify_password(password, user_row["password_hash"]):
            security.log_security_event(
                conn,
                acting_user=cleaned_username or "anonymous",
                event_type="LOGIN_FAILED",
                target_resource="auth/login",
                result="FAILURE",
                details="Invalid credentials",
            )
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"error": security.GENERIC_LOGIN_ERROR, "message": None},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        if not bool(user_row["is_active"]):
            security.log_security_event(
                conn,
                acting_user=user_row["username"],
                event_type="LOGIN_FAILED",
                target_resource="auth/login",
                result="FAILURE",
                details="Disabled account attempted login",
            )
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"error": security.GENERIC_LOGIN_ERROR, "message": None},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        token = security.generate_session_token()
        expires_at = security.session_expiry_iso()
        database.create_session(conn, token, user_row["id"], expires_at)

        security.log_security_event(
            conn,
            acting_user=user_row["username"],
            event_type="LOGIN_SUCCESS",
            target_resource="auth/login",
            result="SUCCESS",
            details="User authenticated",
        )

        response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        secure_cookie = os.getenv("COOKIE_SECURE", "false").lower() == "true"
        response.set_cookie(
            key=security.SESSION_COOKIE_NAME,
            value=token,
            httponly=True,
            samesite="lax",
            secure=secure_cookie,
            max_age=security.get_session_expire_minutes() * 60,
        )
        return response

    @app.post("/logout")
    def logout(request: Request, conn: sqlite3.Connection = Depends(get_db)):
        token = request.cookies.get(security.SESSION_COOKIE_NAME)
        user = security.get_authenticated_user(conn, token)
        if token:
            database.revoke_session(conn, token)
        if user:
            security.log_security_event(
                conn,
                acting_user=user["username"],
                event_type="LOGOUT",
                target_resource="auth/logout",
                result="SUCCESS",
                details="Session invalidated",
            )
        response = RedirectResponse(
            url="/login?msg=Logged+out+successfully", status_code=status.HTTP_303_SEE_OTHER
        )
        response.delete_cookie(security.SESSION_COOKIE_NAME)
        return response

    # -----------------------------------------------------------------------
    # Dashboard
    # -----------------------------------------------------------------------

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard(
        request: Request,
        search: str = "",
        user: dict[str, Any] = Depends(get_current_user),
        conn: sqlite3.Connection = Depends(get_db),
    ):
        roles = set(user["roles"])
        student_profile = None
        student_enrollments = []
        lecturer_courses = []
        lecturer_rosters: dict[int, list[sqlite3.Row]] = {}
        all_students = []
        all_courses = []
        all_grades = []
        all_users = []
        all_roles = []
        audit_logs = []
        ac_matrix = []

        if security.ROLE_STUDENT in roles:
            student_profile = database.get_student_by_user_id(conn, user["id"])
            if student_profile is not None:
                student_enrollments = database.list_enrollments_for_student(
                    conn, student_profile["id"]
                )

        if security.ROLE_LECTURER in roles:
            lecturer_courses = database.list_courses_for_lecturer(conn, user["id"])
            for c in lecturer_courses:
                lecturer_rosters[c["id"]] = database.list_enrollments_for_course(conn, c["id"])

        if security.ROLE_REGISTRAR in roles:
            cleaned_search = security.sanitize_text(search, "Search", max_len=80)
            all_students = database.list_students(conn, cleaned_search)
            all_courses = database.list_courses(conn)
            all_grades = database.list_all_grades(conn)

        if security.ROLE_AUDITOR in roles:
            audit_logs = database.list_audit_logs(conn, limit=100)
            ac_matrix = security.ACCESS_CONTROL_MATRIX

        if security.ROLE_ADMIN in roles:
            all_users = database.list_users_with_roles(conn)
            all_roles = database.list_roles(conn)

        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                "user": user,
                "roles": user["roles"],
                "msg": request.query_params.get("msg"),
                "err": request.query_params.get("err"),
                "search": search,
                "student_profile": student_profile,
                "student_enrollments": student_enrollments,
                "lecturer_courses": lecturer_courses,
                "lecturer_rosters": lecturer_rosters,
                "all_students": all_students,
                "all_courses": all_courses,
                "all_grades": all_grades,
                "all_users": all_users,
                "all_roles": all_roles,
                "audit_logs": audit_logs,
                "ac_matrix": ac_matrix,
            },
        )

    # -----------------------------------------------------------------------
    # Student Record & Contact Operations (Record-level Authorization)
    # -----------------------------------------------------------------------

    @app.get("/students/{student_id}")
    def view_student_record(
        student_id: int,
        user: dict[str, Any] = Depends(get_current_user),
        conn: sqlite3.Connection = Depends(get_db),
    ):
        student = database.get_student_by_id(conn, student_id)
        if student is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Student not found.")

        if not security.can_view_student_record(user, student):
            security.log_security_event(
                conn,
                acting_user=user["username"],
                event_type="ACCESS_DENIED",
                target_resource=f"student/{student_id}",
                result="REJECTED",
                details="Unauthorized attempt to view another user's student record",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: you are not authorized to view this student record.",
            )

        enrollments = database.list_enrollments_for_student(conn, student_id)
        return {
            "student": dict(student),
            "enrollments": [dict(row) for row in enrollments],
        }

    @app.post("/students/{student_id}/contact")
    def update_student_contact_route(
        student_id: int,
        email: str = Form(...),
        phone: str = Form(...),
        address: str = Form(""),
        user: dict[str, Any] = Depends(get_current_user),
        conn: sqlite3.Connection = Depends(get_db),
    ):
        student = database.get_student_by_id(conn, student_id)
        if student is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Student not found.")

        if not security.can_update_student_contact(user, student):
            security.log_security_event(
                conn,
                acting_user=user["username"],
                event_type="ACCESS_DENIED",
                target_resource=f"student/{student_id}/contact",
                result="REJECTED",
                details="Unauthorized attempt to modify another student's contact info",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: you cannot update this student's contact information.",
            )

        try:
            clean_email = security.validate_email(email)
            clean_phone = security.validate_phone(phone)
            clean_address = security.sanitize_text(address, "Address", max_len=200)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

        database.update_student_contact(conn, student_id, clean_email, clean_phone, clean_address)
        security.log_security_event(
            conn,
            acting_user=user["username"],
            event_type="CONTACT_UPDATED",
            target_resource=f"student/{student_id}/contact",
            result="SUCCESS",
            details="Updated student contact information",
        )
        return RedirectResponse(
            url="/dashboard?msg=" + quote_plus("Contact information updated."),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    # -----------------------------------------------------------------------
    # Course Roster & Grade Operations (Lecturer assigned courses only)
    # -----------------------------------------------------------------------

    @app.get("/courses/{course_id}/roster")
    def view_course_roster(
        course_id: int,
        user: dict[str, Any] = Depends(get_current_user),
        conn: sqlite3.Connection = Depends(get_db),
    ):
        course = database.get_course_by_id(conn, course_id)
        if course is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Course not found.")

        if not security.can_view_course_roster(user, course):
            security.log_security_event(
                conn,
                acting_user=user["username"],
                event_type="ACCESS_DENIED",
                target_resource=f"course/{course_id}/roster",
                result="REJECTED",
                details="Unauthorized attempt to view course roster",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: you are not assigned to this course.",
            )

        roster = database.list_enrollments_for_course(conn, course_id)
        return {"course": dict(course), "roster": [dict(r) for r in roster]}

    @app.post("/grades")
    def upsert_grade_route(
        enrollment_id: int = Form(...),
        score: str = Form(...),
        remarks: str = Form(""),
        user: dict[str, Any] = Depends(get_current_user),
        conn: sqlite3.Connection = Depends(get_db),
    ):
        enrollment = database.get_enrollment_by_id(conn, enrollment_id)
        if enrollment is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Enrollment not found.")

        if not security.can_modify_grade(user, enrollment):
            security.log_security_event(
                conn,
                acting_user=user["username"],
                event_type="GRADE_MODIFICATION_REJECTED",
                target_resource=f"grade/enrollment/{enrollment_id}",
                result="REJECTED",
                details=(
                    f"User lacks assigned-lecturer permission for course "
                    f"{enrollment['course_code']}"
                ),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: only the assigned lecturer can modify grades for this course.",
            )

        try:
            valid_score = security.validate_score(score)
            clean_remarks = security.sanitize_text(remarks, "Remarks", max_len=200)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

        database.upsert_grade(conn, enrollment_id, valid_score, clean_remarks, user["id"])
        security.log_security_event(
            conn,
            acting_user=user["username"],
            event_type="GRADE_MODIFIED",
            target_resource=f"grade/enrollment/{enrollment_id}",
            result="SUCCESS",
            details=f"Set score={valid_score} for {enrollment['student_code']} in {enrollment['course_code']}",
        )
        return RedirectResponse(
            url="/dashboard?msg=" + quote_plus("Grade saved successfully."),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.get("/grades")
    def view_all_grades_route(
        user: dict[str, Any] = Depends(get_current_user),
        conn: sqlite3.Connection = Depends(get_db),
    ):
        # System Administrators and Security Auditors must NOT view academic grades
        # unless separately authorized (e.g. also hold Registrar role).
        if not security.has_role(user, security.ROLE_REGISTRAR):
            security.log_security_event(
                conn,
                acting_user=user["username"],
                event_type="ACCESS_DENIED",
                target_resource="grades/all",
                result="REJECTED",
                details="Unauthorized attempt to view all academic grades",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: you are not authorized to view all grades.",
            )
        return {"grades": [dict(r) for r in database.list_all_grades(conn)]}

    # -----------------------------------------------------------------------
    # Registrar Operations (Student records & enrollment; NO grade modification)
    # -----------------------------------------------------------------------

    @app.post("/registrar/students")
    def registrar_create_student(
        username: str = Form(...),
        password: str = Form(...),
        student_code: str = Form(...),
        full_name: str = Form(...),
        email: str = Form(...),
        phone: str = Form(...),
        address: str = Form(""),
        user: dict[str, Any] = Depends(get_current_user),
        conn: sqlite3.Connection = Depends(get_db),
    ):
        if not security.has_role(user, security.ROLE_REGISTRAR):
            security.log_security_event(
                conn,
                acting_user=user["username"],
                event_type="ACCESS_DENIED",
                target_resource="registrar/students",
                result="REJECTED",
                details="Non-registrar attempted to create student record",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Registrar role required.",
            )

        try:
            clean_username = security.validate_username(username)
            valid_pw = security.validate_password_strength(password)
            clean_code = security.validate_student_code(student_code)
            clean_name = security.sanitize_text(full_name, "Full name", max_len=100, required=True)
            clean_email = security.validate_email(email)
            clean_phone = security.validate_phone(phone)
            clean_address = security.sanitize_text(address, "Address", max_len=200)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

        if database.get_user_by_username(conn, clean_username) is not None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists.")

        try:
            pw_hash = security.hash_password(valid_pw)
            new_user_id = database.create_user(conn, clean_username, pw_hash, clean_name, is_active=1)
            database.assign_role_to_user(conn, new_user_id, security.ROLE_STUDENT)
            student_id = database.create_student_record(
                conn, new_user_id, clean_code, clean_name, clean_email, clean_phone, clean_address
            )
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Student code or username already exists.",
            )

        security.log_security_event(
            conn,
            acting_user=user["username"],
            event_type="USER_CREATED",
            target_resource=f"student/{student_id}",
            result="SUCCESS",
            details=f"Created student record {clean_code} for user {clean_username}",
        )
        return RedirectResponse(
            url="/dashboard?msg=" + quote_plus("Student record created."),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.post("/registrar/students/{student_id}/update")
    def registrar_update_student(
        student_id: int,
        full_name: str = Form(...),
        email: str = Form(...),
        phone: str = Form(...),
        address: str = Form(""),
        user: dict[str, Any] = Depends(get_current_user),
        conn: sqlite3.Connection = Depends(get_db),
    ):
        if not security.has_role(user, security.ROLE_REGISTRAR):
            security.log_security_event(
                conn,
                acting_user=user["username"],
                event_type="ACCESS_DENIED",
                target_resource=f"registrar/students/{student_id}",
                result="REJECTED",
                details="Unauthorized attempt to modify student record",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Registrar role required.",
            )

        if database.get_student_by_id(conn, student_id) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Student not found.")

        try:
            clean_name = security.sanitize_text(full_name, "Full name", max_len=100, required=True)
            clean_email = security.validate_email(email)
            clean_phone = security.validate_phone(phone)
            clean_address = security.sanitize_text(address, "Address", max_len=200)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

        database.update_student_record(conn, student_id, clean_name, clean_email, clean_phone, clean_address)
        security.log_security_event(
            conn,
            acting_user=user["username"],
            event_type="STUDENT_RECORD_UPDATED",
            target_resource=f"student/{student_id}",
            result="SUCCESS",
            details="Updated student profile",
        )
        return RedirectResponse(
            url="/dashboard?msg=" + quote_plus("Student record updated."),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.post("/registrar/enrollments")
    def registrar_create_enrollment(
        student_id: int = Form(...),
        course_id: int = Form(...),
        user: dict[str, Any] = Depends(get_current_user),
        conn: sqlite3.Connection = Depends(get_db),
    ):
        if not security.has_role(user, security.ROLE_REGISTRAR):
            security.log_security_event(
                conn,
                acting_user=user["username"],
                event_type="ACCESS_DENIED",
                target_resource="registrar/enrollments",
                result="REJECTED",
                details="Unauthorized attempt to manage enrollments",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Registrar role required.",
            )

        if database.get_student_by_id(conn, student_id) is None or database.get_course_by_id(conn, course_id) is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Student or course not found.")

        try:
            enrollment_id = database.create_enrollment(conn, student_id, course_id)
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Student already enrolled.")

        security.log_security_event(
            conn,
            acting_user=user["username"],
            event_type="ENROLLMENT_CREATED",
            target_resource=f"enrollment/{enrollment_id}",
            result="SUCCESS",
            details=f"Enrolled student_id={student_id} in course_id={course_id}",
        )
        return RedirectResponse(
            url="/dashboard?msg=" + quote_plus("Enrollment created."),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    # -----------------------------------------------------------------------
    # System Administrator Operations (Accounts & Role Assignments only)
    # -----------------------------------------------------------------------

    @app.post("/admin/users")
    def admin_create_user(
        username: str = Form(...),
        password: str = Form(...),
        full_name: str = Form(...),
        role_name: str = Form(...),
        user: dict[str, Any] = Depends(get_current_user),
        conn: sqlite3.Connection = Depends(get_db),
    ):
        if not security.has_role(user, security.ROLE_ADMIN):
            security.log_security_event(
                conn,
                acting_user=user["username"],
                event_type="ACCESS_DENIED",
                target_resource="admin/users",
                result="REJECTED",
                details="Unauthorized attempt to create user account",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: System Administrator role required.",
            )

        try:
            clean_username = security.validate_username(username)
            valid_pw = security.validate_password_strength(password)
            clean_name = security.sanitize_text(full_name, "Full name", max_len=100, required=True)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

        if role_name not in security.VALID_ROLES:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role specified.")

        if database.get_user_by_username(conn, clean_username) is not None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists.")

        pw_hash = security.hash_password(valid_pw)
        new_user_id = database.create_user(conn, clean_username, pw_hash, clean_name, is_active=1)
        database.assign_role_to_user(conn, new_user_id, role_name)

        security.log_security_event(
            conn,
            acting_user=user["username"],
            event_type="USER_CREATED",
            target_resource=f"user/{new_user_id}",
            result="SUCCESS",
            details=f"Created user {clean_username} with role {role_name}",
        )
        return RedirectResponse(
            url="/dashboard?msg=" + quote_plus("User account created."),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.post("/admin/users/{target_user_id}/status")
    def admin_toggle_user_status(
        target_user_id: int,
        is_active: int = Form(...),
        user: dict[str, Any] = Depends(get_current_user),
        conn: sqlite3.Connection = Depends(get_db),
    ):
        if not security.has_role(user, security.ROLE_ADMIN):
            security.log_security_event(
                conn,
                acting_user=user["username"],
                event_type="ACCESS_DENIED",
                target_resource=f"admin/users/{target_user_id}/status",
                result="REJECTED",
                details="Unauthorized attempt to change user status",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: System Administrator role required.",
            )

        target = database.get_user_by_id(conn, target_user_id)
        if target is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

        flag = 1 if int(is_active) == 1 else 0
        database.set_user_active(conn, target_user_id, flag)
        action_label = "enabled" if flag == 1 else "disabled"
        security.log_security_event(
            conn,
            acting_user=user["username"],
            event_type="USER_STATUS_CHANGED",
            target_resource=f"user/{target_user_id}",
            result="SUCCESS",
            details=f"Account {target['username']} {action_label}",
        )
        return RedirectResponse(
            url="/dashboard?msg=" + quote_plus(f"User {action_label}."),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @app.post("/admin/users/{target_user_id}/roles")
    def admin_manage_role(
        target_user_id: int,
        role_name: str = Form(...),
        action: str = Form("assign"),
        user: dict[str, Any] = Depends(get_current_user),
        conn: sqlite3.Connection = Depends(get_db),
    ):
        if not security.has_role(user, security.ROLE_ADMIN):
            security.log_security_event(
                conn,
                acting_user=user["username"],
                event_type="ACCESS_DENIED",
                target_resource=f"admin/users/{target_user_id}/roles",
                result="REJECTED",
                details="Unauthorized attempt to modify role assignment",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: System Administrator role required.",
            )

        target = database.get_user_by_id(conn, target_user_id)
        if target is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

        if role_name not in security.VALID_ROLES or action not in {"assign", "remove"}:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role or action.")

        if action == "assign":
            database.assign_role_to_user(conn, target_user_id, role_name)
            ev = "ROLE_ASSIGNED"
        else:
            database.remove_role_from_user(conn, target_user_id, role_name)
            ev = "ROLE_REMOVED"

        security.log_security_event(
            conn,
            acting_user=user["username"],
            event_type=ev,
            target_resource=f"user/{target_user_id}/roles",
            result="SUCCESS",
            details=f"{action} role '{role_name}' for {target['username']}",
        )
        return RedirectResponse(
            url="/dashboard?msg=" + quote_plus("Role assignment updated."),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    # -----------------------------------------------------------------------
    # Security Auditor Operations (Read-only Audit Logs & AC Config)
    # -----------------------------------------------------------------------

    @app.get("/audit-logs")
    def read_audit_logs_route(
        user: dict[str, Any] = Depends(get_current_user),
        conn: sqlite3.Connection = Depends(get_db),
    ):
        if not security.has_role(user, security.ROLE_AUDITOR):
            security.log_security_event(
                conn,
                acting_user=user["username"],
                event_type="ACCESS_DENIED",
                target_resource="audit-logs",
                result="REJECTED",
                details="Unauthorized attempt to read security audit logs",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Security Auditor role required.",
            )

        logs = [dict(row) for row in database.list_audit_logs(conn, limit=200)]
        return {
            "audit_logs": logs,
            "access_control_matrix": security.ACCESS_CONTROL_MATRIX,
        }

    return app


app = create_app()
