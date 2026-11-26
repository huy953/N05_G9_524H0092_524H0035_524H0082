-- University Records System - Seed Data
-- Default demo password for all seeded accounts: Password@123
-- All passwords are hashed with Argon2id (never stored in plaintext).

PRAGMA foreign_keys = ON;

INSERT OR IGNORE INTO roles (id, name, description) VALUES
    (1, 'Student', 'View own profile, enrollment, and grades; update own contact information'),
    (2, 'Lecturer', 'View students enrolled in assigned courses; create and update grades for assigned courses'),
    (3, 'Registrar', 'Create and update student records; manage enrollment; view grades; cannot modify grades'),
    (4, 'Security Auditor', 'Read audit logs and access-control configuration; cannot modify academic data'),
    (5, 'System Administrator', 'Manage user accounts and role assignments; cannot view or modify grades unless separately authorized');

INSERT OR IGNORE INTO users (id, username, password_hash, full_name, is_active) VALUES
    (1, 'student1', '$argon2id$v=19$m=65536,t=3,p=4$ew3sTUC0ZI8TqZbkeO973g$pwf6Igt4G6NAfLomReRCQUIk2ZZQRXXX3+DC/WaxAU8', 'Alice Nguyen', 1),
    (2, 'student2', '$argon2id$v=19$m=65536,t=3,p=4$Cz08QuRUGGiI6PETgCvQYg$nkAlBNKD3XO6LJnHUnPUABGuhR5K4z7rUUFJ3RQpM4w', 'Bob Tran', 1),
    (3, 'lecturer1', '$argon2id$v=19$m=65536,t=3,p=4$v4DIx4WbOcd3ptu/po/vKw$JhecN7elCVnRPEJCwWGpdBMkveZCklXYJLaU6k621Ks', 'Dr. Minh Le', 1),
    (4, 'lecturer2', '$argon2id$v=19$m=65536,t=3,p=4$wdeEX5fxnZcvDJt8EdeyMg$JM9I7eKLO3O/uvw3FG6K2+BVqg0fCQG68NzUtlRbwac', 'Dr. Lan Pham', 1),
    (5, 'registrar1', '$argon2id$v=19$m=65536,t=3,p=4$cgyV845P40qbx57OI3puKg$ZspFhnW+zjzumKrYS5BiNCMybQvXOPzIx8PkdgL0zcM', 'Huong Vo', 1),
    (6, 'auditor1', '$argon2id$v=19$m=65536,t=3,p=4$lvYKRaAlqKzDazfK62LuVw$QARav9AUWh6Lb+A4WU11wd8Su1HrWTsbiHk9gECIGsU', 'Khang Hoang', 1),
    (7, 'admin1', '$argon2id$v=19$m=65536,t=3,p=4$bav3cjvTAvjzKh+0P30bDg$+nubfLgnOKXLhGjFqFgd78pZ+gsNbT9rIaUx5fekxYg', 'System Admin', 1),
    (8, 'disabled_user', '$argon2id$v=19$m=65536,t=3,p=4$YEg4lFOoFvISVC1ecsbdcQ$t4KJPKjAWFcAF+9ui5CzqVl9vpuTcqA5/+05A8xBh3o', 'Disabled Account', 0);

INSERT OR IGNORE INTO user_roles (user_id, role_id) VALUES
    (1, 1), -- student1 -> Student
    (2, 1), -- student2 -> Student
    (3, 2), -- lecturer1 -> Lecturer
    (4, 2), -- lecturer2 -> Lecturer
    (5, 3), -- registrar1 -> Registrar
    (6, 4), -- auditor1 -> Security Auditor
    (7, 5), -- admin1 -> System Administrator
    (8, 1); -- disabled_user -> Student

INSERT OR IGNORE INTO students (id, user_id, student_code, full_name, email, phone, address) VALUES
    (1, 1, 'SV001', 'Alice Nguyen', 'alice@university.edu', '0901000001', '123 Nguyen Huu Tho, HCMC'),
    (2, 2, 'SV002', 'Bob Tran', 'bob@university.edu', '0901000002', '456 Le Loi, HCMC');

INSERT OR IGNORE INTO courses (id, course_code, course_name, lecturer_id) VALUES
    (1, 'CS101', 'Introduction to Programming', 3),
    (2, 'SEC201', 'Information Security', 4);

INSERT OR IGNORE INTO enrollments (id, student_id, course_id) VALUES
    (1, 1, 1), -- Alice in CS101
    (2, 2, 1), -- Bob in CS101
    (3, 1, 2); -- Alice in SEC201

INSERT OR IGNORE INTO grades (id, enrollment_id, score, remarks, updated_by) VALUES
    (1, 1, 8.5, 'Good progress', 3),
    (2, 3, 9.0, 'Excellent', 4);

INSERT INTO audit_logs (acting_user, event_type, target_resource, result, details) VALUES
    ('system', 'SYSTEM_SEED', 'database', 'SUCCESS', 'Initial seed data loaded');
