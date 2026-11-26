# Hệ Thống Quản Lý Hồ Sơ Sinh Viên (University Records System) — Kiểm Soát Truy Cập An Toàn

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?logo=sqlite&logoColor=white)
![Argon2id](https://img.shields.io/badge/Password_Hash-Argon2id-success)
![Tests](https://img.shields.io/badge/Security_Tests-26%2F26_Passed-brightgreen)

> **Nhóm thực hiện:** `N05_G9_524H0092_524H0035_524H0082`  
> **Đề tài:** Design, Implement, and Audit Secure Access Control  
> **Công nghệ sử dụng:** Python, FastAPI, Jinja2, SQLite, Argon2id, Pytest

---

## 1. Tổng quan

**University Records System** là ứng dụng web quản lý hồ sơ học vụ được xây dựng bằng **FastAPI** và **SQLite**, áp dụng chính sách kiểm soát truy cập **Default-Deny (từ chối mặc định)** dựa trên vai trò (**RBAC**), kiểm tra quyền sở hữu ở mức bản ghi (**Record-level Authorization**), truy vấn cơ sở dữ liệu tham số hóa, kiểm tra dữ liệu đầu vào trên server, mã hóa đầu ra HTML và ghi nhật ký bảo mật **chỉ nối thêm (append-only)**.

### Các cơ chế bảo mật đã triển khai

| Lĩnh vực | Cơ chế bảo mật |
|---|---|
| **Xác thực (Authentication)** | Đăng nhập bằng username/password, băm mật khẩu bằng **Argon2id**, thông báo lỗi đăng nhập chung chung (chống dò tài khoản), từ chối tài khoản bị vô hiệu hóa, quản lý session token phía server (`HttpOnly`, `SameSite=Lax`) và hủy ngay lập tức khi đăng xuất. |
| **Phân quyền (Authorization)** | Kiểm tra quyền **Default-Deny** ở server-side trên mọi endpoint; hỗ trợ một người dùng có nhiều vai trò; kiểm soát phạm vi dữ liệu (`Student` chỉ xem/sửa thông tin liên hệ của chính mình, `Lecturer` chỉ chấm điểm môn được phân công); tách biệt nhiệm vụ (`Registrar` không thể sửa điểm, `Security Auditor` chỉ có quyền đọc, `System Administrator` không tự động có quyền xem/sửa điểm). |
| **Bảo mật CSDL (Database Security)** | 100% câu truy vấn sử dụng **parameterized queries** (`?` placeholders), bật ràng buộc khóa ngoại (`PRAGMA foreign_keys = ON`), ràng buộc miền giá trị điểm số, và cài đặt SQLite triggers chặn `UPDATE`/`DELETE` trên bảng `audit_logs`. |
| **Bảo mật phần mềm (Software Security)** | Validate toàn bộ dữ liệu đầu vào ở server, tự động HTML-escape qua Jinja2 (chống XSS), tách cấu hình nhạy cảm qua file `.env`, và xử lý lỗi an toàn (không làm lộ stack trace, câu SQL hay cấu hình CSDL). |
| **Nhật ký kiểm toán (Audit Logging)** | Ghi nhận đầy đủ 8 nhóm sự kiện bảo mật bắt buộc (đăng nhập thành công/thất bại, đăng xuất, tạo/khóa tài khoản, gán/gỡ vai trò, cập nhật điểm, các hành vi bị từ chối quyền/IDOR) và tuyệt đối không ghi mật khẩu hay session token vào log. |

---

## 2. Cấu trúc thư mục

```text
N05_G9_524H0092_524H0035_524H0082/
├── README.md
├── database/
│   ├── schema.sql              # Cấu trúc bảng SQLite + triggers bảo vệ append-only cho audit_logs
│   └── seed-data.sql           # Dữ liệu mẫu: roles, users (đã băm Argon2id), môn học, điểm số
├── source/
│   ├── .env.example            # Mẫu biến môi trường (không chứa secret thật)
│   ├── requirements.txt        # Danh sách thư viện Python cần thiết
│   ├── database.py             # Kết nối SQLite & các hàm truy vấn tham số hóa
│   ├── security.py             # Argon2id, session, validation, RBAC & audit logging
│   ├── main.py                 # Ứng dụng FastAPI & các route đã bảo vệ
│   └── templates/
│       ├── login.html          # Giao diện đăng nhập
│       └── dashboard.html      # Giao diện bảng điều khiển theo vai trò
└── tests/
    └── test_security.py        # 26 kiểm thử bảo mật tự động (T01–T20 bắt buộc + T21–T26 mở rộng)
```

---

## 3. Hướng dẫn cài đặt và chạy ứng dụng

### Bước 1: Cài đặt thư viện

Chạy tại thư mục gốc (`N05_G9_524H0092_524H0035_524H0082/`):

```bash
pip install -r source/requirements.txt
```

### Bước 2: Tạo file cấu hình môi trường `.env`

- **Windows Command Prompt (`cmd`)**:
  ```cmd
  copy source\.env.example source\.env
  ```
- **Windows PowerShell**:
  ```powershell
  Copy-Item source\.env.example source\.env
  ```
- **macOS / Linux**:
  ```bash
  cp source/.env.example source/.env
  ```

### Bước 3: Khởi tạo cơ sở dữ liệu SQLite

```bash
python -c "import sys; sys.path.insert(0, 'source'); import database; database.init_db(seed=True)"
```

### Bước 4: Khởi động Web Server

```bash
cd source
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

Mở trình duyệt và truy cập: **http://127.0.0.1:8000/login**

---

## 4. Danh sách tài khoản mẫu

> **Mật khẩu mặc định của tất cả tài khoản mẫu:** `Password@123`

| Username | Vai trò (Role) | Phạm vi / Ghi chú |
|---|---|---|
| `student1` | `Student` | Alice Nguyen (`SV001`) — học môn `CS101` và `SEC201` |
| `student2` | `Student` | Bob Tran (`SV002`) — học môn `CS101` |
| `lecturer1` | `Lecturer` | Dr. Minh Le — chỉ phụ trách môn `CS101` |
| `lecturer2` | `Lecturer` | Dr. Lan Pham — chỉ phụ trách môn `SEC201` |
| `registrar1` | `Registrar` | Huong Vo — quản lý hồ sơ SV & đăng ký môn; chỉ xem điểm (không sửa) |
| `auditor1` | `Security Auditor` | Khang Hoang — chỉ đọc nhật ký kiểm toán & ma trận phân quyền |
| `admin1` | `System Administrator` | System Admin — quản lý tài khoản & gán/gỡ vai trò |
| `disabled_user` | `Student` *(Bị khóa)* | Tài khoản bị vô hiệu hóa (`is_active = 0`) để kiểm thử từ chối đăng nhập |

---

## 5. Chạy bộ kiểm thử bảo mật tự động

Chạy toàn bộ **26 test case** từ thư mục gốc (`N05_G9_524H0092_524H0035_524H0082/`):

```bash
pytest -v tests/test_security.py
```

### Tóm tắt phạm vi kiểm thử

| Nhóm kiểm thử | Mã Test | Nội dung kiểm tra |
|---|---|---|
| **Xác thực (Authentication)** | `T01` – `T05` | Đăng nhập hợp lệ, thông báo lỗi chung khi sai mật khẩu/tài khoản không tồn tại, chặn tài khoản bị vô hiệu hóa, vô hiệu hóa session sau khi đăng xuất, mật khẩu lưu trong DB đều được băm Argon2id. |
| **Phân quyền (Authorization & RBAC)** | `T06` – `T17`, `T24` – `T26` | Sinh viên chỉ xem điểm của mình & chặn IDOR, giảng viên chỉ sửa điểm môn được gán, giáo vụ không sửa được điểm, auditor chỉ đọc, admin không xem được điểm khi chưa có role học vụ, hỗ trợ đa vai trò, chặn truy cập chưa đăng nhập. |
| **Chống tấn công & Validate** | `T18`, `T19`, `T21` | Chống SQL Injection tại màn hình đăng nhập và tìm kiếm, HTML-escape chống Stored XSS, kiểm tra miền giá trị điểm số (`0.0` – `10.0`) phía server. |
| **Nhật ký kiểm toán (Audit Log)** | `T20`, `T22`, `T23` | Ghi nhận các hành vi leo thang đặc quyền bị từ chối, không làm lộ mật khẩu/token trong log, bảo vệ tính append-only ở tầng CSDL (chặn `UPDATE`/`DELETE`). |
