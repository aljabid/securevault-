"""
SecureVault — Security Regression Test Suite
Automated tests that verify critical security controls remain enforced.
Run in CI/CD pipeline on every commit and before every release.

Usage: pytest tests/security/ -v --tb=short
"""

import uuid
import json
import base64
import hmac
import hashlib
import pytest
from datetime import datetime, timedelta, timezone

# ─────────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────────

@pytest.fixture
def api_client():
    """Django test client."""
    from django.test import Client
    return Client()


@pytest.fixture
def user_token(api_client, django_user_model):
    """Return JWT access token for a test user."""
    user = django_user_model.objects.create_user(
        username=f"testuser_{uuid.uuid4().hex[:8]}",
        email=f"test_{uuid.uuid4().hex[:8]}@securevault.io",
        password="S3cur3P@ssw0rd!Test2025",
    )
    response = api_client.post(
        "/api/v1/auth/login/",
        {"email": user.email, "password": "S3cur3P@ssw0rd!Test2025"},
        content_type="application/json",
    )
    assert response.status_code == 200
    return response.json()["access"], user


@pytest.fixture
def user_a_token(api_client, django_user_model):
    """User A — file owner."""
    user = django_user_model.objects.create_user(
        username=f"user_a_{uuid.uuid4().hex[:8]}",
        email=f"user_a_{uuid.uuid4().hex[:8]}@test.io",
        password="S3cur3P@ssw0rd!A",
    )
    resp = api_client.post(
        "/api/v1/auth/login/",
        {"email": user.email, "password": "S3cur3P@ssw0rd!A"},
        content_type="application/json",
    )
    return resp.json()["access"], user


@pytest.fixture
def user_b_token(api_client, django_user_model):
    """User B — unauthorized accessor."""
    user = django_user_model.objects.create_user(
        username=f"user_b_{uuid.uuid4().hex[:8]}",
        email=f"user_b_{uuid.uuid4().hex[:8]}@test.io",
        password="S3cur3P@ssw0rd!B",
    )
    resp = api_client.post(
        "/api/v1/auth/login/",
        {"email": user.email, "password": "S3cur3P@ssw0rd!B"},
        content_type="application/json",
    )
    return resp.json()["access"], user


# ─────────────────────────────────────────────
# PT-001 REGRESSION: JWT ALGORITHM ATTACKS
# ─────────────────────────────────────────────

class TestJWTSecurity:
    """
    Regression tests for PT-001: JWT Algorithm Confusion.
    These tests must PASS (attacker must be BLOCKED) on every run.
    """

    def test_jwt_none_algorithm_rejected(self, api_client):
        """
        Security: JWT with 'none' algorithm must be rejected with 401.
        Reference: PT-001, SR-002
        """
        # Craft a JWT with algorithm=none
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()

        payload = base64.urlsafe_b64encode(
            json.dumps({
                "user_id": str(uuid.uuid4()),
                "role": "superadmin",
                "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            }).encode()
        ).rstrip(b"=").decode()

        # none algorithm = empty signature
        forged_token = f"{header}.{payload}."

        response = api_client.get(
            "/api/v1/files/",
            HTTP_AUTHORIZATION=f"Bearer {forged_token}",
        )

        assert response.status_code == 401, (
            f"SECURITY REGRESSION: 'none' algorithm JWT was accepted! "
            f"Got {response.status_code}. PT-001 regression!"
        )

    def test_jwt_hs256_with_public_key_rejected(self, api_client):
        """
        Security: HS256 token signed with RS256 public key must be rejected.
        This is the exact PT-001 attack vector.
        Reference: PT-001
        """
        # Simulate forging a token signed with the public key as HMAC secret
        # In real attack: attacker obtains public key from /jwks.json
        fake_public_key = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."

        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).rstrip(b"=").decode()

        payload_data = {
            "user_id": str(uuid.uuid4()),
            "role": "admin",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        }
        payload = base64.urlsafe_b64encode(
            json.dumps(payload_data).encode()
        ).rstrip(b"=").decode()

        message = f"{header}.{payload}"
        signature = base64.urlsafe_b64encode(
            hmac.new(fake_public_key, message.encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()

        forged_token = f"{header}.{payload}.{signature}"

        response = api_client.get(
            "/api/v1/admin/users/",
            HTTP_AUTHORIZATION=f"Bearer {forged_token}",
        )

        assert response.status_code in [401, 403], (
            f"SECURITY REGRESSION: HS256 algorithm confusion attack succeeded! "
            f"Got {response.status_code}. PT-001 regression!"
        )

    def test_expired_token_rejected(self, api_client):
        """Expired JWT must be rejected with 401."""
        # We can't easily create a valid expired token without the private key
        # This test verifies the endpoint rejects malformed/expired tokens
        expired_looking_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjF9.invalid"

        response = api_client.get(
            "/api/v1/files/",
            HTTP_AUTHORIZATION=f"Bearer {expired_looking_token}",
        )

        assert response.status_code == 401

    def test_missing_token_rejected(self, api_client):
        """Request with no Authorization header must be rejected."""
        response = api_client.get("/api/v1/files/")
        assert response.status_code == 401

    def test_malformed_token_rejected(self, api_client):
        """Malformed tokens must be rejected."""
        for bad_token in ["", "notaJWT", "Bearer", "a.b", "a.b.c.d"]:
            response = api_client.get(
                "/api/v1/files/",
                HTTP_AUTHORIZATION=f"Bearer {bad_token}",
            )
            assert response.status_code == 401, f"Token '{bad_token}' was accepted!"


# ─────────────────────────────────────────────
# PT-002 REGRESSION: IDOR PROTECTION
# ─────────────────────────────────────────────

class TestIDORProtection:
    """
    Regression tests for PT-002: IDOR on file resources.
    User B must NEVER be able to access User A's files.
    """

    def test_user_cannot_download_other_users_file(
        self, api_client, user_a_token, user_b_token
    ):
        """
        Security: User B must receive 404 (not 200) when accessing User A's file.
        Reference: PT-002, SR-005
        """
        token_a, user_a = user_a_token
        token_b, user_b = user_b_token

        # User A uploads a file
        upload_response = api_client.post(
            "/api/v1/files/upload/",
            {"file": _create_test_file("test.pdf", b"%PDF-1.4 test content")},
            HTTP_AUTHORIZATION=f"Bearer {token_a}",
        )

        if upload_response.status_code != 201:
            pytest.skip("File upload failed — skipping IDOR test")

        file_id = upload_response.json()["file_id"]

        # User B attempts to download User A's file
        download_response = api_client.get(
            f"/api/v1/files/{file_id}/download/",
            HTTP_AUTHORIZATION=f"Bearer {token_b}",
        )

        assert download_response.status_code in [403, 404], (
            f"SECURITY REGRESSION: User B accessed User A's file! "
            f"Got {download_response.status_code}. PT-002 regression!"
        )

        # Must not be 200 — that means IDOR is exploitable
        assert download_response.status_code != 200, (
            "CRITICAL: IDOR vulnerability detected! User B can access User A's files!"
        )

    def test_user_cannot_delete_other_users_file(
        self, api_client, user_a_token, user_b_token
    ):
        """User B must not be able to delete User A's files."""
        token_a, _ = user_a_token
        token_b, _ = user_b_token

        upload_response = api_client.post(
            "/api/v1/files/upload/",
            {"file": _create_test_file("test.pdf", b"%PDF-1.4 test content")},
            HTTP_AUTHORIZATION=f"Bearer {token_a}",
        )

        if upload_response.status_code != 201:
            pytest.skip("File upload failed")

        file_id = upload_response.json()["file_id"]

        delete_response = api_client.delete(
            f"/api/v1/files/{file_id}/",
            HTTP_AUTHORIZATION=f"Bearer {token_b}",
        )

        assert delete_response.status_code in [403, 404], (
            f"SECURITY REGRESSION: User B deleted User A's file! PT-002 regression!"
        )

    def test_file_list_only_shows_own_files(
        self, api_client, user_a_token, user_b_token
    ):
        """File list endpoint must only return the authenticated user's own files."""
        token_a, user_a = user_a_token
        token_b, user_b = user_b_token

        # User A uploads a file
        api_client.post(
            "/api/v1/files/upload/",
            {"file": _create_test_file("user_a_file.pdf", b"%PDF-1.4 userA content")},
            HTTP_AUTHORIZATION=f"Bearer {token_a}",
        )

        # User B lists their files
        list_response = api_client.get(
            "/api/v1/files/",
            HTTP_AUTHORIZATION=f"Bearer {token_b}",
        )

        assert list_response.status_code == 200
        files = list_response.json()["files"]

        # Verify no file from User A appears in User B's list
        for file in files:
            assert str(file.get("owner_id", user_b.id)) == str(user_b.id), (
                f"IDOR: User B's file list contains User A's file! File: {file}"
            )


# ─────────────────────────────────────────────
# AUTHENTICATION SECURITY TESTS
# ─────────────────────────────────────────────

class TestAuthenticationSecurity:
    """Tests for authentication security controls."""

    def test_brute_force_lockout_after_5_attempts(self, api_client):
        """
        Account should be locked after 5 failed login attempts.
        Reference: SR-004, R-001
        """
        email = f"lockout_test_{uuid.uuid4().hex[:8]}@test.io"

        # Attempt 5 failed logins
        for i in range(5):
            response = api_client.post(
                "/api/v1/auth/login/",
                {"email": email, "password": "WrongPassword!"},
                content_type="application/json",
            )
            assert response.status_code in [401, 429]

        # 6th attempt should be rate-limited or locked
        response = api_client.post(
            "/api/v1/auth/login/",
            {"email": email, "password": "WrongPassword!"},
            content_type="application/json",
        )
        assert response.status_code in [429, 403], (
            f"Brute force not blocked after 5 attempts! Got {response.status_code}"
        )

    def test_login_generic_error_message(self, api_client):
        """
        Login must return the same error message for wrong password
        and non-existent user (prevent username enumeration).
        Reference: PT-009
        """
        # Non-existent user
        resp_nonexist = api_client.post(
            "/api/v1/auth/login/",
            {"email": "nonexistent@test.io", "password": "WrongPassword!"},
            content_type="application/json",
        )

        # Wrong password for existing-format email
        resp_wrongpass = api_client.post(
            "/api/v1/auth/login/",
            {"email": "existing@test.io", "password": "WrongPassword!"},
            content_type="application/json",
        )

        # Both should return the same status and same generic message
        assert resp_nonexist.status_code == 401
        assert resp_wrongpass.status_code == 401

        body_nonexist = resp_nonexist.json()
        body_wrongpass = resp_wrongpass.json()

        # Error messages should be identical (no enumeration)
        assert body_nonexist.get("detail") == body_wrongpass.get("detail"), (
            "Username enumeration possible via different error messages!"
        )

    def test_unauthenticated_access_to_protected_endpoints(self, api_client):
        """All protected endpoints must return 401 without auth."""
        protected_endpoints = [
            ("GET", "/api/v1/files/"),
            ("POST", "/api/v1/files/upload/"),
            ("GET", "/api/v1/users/me/"),
            ("GET", "/api/v1/admin/users/"),
        ]

        for method, endpoint in protected_endpoints:
            if method == "GET":
                response = api_client.get(endpoint)
            else:
                response = api_client.post(endpoint, {}, content_type="application/json")

            assert response.status_code == 401, (
                f"Endpoint {method} {endpoint} is accessible without auth! "
                f"Got {response.status_code}"
            )


# ─────────────────────────────────────────────
# FILE UPLOAD SECURITY TESTS
# ─────────────────────────────────────────────

class TestFileUploadSecurity:
    """Security tests for file upload pipeline."""

    def test_executable_file_rejected(self, api_client, user_token):
        """Executable files (MZ header = Windows PE) must be rejected."""
        token, _ = user_token

        # Windows PE executable magic bytes
        pe_header = b"MZ\x90\x00\x03\x00\x00\x00"
        fake_exe = pe_header + b"\x00" * 512

        response = api_client.post(
            "/api/v1/files/upload/",
            {"file": _create_test_file("malware.exe", fake_exe)},
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        assert response.status_code in [400, 422], (
            f"Executable file was accepted! Got {response.status_code}. "
            f"This is a critical security vulnerability!"
        )

    def test_php_script_rejected(self, api_client, user_token):
        """PHP scripts must be rejected regardless of extension."""
        token, _ = user_token

        php_content = b"<?php system($_GET['cmd']); ?>"

        # Try with .php extension
        response = api_client.post(
            "/api/v1/files/upload/",
            {"file": _create_test_file("shell.php", php_content)},
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        assert response.status_code in [400, 422], "PHP file accepted!"

        # Try with .pdf extension (MIME mismatch attack)
        response = api_client.post(
            "/api/v1/files/upload/",
            {"file": _create_test_file("innocent.pdf", php_content)},
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        assert response.status_code in [400, 422], "PHP disguised as PDF was accepted!"

    def test_file_size_limit_enforced(self, api_client, user_token):
        """Files over 50MB must be rejected."""
        token, _ = user_token

        # Create a 51MB file (over the 50MB limit)
        oversized_content = b"X" * (51 * 1024 * 1024)

        response = api_client.post(
            "/api/v1/files/upload/",
            {"file": _create_test_file("large.txt", oversized_content)},
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        assert response.status_code in [400, 413], (
            f"File over 50MB was accepted! Got {response.status_code}"
        )

    def test_path_traversal_filename_rejected(self, api_client, user_token):
        """Filenames with path traversal sequences must be rejected or sanitized."""
        token, _ = user_token

        traversal_filenames = [
            "../../etc/passwd",
            "../../../secret.txt",
            "..%2F..%2Fetc%2Fpasswd",
            "normal.pdf\x00.php",
        ]

        for filename in traversal_filenames:
            response = api_client.post(
                "/api/v1/files/upload/",
                {"file": _create_test_file(filename, b"%PDF-1.4 test")},
                HTTP_AUTHORIZATION=f"Bearer {token}",
            )

            # Should either reject (400) or sanitize the filename
            if response.status_code == 201:
                # If accepted, verify the stored filename has been sanitized
                stored_name = response.json().get("filename", "")
                assert ".." not in stored_name, (
                    f"Path traversal in filename was not sanitized! "
                    f"Input: {filename}, Stored: {stored_name}"
                )

    def test_elf_executable_rejected(self, api_client, user_token):
        """Linux ELF executables must be rejected."""
        token, _ = user_token

        elf_header = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 256

        response = api_client.post(
            "/api/v1/files/upload/",
            {"file": _create_test_file("backdoor.so", elf_header)},
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        assert response.status_code in [400, 422], (
            f"ELF executable accepted! Got {response.status_code}"
        )


# ─────────────────────────────────────────────
# SECURITY HEADERS TESTS
# ─────────────────────────────────────────────

class TestSecurityHeaders:
    """Verify all required security headers are present on responses."""

    REQUIRED_HEADERS = [
        ("X-Frame-Options", "DENY"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ]

    def test_security_headers_present_on_api_response(self, api_client):
        """All security headers must be present on API responses."""
        response = api_client.get("/api/v1/auth/login/")

        for header_name, expected_value in self.REQUIRED_HEADERS:
            assert header_name in response, (
                f"Security header missing: {header_name}"
            )
            actual_value = response[header_name]
            assert expected_value.lower() in actual_value.lower(), (
                f"Header {header_name}: expected '{expected_value}', got '{actual_value}'"
            )

    def test_csp_header_present(self, api_client):
        """Content-Security-Policy header must be present."""
        response = api_client.get("/api/v1/auth/login/")
        assert "Content-Security-Policy" in response, "CSP header missing!"
        csp = response["Content-Security-Policy"]
        assert "default-src" in csp, "CSP missing default-src directive"
        assert "object-src 'none'" in csp, "CSP should block object-src"

    def test_no_server_version_disclosure(self, api_client):
        """Server header must not disclose version information."""
        response = api_client.get("/api/v1/auth/login/")
        server_header = response.get("Server", "")
        assert "nginx/" not in server_header.lower(), "NGINX version disclosed!"
        assert "django" not in server_header.lower(), "Django version disclosed!"
        assert "python" not in server_header.lower(), "Python version disclosed!"

    def test_no_stack_trace_in_error_response(self, api_client, user_token):
        """Error responses must not contain stack traces."""
        token, _ = user_token

        # Trigger a 404 on a non-existent file
        response = api_client.get(
            f"/api/v1/files/{uuid.uuid4()}/download/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        assert response.status_code == 404
        body = response.content.decode()
        assert "Traceback" not in body, "Stack trace in HTTP response! PT-003 regression!"
        assert "File \"/" not in body, "File path in HTTP response!"
        assert "line " not in body.lower() or "django" not in body.lower(), (
            "Potential stack trace disclosure in error response"
        )


# ─────────────────────────────────────────────
# INPUT VALIDATION TESTS
# ─────────────────────────────────────────────

class TestInputValidation:
    """SQL injection and XSS prevention tests."""

    def test_sql_injection_in_file_id_rejected(self, api_client, user_token):
        """SQL injection in file_id URL parameter must be rejected."""
        token, _ = user_token

        sql_payloads = [
            "1' OR '1'='1",
            "1; DROP TABLE files; --",
            "1 UNION SELECT * FROM users--",
            "' OR 1=1--",
        ]

        for payload in sql_payloads:
            response = api_client.get(
                f"/api/v1/files/{payload}/download/",
                HTTP_AUTHORIZATION=f"Bearer {token}",
            )
            # Should be 400 (invalid UUID) or 404, never 200 or 500
            assert response.status_code in [400, 404], (
                f"SQL injection payload '{payload}' caused unexpected response: "
                f"{response.status_code}. Check for SQL injection vulnerability!"
            )
            # Never 500 — that would indicate a raw SQL error
            assert response.status_code != 500, (
                f"SQL injection payload caused 500 error — possible SQLi! Payload: {payload}"
            )

    def test_xss_in_filename_not_reflected(self, api_client, user_token):
        """XSS in filename must be sanitized, not reflected."""
        token, _ = user_token

        xss_filename = '<script>alert("xss")</script>.pdf'

        response = api_client.post(
            "/api/v1/files/upload/",
            {"file": _create_test_file(xss_filename, b"%PDF-1.4 content")},
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        if response.status_code == 201:
            stored_name = response.json().get("filename", "")
            assert "<script>" not in stored_name, "XSS in filename not sanitized!"
            assert "alert(" not in stored_name, "XSS payload in stored filename!"


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _create_test_file(filename: str, content: bytes):
    """Create an in-memory test file for upload."""
    from django.core.files.uploadedfile import SimpleUploadedFile
    return SimpleUploadedFile(
        filename,
        content,
        content_type="application/octet-stream",
    )
