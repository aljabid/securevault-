# Secure Coding Guidelines — SecureVault

**Document ID:** SVP-SCG-001  
**Version:** v3.0.0  
**Classification:** Internal — Engineering Team  
**Date:** 2025-01-17  
**Reference:** OWASP Secure Coding Practices Quick Reference Guide v2.0

---

## Table of Contents

1. General Principles
2. Input Validation
3. Authentication & Session Management
4. Access Control
5. Cryptography
6. Error Handling & Logging
7. File Handling
8. Database Security
9. API Security
10. Frontend Security (React/TypeScript)
11. Dependency Management
12. Pre-Commit Hooks & SAST
13. Forbidden Patterns
14. Code Review Security Checklist

---

## 1. General Principles

### Fail Securely
```python
# CORRECT — fail closed
def get_file(file_id, user):
    try:
        file = FileRecord.objects.get(id=file_id)
        if not verify_resource_ownership(file.owner_id, user):
            return None  # Deny on any uncertainty
        return file
    except Exception:
        return None  # Deny on error — never grant access on exception

# WRONG — fail open
def get_file_bad(file_id, user):
    try:
        file = FileRecord.objects.get(id=file_id)
        if not verify_resource_ownership(file.owner_id, user):
            return None
        return file
    except Exception:
        return file  # NEVER — could return unauthorized resource on DB error
```

### Least Privilege
```python
# CORRECT — each service account has minimal permissions
DB_USER_PERMISSIONS = {
    "api_service": ["SELECT", "INSERT", "UPDATE", "DELETE"],
    "celery_worker": ["SELECT", "INSERT", "UPDATE"],  # no DELETE
    "read_replica": ["SELECT"],
}

# WRONG — giving excessive permissions
# GRANT ALL ON ALL TABLES TO api_service;  # Never do this
```

### Defence in Depth
Every security check is applied at MULTIPLE layers — never rely on a single gate.

---

## 2. Input Validation

### Rule: Whitelist, Not Blacklist
```python
import re

# CORRECT — whitelist approach
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{3,32}$")

def validate_username(value: str) -> bool:
    """Only allow alphanumeric, underscore, hyphen. 3-32 chars."""
    return bool(USERNAME_PATTERN.match(value))

# WRONG — trying to block bad characters (always incomplete)
def validate_username_bad(value: str) -> bool:
    return "<" not in value and ">" not in value and "'" not in value  # Easily bypassed
```

### Rule: Validate on the Server — Always
```python
# CORRECT — server-side validation regardless of client validation
@api_view(["POST"])
def create_user(request):
    serializer = UserSerializer(data=request.data)
    if not serializer.is_valid():  # Server-side validation runs here
        return Response({"detail": "Invalid input."}, status=400)
    # Proceed only after validation passes
```

### Rule: Validate Type, Length, Format, Range
```python
from typing import Optional

def validate_file_size(size: int, max_bytes: int = 52_428_800) -> Optional[str]:
    if not isinstance(size, int):
        return "Size must be an integer."
    if size <= 0:
        return "Size must be positive."
    if size > max_bytes:
        return f"Size exceeds maximum ({max_bytes // 1_048_576}MB)."
    return None
```

### Rule: Sanitize Filenames
```python
import os
import re

def sanitize_filename(name: str) -> Optional[str]:
    if not name:
        return None
    name = os.path.basename(name)        # Strip path components
    name = name.replace("\x00", "")      # Strip null bytes
    name = re.sub(r"[^a-zA-Z0-9._\-]", "_", name)  # Whitelist chars
    name = name.strip(". ")              # Strip leading dots/spaces
    if not name or len(name) > 255:
        return None
    return name.lower()
```

---

## 3. Authentication & Session Management

### Rule: Use Argon2id for Passwords
```python
# Django settings — CORRECT
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",  # PRIMARY
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",  # Migration fallback only
]

# WRONG — never use these for passwords
import hashlib
hashlib.md5(password.encode()).hexdigest()    # FORBIDDEN
hashlib.sha1(password.encode()).hexdigest()   # FORBIDDEN
hashlib.sha256(password.encode()).hexdigest() # FORBIDDEN — no salt, fast hash
```

### Rule: Constant-Time Comparison for Secrets
```python
import hmac

# CORRECT — timing-safe comparison
def verify_token(provided: str, stored: str) -> bool:
    return hmac.compare_digest(provided.encode(), stored.encode())

# WRONG — timing oracle
def verify_token_bad(provided: str, stored: str) -> bool:
    return provided == stored  # Returns early on first mismatch — timing attack!
```

### Rule: Short JWT Expiry + Rotation
```python
# CORRECT — 15 minute access, 7 day refresh with rotation
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,       # New refresh token each use
    "BLACKLIST_AFTER_ROTATION": True,    # Old token immediately invalidated
    "ALGORITHM": "RS256",                # Asymmetric — never HS256 with shared key
}

# WRONG
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(days=30),   # Far too long
    "ALGORITHM": "none",                            # CRITICAL VULNERABILITY
}
```

### Rule: Never Store Tokens in localStorage
```typescript
// CORRECT — keep in memory; refresh token in HttpOnly cookie
let accessToken: string | null = null;

function setAccessToken(token: string) {
    accessToken = token;  // Memory only
}

// WRONG
localStorage.setItem("access_token", token);     // Accessible to XSS
sessionStorage.setItem("access_token", token);   // Accessible to XSS
document.cookie = `token=${token}`;              // Accessible if not HttpOnly
```

---

## 4. Access Control

### Rule: Verify Ownership Server-Side on EVERY Request
```python
# CORRECT — ownership check on every file access
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def download_file(request, file_id):
    file = FileRecord.objects.get(id=file_id)
    
    # THIS CHECK IS NON-NEGOTIABLE — prevents IDOR
    if not verify_resource_ownership(file.owner_id, request.user):
        return Response({"detail": "Not found."}, status=404)  # 404, not 403
    
    return generate_presigned_url(file)

# WRONG — trusting client-provided data
@api_view(["GET"])
def download_file_bad(request, file_id):
    # Never trust: request.data["user_id"] or request.GET["owner"]
    file = FileRecord.objects.get(id=file_id)
    return generate_presigned_url(file)  # No ownership check — IDOR vulnerability!
```

### Rule: Apply Permissions at Route Level (Not Business Logic)
```python
# CORRECT — decorator at the route, not inside the function
@api_view(["POST"])
@permission_classes([IsAuthenticated])
@require_permission(Permission.ADMIN_PANEL)  # Route-level enforcement
def admin_endpoint(request):
    # Business logic here — no need to check permissions again
    ...

# WRONG — permission check buried in business logic
@api_view(["POST"])
def admin_endpoint_bad(request):
    # Easily forgotten, bypassed, or applied inconsistently
    if request.user.role == "admin":
        ...
```

### Rule: Use DB-Stored Roles, Not JWT Claims for Authorization
```python
# CORRECT — always query DB for authoritative role
def get_user_role(user) -> Role:
    # DB is the source of truth; JWT claim is only used for identification
    return Role(user.profile.role_int)

# WRONG — trusting JWT claim directly
def get_user_role_bad(request) -> str:
    return request.auth.get("role", "user")  # JWT claim can be forged/stale!
```

---

## 5. Cryptography

### Rule: Use Approved Algorithms Only

| Purpose | APPROVED | FORBIDDEN |
|---|---|---|
| Password hashing | Argon2id | MD5, SHA1, SHA256, bcrypt (weak params) |
| Symmetric encryption | AES-256-GCM | DES, 3DES, RC4, AES-CBC without HMAC |
| Asymmetric | RSA-4096, ECDSA P-384 | RSA <2048, DSA |
| JWT signing | RS256, ES256 | HS256 (shared secret), `none` |
| TLS | TLS 1.3 | TLS 1.0, 1.1, 1.2, SSLv3 |
| Hashing (non-password) | SHA-256, SHA-3 | MD5, SHA1 |

### Rule: Use Cryptographically Secure Random
```python
import secrets

# CORRECT
token = secrets.token_urlsafe(32)          # 256 bits of entropy
nonce = secrets.token_bytes(16)            # 128-bit nonce

# WRONG
import random
token = str(random.random())               # Not cryptographically random
token = str(uuid.uuid4())                  # UUID4 is NOT a secure token
```

### Rule: AES-256-GCM for Sensitive Field Encryption
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt_field(plaintext: str, key: bytes) -> str:
    """Encrypt sensitive DB field. Key from Vault/KMS."""
    assert len(key) == 32, "Key must be 256 bits"
    nonce = os.urandom(12)                 # 96-bit random nonce, unique per message
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    import base64
    return base64.b64encode(nonce + ciphertext).decode()

def decrypt_field(encoded: str, key: bytes) -> str:
    import base64
    data = base64.b64decode(encoded)
    nonce, ciphertext = data[:12], data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode()

# WRONG — NEVER implement custom crypto
def encrypt_bad(plaintext: str, key: str) -> str:
    return "".join(chr(ord(c) ^ ord(k)) for c, k in zip(plaintext, key * 100))  # XOR is NOT encryption!
```

---

## 6. Error Handling & Logging

### Rule: Generic Errors to Client, Full Details to Logs
```python
import logging
logger = logging.getLogger("securevault.audit")

# CORRECT
def process_file(file_id):
    try:
        _do_processing(file_id)
    except SpecificError as e:
        logger.error("file.processing_failed", extra={"file_id": file_id, "error": str(e)})
        return Response({"detail": "Processing failed. Please try again."}, status=500)
    except Exception as e:
        logger.critical("file.unexpected_error", extra={"file_id": file_id, "error": str(e)}, exc_info=True)
        return Response({"detail": "An error occurred."}, status=500)  # No stack trace to client

# WRONG
def process_file_bad(file_id):
    try:
        _do_processing(file_id)
    except Exception as e:
        return Response({"error": str(e), "traceback": traceback.format_exc()}, status=500)
        # Exposes: file paths, library versions, internal logic, DB schema
```

### Rule: No PII in Logs
```python
# CORRECT — log user_id (UUID), never email/name directly
logger.info("auth.login.success", extra={"user_id": str(user.id), "ip": ip_hash})

# WRONG
logger.info(f"User {user.email} logged in from {real_ip}")  # PII in logs violates GDPR
```

### Rule: Structured Logging — Always
```python
# CORRECT — structured, searchable in SIEM
audit_log.info(
    "file.upload.success",
    extra={
        "user_id": str(request.user.id),
        "file_id": file_id,
        "filename": safe_name,
        "size_bytes": file_size,
        "outcome": "success",
    }
)

# WRONG — unstructured string
print(f"User uploaded file {filename}")  # Not searchable, not structured
```

---

## 7. File Handling

### Rule: Validate MIME via Magic Bytes — Never Extension or Header
```python
# CORRECT — read first bytes and check signature
def get_real_mime(file_bytes: bytes) -> str:
    if file_bytes[:5] == b"%PDF-":
        return "application/pdf"
    if file_bytes[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    # ... etc

# WRONG — trusting Content-Type header or extension
content_type = request.headers.get("Content-Type")  # Client-controlled, never trust
mime = mimetypes.guess_type(filename)[0]             # Based on extension, not content
```

### Rule: Store Files Outside Webroot — Always
```python
# CORRECT — private bucket, no public URL ever
MINIO_BUCKET = "securevault-private-files"   # private ACL
# Access via pre-signed URLs with expiry

# WRONG — never serve uploaded files directly via URL
MEDIA_URL = "/uploads/"   # Uploaded files accessible at /uploads/malware.php!
```

### Rule: Scan Before Store — ClamAV
```python
# CORRECT — scan BEFORE writing to storage
scan_result = scan_file_with_clamav(file_bytes)
if not scan_result.is_clean:
    return Response({"detail": "File rejected."}, status=422)
# Only store if clean
storage.put_object(key, file_bytes)
```

### Rule: Strip EXIF Metadata from Images
```python
from PIL import Image
import io

def strip_exif(image_bytes: bytes) -> bytes:
    """Remove EXIF data that may contain GPS, device info, etc."""
    img = Image.open(io.BytesIO(image_bytes))
    output = io.BytesIO()
    # Save without EXIF
    img.save(output, format=img.format, exif=b"")
    return output.getvalue()
```

---

## 8. Database Security

### Rule: Parameterized Queries — Always (Django ORM)
```python
# CORRECT — Django ORM uses parameterized queries automatically
files = FileRecord.objects.filter(owner=user, id=file_id)

# Also CORRECT — explicit parameterized raw SQL (if ORM can't express it)
from django.db import connection
with connection.cursor() as cursor:
    cursor.execute("SELECT * FROM files WHERE owner_id = %s", [str(user.id)])

# WRONG — string interpolation in SQL (SQL Injection!)
with connection.cursor() as cursor:
    cursor.execute(f"SELECT * FROM files WHERE owner_id = '{user_id}'")  # NEVER
    cursor.execute("SELECT * FROM files WHERE name = '" + name + "'")    # NEVER
```

### Rule: Minimal DB Permissions
```sql
-- CORRECT — create restricted DB user for API
CREATE ROLE securevault_api LOGIN PASSWORD '...';
GRANT CONNECT ON DATABASE securevault_db TO securevault_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO securevault_api;
-- No GRANT CREATE, DROP, TRUNCATE, REFERENCES

-- Celery worker (no DELETE)
CREATE ROLE securevault_celery LOGIN PASSWORD '...';
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO securevault_celery;
```

---

## 9. API Security

### Rule: Deny by Default
```python
# CORRECT — authentication required on all views
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
}

# Explicitly allow public endpoints only
@permission_classes([AllowAny])  # Must be explicit opt-in
def public_endpoint(request):
    ...
```

### Rule: Rate Limit Every Endpoint
```python
# Login — strictest limit
@throttle_classes([LoginRateThrottle])   # 5 per minute per IP
def login(request): ...

# Upload — moderate limit
@throttle_classes([UploadRateThrottle]) # 10 per minute per user
def upload_file(request): ...

# API — standard limit
# Applied globally via DEFAULT_THROTTLE_CLASSES
```

### Rule: Validate & Sanitize All URL Parameters
```python
import uuid

# CORRECT — validate UUID format before DB query
def download_file(request, file_id: str):
    try:
        uuid.UUID(file_id)   # Raises ValueError if not valid UUID
    except ValueError:
        return Response({"detail": "Invalid identifier."}, status=400)
    # Safe to use file_id in query now
```

---

## 10. Frontend Security (React / TypeScript)

### Rule: DOMPurify for All User Content
```typescript
import DOMPurify from "dompurify";

// CORRECT — sanitize before rendering user content
const safeHTML = DOMPurify.sanitize(userContent, {
    ALLOWED_TAGS: ["p", "b", "i", "em", "strong", "a"],
    ALLOWED_ATTR: ["href"],
});
return <div dangerouslySetInnerHTML={{ __html: safeHTML }} />;

// WRONG — XSS vulnerability
return <div dangerouslySetInnerHTML={{ __html: userContent }} />;
```

### Rule: Attach CSRF Token to All Mutations
```typescript
import axios from "axios";

// CORRECT — axios interceptor attaches CSRF token automatically
axios.interceptors.request.use((config) => {
    if (["post", "put", "patch", "delete"].includes(config.method ?? "")) {
        const csrfToken = getCookie("csrftoken");
        if (csrfToken) {
            config.headers["X-CSRFToken"] = csrfToken;
        }
    }
    return config;
});
```

### Rule: Strict TypeScript — No `any`
```typescript
// CORRECT
interface FileRecord {
    id: string;
    filename: string;
    size: number;
    uploadedAt: string;
}

async function fetchFile(fileId: string): Promise<FileRecord> { ... }

// WRONG
async function fetchFile(fileId: any): Promise<any> { ... }  // No type safety
```

---

## 11. Dependency Management

### Rules
1. **Pin exact versions** in `requirements.txt` and `package-lock.json`
2. **Run `safety check`** (Python) and **`npm audit`** weekly in CI
3. **Review all new dependencies** — check: maintainer reputation, GitHub stars, last update, known CVEs
4. **Minimize dependencies** — every dependency is an attack surface
5. **Use Dependabot** for automated PR creation on vulnerable dependencies
6. **Generate SBOM** (Software Bill of Materials) per release

```bash
# Python — check for vulnerable packages
safety check --json -r requirements.txt

# Node.js — audit
npm audit --audit-level=moderate

# Python — detect secrets in code
trufflehog git file://. --only-verified

# Python — SAST scan
bandit -r src/ -ll -f json -o bandit-report.json

# JS — SAST scan
npx eslint src/ --plugin security --format json > eslint-security-report.json
```

---

## 12. Pre-Commit Hooks

`.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.6
    hooks:
      - id: bandit
        args: ["-ll", "-r", "src/backend/"]
        
  - repo: https://github.com/trufflesecurity/trufflehog
    rev: v3.67.0
    hooks:
      - id: trufflehog
        args: ["--only-verified"]
        
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
      - id: detect-private-key
      - id: check-merge-conflict
      - id: trailing-whitespace
      - id: end-of-file-fixer

  - repo: local
    hooks:
      - id: no-raw-sql
        name: No raw SQL strings
        language: pygrep
        entry: "cursor\.execute\(['\"]SELECT|cursor\.execute\(['\"]INSERT|cursor\.execute\(['\"]UPDATE"
        types: [python]
        
      - id: no-debug-true
        name: No DEBUG=True in settings
        language: pygrep
        entry: "DEBUG\s*=\s*True"
        types: [python]
```

---

## 13. Forbidden Patterns

The following patterns are **permanently banned** from the codebase. Any PR introducing them will be rejected.

### Python
```python
# FORBIDDEN — SQL string concatenation
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
cursor.execute(f"SELECT * FROM files WHERE name = '{filename}'")

# FORBIDDEN — eval/exec on user input
eval(user_input)
exec(request.data.get("code"))
__import__(module_name)

# FORBIDDEN — insecure deserialization
import pickle
pickle.loads(user_data)   # Remote code execution

# FORBIDDEN — weak hashing for security
import hashlib
hashlib.md5(password).hexdigest()
hashlib.sha1(secret).hexdigest()

# FORBIDDEN — hardcoded credentials
SECRET_KEY = "my-secret-key"
DB_PASSWORD = "password123"
API_KEY = "sk-abcdef..."

# FORBIDDEN — debug info to HTTP response
return Response({"traceback": traceback.format_exc()})
return Response({"error": str(exception), "file": __file__})
```

### TypeScript/JavaScript
```typescript
// FORBIDDEN — XSS via innerHTML
element.innerHTML = userContent;
document.write(userContent);
$(element).html(userContent);

// FORBIDDEN — token storage in localStorage
localStorage.setItem("token", accessToken);
sessionStorage.setItem("jwt", token);

// FORBIDDEN — eval with user data
eval(userInput);
new Function(userInput)();
setTimeout(userInput, 100);    // If userInput is a string

// FORBIDDEN — disabling TLS verification
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

// FORBIDDEN — hardcoded API keys in frontend
const API_KEY = "sk-prod-abcdef123";
```

---

## 14. Code Review Security Checklist

Every PR must pass this checklist before merge:

### Input & Validation
- [ ] All user inputs validated server-side with whitelist approach
- [ ] File uploads: extension + magic bytes + size + ClamAV
- [ ] No SQL string concatenation — ORM or parameterized queries only
- [ ] URL parameters validated (UUID format, type checks)

### Authentication & Authorization
- [ ] New endpoints: authentication required by default
- [ ] IDOR checks on every resource access (ownership verified)
- [ ] Role checks use DB-authoritative source (not JWT claims alone)
- [ ] No new endpoints without appropriate `@require_permission` decorator

### Cryptography & Secrets
- [ ] No hardcoded secrets, keys, or credentials
- [ ] No MD5/SHA1/SHA256 for password hashing or security tokens
- [ ] AES-256-GCM used for any new encrypted fields
- [ ] `secrets` module used for token/nonce generation (not `random`)

### Error Handling & Logging
- [ ] Exceptions caught, generic message to client, full detail to logger
- [ ] Audit log entry added for any new significant action
- [ ] No PII (email, name, IP) in log messages directly
- [ ] No stack traces in HTTP responses

### Frontend
- [ ] DOMPurify used for any user content rendered as HTML
- [ ] CSRF token attached to all mutating requests
- [ ] No token storage in localStorage/sessionStorage
- [ ] No `any` TypeScript types in security-critical code paths

### Dependencies
- [ ] No new dependencies added without review and approval
- [ ] `safety check` / `npm audit` passing with no high/critical CVEs
- [ ] New dependencies pinned to exact versions
