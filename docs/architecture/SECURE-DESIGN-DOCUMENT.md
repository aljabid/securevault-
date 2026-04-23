# Secure SDLC Design Document — SecureVault

**Document ID:** SVP-ARCH-001  
**Version:** v2.0.0  
**Classification:** Confidential — Internal Use Only  
**Date:** 2025-01-10  
**Status:** Approved

---

## Table of Contents

1. Executive Summary
2. System Architecture (C4 Model)
3. Data Flow Diagrams
4. Security-by-Design Principles
5. Authentication & Session Architecture
6. Secure Data Storage Design
7. Secure Communication Design
8. Logging, Monitoring & Alerting
9. Compliance Requirements
10. Architecture Decision Records (ADRs)
11. Security Requirements Specification
12. Data Classification Matrix

---

## 1. Executive Summary

This document defines the complete security architecture for SecureVault. It serves as the binding reference for all implementation decisions, mapping each security requirement to a specific technical control. All security requirements derived from the Phase 1 Risk Analysis Report (SVP-RA-001) are addressed.

**Architecture Style:** Modular monolith with async task processing (Celery)  
**Deployment:** Containerized (Docker), cloud-hosted (AWS/GCP)  
**Primary Language:** Python 3.12 (Django REST Framework)  
**Frontend:** React 18 + TypeScript  

---

## 2. System Architecture (C4 Model)

### 2.1 C4 Level 1 — System Context

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         INTERNET (Untrusted)                            │
│                                                                         │
│   [End User Browser]    [Mobile App]    [API Clients]                   │
└──────────────┬───────────────────────────────────────────────────────────┘
               │ HTTPS (TLS 1.3 only)
               ▼
┌─────────────────────────────────────┐
│   Cloudflare WAF / CDN              │  ← DDoS protection, IP allowlist
│   (Edge Security Layer)             │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│   SECUREVAULT SYSTEM                │
│   (Secure File-Sharing Platform)    │
│                                     │
│  - User registration & auth         │
│  - Encrypted file storage           │
│  - Role-based access control        │
│  - Full audit trail                 │
└──────────────┬──────────────────────┘
               │
   ┌───────────┴───────────┐
   ▼                       ▼
[Identity Provider]   [Email Service]
(Google OAuth2)       (SMTP / SES)
```

### 2.2 C4 Level 2 — Container Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                        SECUREVAULT SYSTEM                            │
│                                                                      │
│  ┌─────────────┐    ┌──────────────────┐    ┌───────────────────┐  │
│  │   NGINX     │    │  React Frontend  │    │   Django API      │  │
│  │  (Reverse   │───▶│  (React 18 +     │    │  (Python 3.12 +   │  │
│  │   Proxy)    │    │   TypeScript)    │    │   DRF)            │  │
│  │  TLS 1.3    │    │  Port 3000       │    │  Port 8000        │  │
│  │  HSTS       │    └──────────────────┘    └────────┬──────────┘  │
│  │  CSP        │                                      │             │
│  └─────────────┘                           ┌──────────┴──────────┐ │
│                                            │                      │ │
│                          ┌─────────────────▼┐  ┌────────────────▼┐│
│                          │   PostgreSQL 16   │  │  Redis 7        ││
│                          │  (Primary DB,     │  │  (Sessions,     ││
│                          │   encrypted)      │  │   cache, rate   ││
│                          └───────────────────┘  │   limiting)     ││
│                                                 └─────────────────┘│
│                          ┌────────────────────┐                    │
│                          │   MinIO / S3       │                    │
│                          │  (Object Storage,  │                    │
│                          │   private ACL)     │                    │
│                          └────────────────────┘                    │
│                                                                      │
│  ┌─────────────┐    ┌──────────────────┐    ┌───────────────────┐  │
│  │  Celery     │    │   ClamAV         │    │  Elasticsearch +  │  │
│  │  Workers    │    │  (Antivirus)     │    │  Kibana (SIEM)    │  │
│  │  (Async     │    │  Port 3310       │    │  Port 9200/5601   │  │
│  │   tasks)    │    └──────────────────┘    └───────────────────┘  │
│  └─────────────┘                                                    │
│                          ┌────────────────────┐                    │
│                          │  HashiCorp Vault   │                    │
│                          │  (Secrets Manager) │                    │
│                          └────────────────────┘                    │
└──────────────────────────────────────────────────────────────────────┘
```

### 2.3 C4 Level 3 — Auth Service Components

```
AUTH SERVICE (Django apps: auth/)
├── OAuthProvider          — OAuth2 PKCE authorization code flow
├── JWTManager             — RS256 token issuance, validation, refresh
├── TOTPVerifier           — RFC 6238 TOTP validation
├── WebAuthnHandler        — FIDO2/WebAuthn registration and assertion
├── SessionManager         — Redis-backed session store
├── LockoutManager         — Account lockout + exponential backoff
└── RBACMiddleware         — Role/permission enforcement decorator
```

---

## 3. Data Flow Diagrams

### 3.1 DFD Level 0 — System Overview

```
[User] ──upload──▶ [SecureVault System] ──store──▶ [Object Storage]
[User] ◀─download── [SecureVault System] ◀─retrieve── [Object Storage]
[User] ──auth──▶ [SecureVault System] ──verify──▶ [Identity Provider]
[SecureVault] ──logs──▶ [SIEM / Elasticsearch]
```

### 3.2 DFD Level 1 — File Upload Flow

```
[Browser]
   │ 1. POST /api/v1/files/upload (multipart)
   │    Headers: Authorization: Bearer <JWT>
   │             X-CSRF-Token: <token>
   ▼
[NGINX] — TLS termination, rate limiting (50 req/min)
   │
   ▼
[API Gateway Middleware]
   │ 2. JWT validation (RS256, expiry, claims)
   │ 3. CSRF token validation
   │ 4. Rate limit check (Redis)
   │ 5. Request size check (max 50MB)
   ▼
[FileUploadView]
   │ 6. Input validation (extension whitelist)
   │ 7. MIME type check (magic bytes)
   │ 8. Filename sanitization
   ▼
[Celery Worker — async]
   │ 9. ClamAV virus scan
   │ 10. EXIF metadata stripping (images)
   │ 11. File encryption (AES-256-GCM at app layer)
   ▼
[MinIO / S3]
   │ 12. Store with private ACL
   │ 13. Record metadata in PostgreSQL
   ▼
[Audit Logger]
   │ 14. Log: user_id, file_id, timestamp, IP, action=upload, outcome=success
   ▼
[Elasticsearch SIEM]

[Browser] ◀── 15. Return: { file_id, presigned_url (5min expiry) }
```

---

## 4. Security-by-Design Principles

### 4.1 Least Privilege
- Each DB service account: read/write only to its own schema, no DDL permissions
- Users: can only access files they own or have been explicitly shared with
- Celery workers: no DB write access except to task result backend
- NGINX: runs as non-root user (uid 101)

### 4.2 Defense in Depth
```
Layer 1: Cloudflare WAF        — block known malicious IPs, DDoS
Layer 2: NGINX                 — TLS termination, rate limiting, CSP headers
Layer 3: API Gateway           — JWT validation, CSRF, request size
Layer 4: Input Validation      — whitelist-based, every endpoint
Layer 5: Django ORM            — parameterized queries prevent SQLi
Layer 6: RBAC Middleware       — enforce permissions before business logic
Layer 7: Encrypted Storage     — AES-256-GCM for sensitive fields
Layer 8: ClamAV                — virus scanning before storage
```

### 4.3 Secure Defaults
- New accounts: locked until email verification complete
- File uploads: rejected unless extension is explicitly whitelisted
- API endpoints: unauthenticated by default (opt-in `@allow_public`)
- Cookie flags: HttpOnly + Secure + SameSite=Strict by default
- DEBUG: False by default, only enable via explicit ENV variable

### 4.4 Fail-Safe Defaults
- Any unhandled exception → HTTP 500 with generic message, no stack trace
- Full exception details logged server-side only
- Auth failure → HTTP 401 with generic "Invalid credentials" (no username enumeration)
- File scan failure → reject upload, do not store

---

## 5. Authentication & Session Architecture

### 5.1 OAuth2 Authorization Code Flow with PKCE

```
1. Client generates: code_verifier (43–128 chars, random)
                     code_challenge = BASE64URL(SHA256(code_verifier))

2. GET /oauth/authorize?
      response_type=code
      &client_id=...
      &redirect_uri=...
      &scope=openid profile email
      &state=<random 32 bytes>
      &code_challenge=<hash>
      &code_challenge_method=S256

3. User authenticates with Identity Provider

4. IdP redirects to: /callback?code=<auth_code>&state=<verified>

5. POST /oauth/token with code + code_verifier → access_token + refresh_token

6. Access token stored in memory (JavaScript variable, not localStorage)
7. Refresh token stored in HttpOnly + Secure + SameSite=Strict cookie
```

### 5.2 JWT Architecture

```
Access Token:
  Algorithm: RS256 (asymmetric — private key on server, public key for verification)
  Expiry: 15 minutes
  Claims: {
    sub: user_id (UUID),
    email: user_email,
    role: user_role,          ← validated server-side, not trusted from client
    session_id: session_uuid,
    iat: issued_at,
    exp: expiry,
    jti: token_id             ← for revocation/blocklist
  }
  Storage: JavaScript memory only (never localStorage, sessionStorage, or cookie)

Refresh Token:
  Algorithm: RS256
  Expiry: 7 days
  Storage: HttpOnly + Secure + SameSite=Strict cookie
  Rotation: New refresh token issued on every use (old immediately invalidated)
  Binding: IP address + User-Agent fingerprint stored in Redis
```

### 5.3 MFA

```
TOTP (RFC 6238):
  - 6-digit code, 30-second interval
  - Issuer: "SecureVault"
  - Secret: 160-bit random (stored encrypted in DB via AES-256-GCM + Vault key)
  - Backup codes: 8 × 8-char alphanumeric (one-time use, stored as Argon2id hashes)

WebAuthn (FIDO2):
  - RP ID: domain name
  - User verification: required
  - Attestation: indirect
  - Authenticator attachment: platform or cross-platform
```

### 5.4 Account Lockout

```python
# Pseudocode
MAX_ATTEMPTS = 5
LOCKOUT_DURATION = 900  # 15 minutes base

def calculate_lockout(attempt_count):
    if attempt_count < MAX_ATTEMPTS:
        return None
    multiplier = 2 ** (attempt_count - MAX_ATTEMPTS)
    return min(LOCKOUT_DURATION * multiplier, 86400)  # max 24 hours
```

---

## 6. Secure Data Storage Design

### 6.1 Password Hashing

```
Algorithm: Argon2id (winner of Password Hashing Competition)
Parameters:
  - time_cost: 2 (iterations)
  - memory_cost: 65536 (64 MB)
  - parallelism: 1
  - hash_len: 32 bytes
  - salt: 16 bytes (cryptographically random, per-password)
```

### 6.2 Sensitive Field Encryption

```
Fields encrypted at application layer before DB write:
  - SSN / National ID
  - Phone number
  - Recovery email

Algorithm: AES-256-GCM
  - Key: 256-bit, stored in HashiCorp Vault / AWS KMS
  - IV: 96-bit random, per-encryption
  - Authentication tag: 128-bit (prevents tampering)
  - Stored format: base64(iv || ciphertext || tag)
```

### 6.3 Database Security

```
- Full-disk encryption: AWS RDS encryption or LUKS
- Connection: SSL/TLS required (verify-full mode)
- User: separate DB user per service with minimal permissions
- Backup: AES-256-GCM encrypted, versioned S3, 90-day retention
- Backup access: separate IAM role with MFA requirement
```

---

## 7. Secure Communication Design

### 7.1 TLS Configuration (nginx.conf)

```nginx
ssl_protocols TLSv1.3;          # TLS 1.0/1.1/1.2 disabled
ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
ssl_prefer_server_ciphers off;  # Let client choose (TLS 1.3)
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;        # Forward secrecy
```

### 7.2 Security Headers

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
Content-Security-Policy: default-src 'none'; script-src 'nonce-{RANDOM}'; 
  style-src 'nonce-{RANDOM}'; img-src 'self' data:; connect-src 'self';
  font-src 'self'; object-src 'none'; frame-ancestors 'none';
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
```

---

## 8. Logging, Monitoring & Alerting

### 8.1 Audit Log Schema

```json
{
  "timestamp": "2025-01-10T14:23:45.123Z",
  "event_id": "uuid-v4",
  "user_id": "uuid-v4 or null",
  "session_id": "uuid-v4",
  "ip_address": "203.0.113.42",
  "user_agent": "Mozilla/5.0 ...",
  "action": "file.download",
  "resource_type": "file",
  "resource_id": "uuid-v4",
  "outcome": "success",
  "details": {},
  "risk_score": 0
}
```

### 8.2 Monitored Events

All of the following are logged unconditionally:
- Authentication: login success/failure, logout, MFA pass/fail, password change
- Authorization: permission check failure, admin endpoint access
- File events: upload, download, delete, share, access denied
- Account: registration, email verification, lockout, unlock
- Admin: any admin panel action, user role change
- System: config change, service start/stop

### 8.3 Alert Rules

| Alert | Condition | Severity | Response |
|---|---|---|---|
| Brute force | >10 failed logins in 60s from same IP | Critical | Auto-block IP |
| Admin abuse | Admin endpoint from non-admin role | Critical | Immediate alert + lock |
| Data exfiltration | >50 file downloads in 5 min by one user | High | Throttle + alert |
| Anomalous login | Login from new country/device | Medium | Email user |
| Dependency CVE | New CVE in dependency | High | Ticket + patch |

---

## 9. Compliance Requirements

### 9.1 GDPR
- **Data minimization:** Collect only fields necessary for the service
- **Right to erasure:** `DELETE /api/v1/users/{id}` cascades to all user data + files
- **Data Portability:** `GET /api/v1/users/{id}/export` returns JSON archive
- **DPA:** Data Processing Agreement template in `/docs/compliance/DPA.md`
- **No PII in logs:** User ID (UUID) logged, never email or name directly

### 9.2 ISO/IEC 27001:2022

| Control | Implementation |
|---|---|
| A.5.9 Inventory of assets | Asset inventory in `/docs/risk-analysis/` |
| A.5.15 Access control | RBAC system, DB-stored permissions |
| A.5.24 Incident management | Incident Response Procedure in `/docs/compliance/` |
| A.8.7 Protection against malware | ClamAV, dependency scanning |
| A.8.9 Configuration management | IaC in `/infra/`, ENV-based config |
| A.8.12 Data leakage prevention | Encryption at rest and in transit |
| A.8.16 Monitoring | Elasticsearch SIEM, Kibana dashboards |
| A.8.24 Use of cryptography | Policy in `/docs/security/` |

---

## 10. Architecture Decision Records (ADRs)

### ADR-001: Django over Node.js for Backend
**Status:** Accepted  
**Context:** Choose backend framework  
**Decision:** Django REST Framework (Python)  
**Rationale:** Django ORM prevents SQLi by default; battle-tested auth; comprehensive security middleware ecosystem; cleaner permission model via decorators  
**Consequences:** Slightly lower raw performance, mitigated by async Celery for heavy operations

### ADR-002: RS256 for JWT Signing
**Status:** Accepted  
**Context:** Choose JWT signing algorithm  
**Decision:** RS256 (RSA + SHA-256, asymmetric)  
**Rationale:** Private key signs tokens on server; public key can be distributed for verification; prevents algorithm confusion attacks; keys can be rotated without breaking existing tokens  
**Consequences:** Slightly larger token size; key rotation procedure required

### ADR-003: Argon2id for Password Hashing
**Status:** Accepted  
**Context:** Choose password hashing algorithm  
**Decision:** Argon2id (PHC winner, time=2, memory=65536)  
**Rationale:** Best resistance against GPU/ASIC attacks; memory-hard; PHC winner; recommended by OWASP  
**Consequences:** Higher CPU/memory per auth operation; mitigated by parameters tuning

### ADR-004: Pre-signed URLs for File Access
**Status:** Accepted  
**Context:** How to serve stored files securely  
**Decision:** Pre-signed URLs with 5-minute expiry  
**Rationale:** Files never exposed via public URL; access controlled at storage layer; URL expiry limits blast radius of URL leakage  
**Consequences:** Short-lived URLs require re-auth for long-lived access; acceptable UX tradeoff

### ADR-005: MinIO over AWS S3 (default)
**Status:** Accepted with condition  
**Context:** Object storage choice  
**Decision:** MinIO for self-hosted, AWS S3 supported via ENV flag  
**Rationale:** Vendor independence; S3-compatible API; data sovereignty for EU clients; AWS S3 supported for cloud deployments  
**Consequences:** Operational overhead for MinIO; S3 requires AWS account

---

## 11. Security Requirements Specification

| Req ID | Category | Requirement | Priority | Verification |
|---|---|---|---|---|
| SR-001 | Auth | All passwords must be hashed with Argon2id (time≥2, mem≥65536) | Critical | Unit test |
| SR-002 | Auth | JWT must use RS256; `none` algorithm must be rejected | Critical | Pentest |
| SR-003 | Auth | MFA must be enforced for admin accounts | Critical | Integration test |
| SR-004 | Auth | Account locked after 5 failed attempts | High | Unit test |
| SR-005 | Access | Every file access must verify ownership/permission server-side | Critical | Pentest (IDOR) |
| SR-006 | Access | Roles stored in DB; not trusted from JWT claims alone | Critical | Code review |
| SR-007 | Data | Sensitive fields encrypted with AES-256-GCM before DB write | High | Code review |
| SR-008 | Data | TLS 1.3 only; downgrade to TLS 1.2 must be rejected | Critical | testssl.sh |
| SR-009 | Files | All uploads scanned with ClamAV before storage | Critical | Integration test |
| SR-010 | Files | MIME type validated via magic bytes, not extension | Critical | Unit test |
| SR-011 | Files | EXIF metadata stripped from all images before storage | Medium | Unit test |
| SR-012 | Files | File size limited to 50MB server-side | High | Integration test |
| SR-013 | Transport | HSTS header with preload, max-age=31536000 | High | Manual check |
| SR-014 | Transport | CSP header with nonce-based script policy | High | ZAP scan |
| SR-015 | Logging | Every auth event logged with: timestamp, user_id, IP, outcome | Critical | Audit test |
| SR-016 | Logging | No PII (email, name) in log entries | High | Log review |
| SR-017 | Input | All inputs validated server-side with whitelist approach | Critical | SAST + pentest |
| SR-018 | Input | No raw SQL; ORM only | Critical | SAST (Bandit) |
| SR-019 | Rate | Rate limiting on login (5/min per IP) | High | Load test |
| SR-020 | GDPR | Right to erasure endpoint returns 200 within 30 days | High | Integration test |

---

## 12. Data Classification Matrix

| Data Type | Classification | Encryption at Rest | Encryption in Transit | Retention | Access |
|---|---|---|---|---|---|
| User files | **Restricted** | AES-256-GCM | TLS 1.3 | User-defined | Owner + explicit shares |
| Passwords (hash) | **Restricted** | Argon2id | TLS 1.3 | Lifetime | Auth service only |
| JWT private key | **Top Secret** | Vault-managed | N/A | Key rotation | Auth service only |
| PII (email, name) | **Confidential** | DB encryption | TLS 1.3 | Account lifetime | Owner + admin |
| Sensitive fields (SSN) | **Restricted** | AES-256-GCM | TLS 1.3 | Minimum required | Owner only |
| Audit logs | **Confidential** | Elasticsearch TLS | TLS 1.3 | 1 year | Security team |
| Session tokens | **Restricted** | Redis encryption | TLS 1.3 | 7 days max | Auth service |
| Encryption keys | **Top Secret** | Vault | N/A | Key rotation | Key service only |
| Metadata (file names) | **Internal** | DB encryption | TLS 1.3 | With file | Owner |
| System logs | **Internal** | Disk encryption | TLS 1.3 | 90 days | Ops team |
