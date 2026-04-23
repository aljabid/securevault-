# Changelog

All notable changes to SecureVault are documented in this file following [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) conventions.

**Format:** `[Version] — Date — Phase`  
**Classification:** Internal / Confidential

---

## [v5.0.0-final] — 2025-01-31 — Phase 5: Final Compilation

### Added
- Full Secure SDLC Report compiled (executive summary through appendices)
- Pentest Audit Report finalized with CVSS-scored findings and remediation roadmap
- Defense presentation slide deck (12 slides, live demo script)
- HTML and PDF versions of all reports with consistent styling
- Repository tagged and all deliverables verified

### Security
- All Critical and High findings from pentest remediated and verified
- Final compliance mapping table published
- SECURITY.md responsible disclosure policy activated

---

## [v4.0.0-pentest] — 2025-01-24 — Phase 4: Security Testing & Penetration Testing

### Added
- SAST: Bandit, Semgrep, SonarQube, Safety, Trufflehog scans executed
- DAST: OWASP ZAP active scan, Nikto, Burp Suite Pro manual testing
- Penetration test: full PTES/OWASP Testing Guide methodology
- Evidence collected: PT-001 through PT-012 (12 findings)
- CVSS 3.1 scoring applied to all findings
- Remediation documentation with code-level fixes

### Security Findings Summary
- Critical: 0 (after remediation)
- High: 2 (JWT algorithm confusion, IDOR on file IDs) — remediated
- Medium: 5 — remediated
- Low: 4 — accepted with documented residual risk
- Informational: 1

### Changed
- JWT validation hardened to reject `none` algorithm
- File access control IDOR patched with ownership check
- Rate limiting thresholds tuned based on testing

---

## [v3.0.0-implementation] — 2025-01-17 — Phase 3: Secure Implementation

### Added
- Django REST API with full authentication stack (OAuth2, JWT, MFA)
- File upload pipeline: validation → ClamAV → MinIO → pre-signed URLs
- RBAC: 5-tier role system (guest/user/moderator/admin/superadmin)
- React + TypeScript frontend with strict CSP and DOMPurify
- Argon2id password hashing (time=2, memory=65536)
- Audit logging middleware (every auth event, file access, permission change)
- Rate limiting: sliding window per-IP and per-user
- CSRF: double-submit cookie + SameSite=Strict
- Pre-commit hooks: Bandit (Python) + eslint-plugin-security (JS)
- Secure Coding Guidelines document published

### Security
- Server-side MIME magic byte validation for all uploads
- EXIF metadata stripping from images
- Parameterized queries everywhere (Django ORM only, no raw SQL)
- AES-256-GCM encryption for sensitive fields at application layer
- Vault/KMS integration for key management

---

## [v2.0.0-design] — 2025-01-10 — Phase 2: Secure Software Design

### Added
- Security Architecture Document (C4 diagrams Levels 1–3)
- Data Flow Diagram (DFD Level 0 and Level 1) with trust boundaries
- Authentication architecture: OAuth2 PKCE, JWT RS256, TOTP/WebAuthn
- Session architecture: HttpOnly + SameSite=Strict cookies, IP-bound refresh tokens
- Secure data storage design: Argon2id, AES-256-GCM, secrets manager
- TLS 1.3 enforcement design with HSTS preload specification
- GDPR compliance requirements documented
- ISO 27001 / NIST CSF control mapping table
- Architecture Decision Records (ADRs) for all major security choices

---

## [v1.0.0-risk-report] — 2025-01-03 — Phase 1: Risk Analysis & Threat Modeling

### Added
- Formal scope definition: secure file-sharing platform, cloud-hosted, containerized
- Asset inventory with CIA scoring (primary and supporting assets)
- Threat modeling: STRIDE model applied systematically, MITRE ATT&CK for Web mapped
- Vulnerability assessment: OWASP Top 10 (2021), CWE identifiers assigned
- Risk register: 18 risks scored (Likelihood × Impact), 5×5 matrix
- Risk scoring: CVSS 3.1 Base Score applied as secondary mechanism
- Control mapping: OWASP, ISO 27001 Annex A, NIST CSF, CIS Controls v8
- Risk treatment decisions: Mitigate / Accept / Transfer / Avoid per risk
- Deliverables: Risk Analysis Report (PDF), risk register (XLSX), threat model diagram

### Risk Summary (Phase 1)
| Severity | Count |
|---|---|
| Critical (≥20) | 3 |
| High (15–19) | 5 |
| Medium (8–14) | 7 |
| Low (1–7) | 3 |
