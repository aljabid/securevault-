# Compliance Mapping — SecureVault

**Document ID:** SVP-COMP-001  
**Version:** v5.0.0  
**Classification:** Confidential  
**Date:** 2025-01-31

---

## 1. GDPR Compliance

### Article Mapping

| Article | Requirement | Implementation | Status |
|---|---|---|---|
| Art. 5 | Data minimisation | Collect only fields required for service operation | ✅ |
| Art. 6 | Lawful basis | Consent captured at registration; contract basis for core service | ✅ |
| Art. 13/14 | Privacy notice | Privacy policy at /privacy with data categories, retention periods | ✅ |
| Art. 17 | Right to erasure | `DELETE /api/v1/users/{id}` cascades to all user data + files | ✅ |
| Art. 20 | Data portability | `GET /api/v1/users/{id}/export` returns JSON/ZIP archive within 30 days | ✅ |
| Art. 25 | Privacy by design | Encryption at rest and in transit; minimal data collection; audit logs | ✅ |
| Art. 30 | Records of processing | Data Processing Register maintained in `/docs/compliance/DPA.md` | ✅ |
| Art. 32 | Security measures | Argon2id, AES-256-GCM, TLS 1.3, RBAC, audit logging | ✅ |
| Art. 33 | Breach notification | Incident Response Procedure; 72h CNIL notification process documented | ✅ |
| Art. 35 | DPIA | Data Protection Impact Assessment completed for file processing pipeline | ✅ |

### Technical Measures

| Measure | Control | Location |
|---|---|---|
| Pseudonymisation | User IDs (UUID) in logs; no email/name in audit trail | `middleware/audit_logger.py` |
| Encryption at rest | AES-256-GCM for sensitive fields; DB encryption | `utils/crypto.py`, PostgreSQL config |
| Encryption in transit | TLS 1.3 only | `infra/nginx/nginx.conf` |
| Access control | RBAC with least privilege | `auth/rbac.py` |
| Integrity verification | SHA-256 hash stored per file | `files/views.py` |
| Availability | Redis caching, health checks, backup policy | `infra/docker/docker-compose.yml` |

---

## 2. ISO/IEC 27001:2022 — Annex A Control Mapping

### A.5 — Organisational Controls

| Control | Title | Implementation | Evidence |
|---|---|---|---|
| A.5.9 | Inventory of assets | Asset register in risk analysis report | `docs/risk-analysis/RISK-ANALYSIS-REPORT.md` |
| A.5.10 | Acceptable use of assets | Acceptable Use Policy document | `docs/compliance/AUP.md` |
| A.5.12 | Classification of information | Data classification matrix | `docs/architecture/SECURE-DESIGN-DOCUMENT.md §12` |
| A.5.14 | Information transfer | TLS 1.3, CORS policy, secure cookies | `infra/nginx/nginx.conf` |
| A.5.15 | Access control | RBAC, DB-stored permissions, least privilege | `src/backend/auth/rbac.py` |
| A.5.16 | Identity management | UUID-based user IDs, email verification | `src/backend/auth/` |
| A.5.17 | Authentication information | Argon2id, MFA enforced for admins | `src/backend/core/settings.py` |
| A.5.24 | Information security incident management | Incident Response Procedure | `docs/compliance/IRP.md` |

### A.8 — Technological Controls

| Control | Title | Implementation | Evidence |
|---|---|---|---|
| A.8.2 | Privileged access rights | Admin role requires MFA; restricted endpoints | `src/backend/auth/rbac.py` |
| A.8.3 | Information access restriction | RBAC, ownership checks, pre-signed URLs | `src/backend/files/views.py` |
| A.8.5 | Secure authentication | OAuth2 PKCE, JWT RS256, TOTP, WebAuthn | `src/backend/auth/views.py` |
| A.8.6 | Capacity management | Rate limiting, max file size, Celery worker limits | `src/backend/core/settings.py` |
| A.8.7 | Protection against malware | ClamAV scanning on all uploads | `src/backend/files/clamav.py` |
| A.8.8 | Management of technical vulnerabilities | Dependabot, weekly `safety check`, SAST in CI | `.pre-commit-config.yaml` |
| A.8.9 | Configuration management | ENV-based config, IaC in `/infra/`, no hardcoded secrets | `.env.example` |
| A.8.10 | Information deletion | Right to erasure endpoint + cascade delete | `src/backend/api/` |
| A.8.12 | Data leakage prevention | Encryption at rest + transit, private S3 ACL | `infra/` |
| A.8.15 | Logging | Structured audit logs shipped to Elasticsearch SIEM | `src/backend/middleware/audit_logger.py` |
| A.8.16 | Monitoring activities | Kibana dashboards, alert rules for anomalies | `infra/docker/docker-compose.yml` |
| A.8.20 | Networks security | Internal Docker network not routable to internet | `infra/docker/docker-compose.yml` |
| A.8.21 | Security of network services | TLS 1.3, WAF, rate limiting | `infra/nginx/nginx.conf` |
| A.8.24 | Use of cryptography | Argon2id, AES-256-GCM, RS256, TLS 1.3 | `docs/security/SECURE-CODING-GUIDELINES.md §5` |
| A.8.25 | Secure development lifecycle | Full SSDLC: risk analysis → design → implement → pentest | This repository |
| A.8.26 | Application security requirements | Security Requirements Specification | `docs/architecture/SECURE-DESIGN-DOCUMENT.md §11` |
| A.8.27 | Secure system architecture | C4 diagrams, DFDs, trust boundaries | `docs/architecture/` |
| A.8.28 | Secure coding | Secure Coding Guidelines, pre-commit SAST | `docs/security/SECURE-CODING-GUIDELINES.md` |
| A.8.29 | Security testing | SAST + DAST + penetration test | `pentest/` |
| A.8.34 | Protection of information systems during audit | Pentest on staging only; production unchanged | `pentest/reports/` |

---

## 3. NIST Cybersecurity Framework (CSF) Mapping

### IDENTIFY (ID)

| Function | Category | Control | Implementation |
|---|---|---|---|
| ID.AM | Asset Management | Asset inventory | `docs/risk-analysis/RISK-ANALYSIS-REPORT.md §4` |
| ID.RA | Risk Assessment | Full risk analysis (EBIOS + NIST SP 800-30) | `docs/risk-analysis/RISK-ANALYSIS-REPORT.md` |
| ID.SC | Supply Chain Risk | Dependency scanning, SBOM, Dependabot | `.github/workflows/security.yml` |

### PROTECT (PR)

| Function | Category | Control | Implementation |
|---|---|---|---|
| PR.AC | Identity Management | OAuth2, JWT, MFA, RBAC, account lockout | `src/backend/auth/` |
| PR.DS | Data Security | AES-256-GCM, TLS 1.3, Argon2id, private storage | `src/backend/utils/crypto.py` |
| PR.IP | Policies and Procedures | Secure Coding Guidelines, SSDLC process | `docs/security/` |
| PR.MA | Maintenance | Dependency updates, security patches | Dependabot config |
| PR.PT | Protective Technology | Firewall/WAF, rate limiting, NGINX hardening | `infra/nginx/nginx.conf` |

### DETECT (DE)

| Function | Category | Control | Implementation |
|---|---|---|---|
| DE.AE | Anomalies and Events | Alert rules in SIEM (brute force, privilege escalation) | `infra/docker/docker-compose.yml` |
| DE.CM | Security Continuous Monitoring | Elasticsearch + Kibana SIEM, health checks | `src/backend/middleware/audit_logger.py` |
| DE.DP | Detection Processes | Audit log on every auth/file/admin event | `src/backend/middleware/audit_logger.py` |

### RESPOND (RS)

| Function | Category | Control | Implementation |
|---|---|---|---|
| RS.AN | Analysis | Incident classification process | `docs/compliance/IRP.md` |
| RS.CO | Communications | Responsible disclosure policy, CNIL 72h notification | `SECURITY.md` |
| RS.MI | Mitigation | Account lockout, IP blocking, token revocation | `src/backend/auth/views.py` |

### RECOVER (RC)

| Function | Category | Control | Implementation |
|---|---|---|---|
| RC.RP | Recovery Planning | Business Continuity Plan summary | `docs/compliance/BCP.md` |
| RC.IM | Improvements | Lessons learned post-incident, CHANGELOG tracking | `CHANGELOG.md` |

---

## 4. CIS Controls v8 Mapping

| CIS Control | Title | Implementation |
|---|---|---|
| CIS-1 | Inventory of Assets | Asset register in risk report |
| CIS-2 | Inventory of Software Assets | SBOM, `requirements.txt`, `package-lock.json` |
| CIS-3 | Data Protection | Encryption at rest + transit, data classification |
| CIS-4 | Secure Configuration | NGINX hardening, Docker security options, ENV-based config |
| CIS-5 | Account Management | RBAC, MFA, account lockout, least privilege |
| CIS-6 | Access Control | IDOR checks, ownership verification, pre-signed URLs |
| CIS-7 | Continuous Vulnerability Management | Dependabot, weekly scans, pentest |
| CIS-8 | Audit Log Management | Elasticsearch SIEM, immutable audit trail |
| CIS-10 | Malware Defence | ClamAV, MIME validation, sandboxed processing |
| CIS-12 | Network Infrastructure Management | Docker internal networks, WAF, rate limiting |
| CIS-16 | Application Software Security | SAST, DAST, secure coding guidelines, pentest |
