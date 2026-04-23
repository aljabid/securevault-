# SecureVault — Enterprise Secure File-Sharing Platform

> **Classification:** Internal / Confidential  
> **Version:** v5.0.0-final  
> **Maintainer:** SecureVault Security Engineering Team  
> **Last Updated:** 2025

---

## Overview

SecureVault is a production-grade, security-first file-sharing platform engineered for enterprises requiring verifiable confidentiality, integrity, and availability of sensitive documents. It is built from the ground up following a full Secure Software Development Lifecycle (SSDLC), covering formal risk analysis, threat modeling, secure architecture, hardened implementation, and structured penetration testing.

This repository serves as the **reference implementation** for clients and auditors demonstrating compliance with GDPR, ISO/IEC 27001:2022, and NIST CSF.

---

## Architecture at a Glance

```
Internet → Cloudflare WAF → NGINX (TLS 1.3) → API Gateway
       → Django REST API (Python 3.12)
       → PostgreSQL 16 (encrypted at rest)
       → MinIO / S3 (private ACL, pre-signed URLs)
       → Redis (session/cache)
       → Elasticsearch + Kibana (SIEM / audit logs)
```

---

## Repository Structure

```
securevault/
├── src/
│   ├── backend/              # Django REST API
│   │   ├── api/              # Route definitions and serializers
│   │   ├── auth/             # OAuth2, JWT, MFA, RBAC
│   │   ├── files/            # Upload pipeline, ClamAV, pre-signed URLs
│   │   ├── core/             # Settings, constants, exceptions
│   │   ├── middleware/       # Security headers, audit logging, rate limiting
│   │   ├── models/           # Database models
│   │   └── utils/            # Crypto helpers, validators, sanitizers
│   └── frontend/             # React + TypeScript SPA
│       ├── components/       # UI, layout, auth, file, dashboard components
│       ├── pages/            # Route pages
│       ├── hooks/            # Custom React hooks
│       └── utils/            # Axios interceptors, token management
├── docs/
│   ├── risk-analysis/        # Phase 1 — Risk Analysis Report
│   ├── architecture/         # Phase 2 — Secure Design Document
│   ├── security/             # Secure Coding Guidelines
│   └── compliance/           # GDPR, ISO 27001, NIST CSF mapping
├── pentest/
│   ├── evidence/             # PT-XXX folders with screenshots/payloads
│   ├── tools/                # Tool configs (ZAP, Burp, Nmap)
│   └── reports/              # Pentest Audit Report PDF/HTML
├── infra/
│   ├── docker/               # Dockerfile, docker-compose
│   ├── nginx/                # nginx.conf (TLS 1.3, HSTS, CSP)
│   └── scripts/              # Deployment and backup scripts
├── tests/
│   ├── unit/                 # Unit tests (pytest)
│   ├── integration/          # API integration tests
│   └── security/             # Automated security regression tests
├── reports/                  # Final compiled reports
├── README.md                 # This file
├── SECURITY.md               # Responsible disclosure policy
├── CHANGELOG.md              # Dated phase entries
└── .env.example              # Environment variable template
```

---

## Quick Start (Development)

```bash
# 1. Clone repository
git clone https://github.com/your-org/securevault.git
cd securevault

# 2. Copy environment template
cp .env.example .env
# Edit .env with your secrets (see docs/security/env-setup.md)

# 3. Start all services
cd infra/docker
docker-compose up --build

# 4. Run database migrations
docker exec -it securevault-backend python manage.py migrate

# 5. Create superuser
docker exec -it securevault-backend python manage.py createsuperuser

# 6. Access the application
# Frontend:  https://localhost:3000
# API:       https://localhost:8000/api/v1/
# Admin:     https://localhost:8000/admin/
# Kibana:    https://localhost:5601 (audit logs)
```

---

## Security Features

| Feature | Implementation |
|---|---|
| Authentication | OAuth2 PKCE + JWT (RS256, 15min expiry) |
| MFA | TOTP (RFC 6238) + WebAuthn (FIDO2) |
| Password Hashing | Argon2id (time=2, mem=65536) |
| Session Management | HttpOnly + SameSite=Strict cookies, IP-bound |
| Transport Security | TLS 1.3 only, HSTS preload, Certificate Pinning |
| Input Validation | Whitelist-based, server-side, every endpoint |
| File Scanning | ClamAV + MIME magic byte validation |
| File Access | Pre-signed URLs (5min expiry), private ACL |
| RBAC | 5-tier role system, DB-stored permissions |
| Audit Logging | Immutable log stream → Elasticsearch/SIEM |
| Rate Limiting | Per-IP, per-user, per-endpoint sliding window |
| CSRF Protection | Double-submit cookie + SameSite=Strict |
| Secret Management | HashiCorp Vault / AWS KMS integration |

---

## Compliance

- **GDPR** — Data minimization, right to erasure, DPA documentation
- **ISO/IEC 27001:2022** — Full Annex A control mapping
- **NIST CSF** — Identify / Protect / Detect / Respond / Recover mapped
- **OWASP Top 10 (2021)** — All 10 categories addressed

---

## Phase Deliverables

| # | Deliverable | Location |
|---|---|---|
| 1 | Risk Analysis Report | `docs/risk-analysis/` |
| 2 | Secure SDLC Design Document | `docs/architecture/` |
| 3 | Secure Web Application (source) | `src/` |
| 4 | Pentest Audit Report | `pentest/reports/` |
| 5 | Final Compiled Reports | `reports/` |

---

## Tags & Versions

```
v1.0.0-risk-report       Phase 1 complete
v2.0.0-design            Phase 2 complete
v3.0.0-implementation    Phase 3 complete
v4.0.0-pentest           Phase 4 complete
v5.0.0-final             All phases complete
```

---

## License

Proprietary — All rights reserved. This codebase may not be copied, distributed, or used without explicit written permission from the owning organization.
