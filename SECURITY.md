# Security Policy

## Responsible Disclosure

SecureVault is committed to maintaining the highest security standards. We welcome responsible disclosure of security vulnerabilities by security researchers and the community.

---

## Supported Versions

| Version | Supported |
|---|---|
| v5.x (current) | ✅ Full support |
| v4.x | ✅ Security patches only |
| v3.x and below | ❌ End of life |

---

## Reporting a Vulnerability

**DO NOT open a public GitHub issue for security vulnerabilities.**

### Contact

- **Email:** security@securevault.io (PGP preferred)
- **PGP Key:** Available at https://securevault.io/.well-known/security.txt
- **Response SLA:** Initial acknowledgement within **24 hours**; full triage within **72 hours**

### What to Include

Please provide:

1. **Vulnerability Type** — e.g., XSS, SQLi, IDOR, SSRF, RCE
2. **Affected Component** — e.g., file upload endpoint, authentication module
3. **Reproduction Steps** — Step-by-step instructions to reproduce
4. **Proof of Concept** — Screenshots, curl commands, or payloads (no destructive testing)
5. **Impact Assessment** — Your assessment of the potential impact
6. **Suggested Fix** — If you have one (optional but appreciated)

---

## Rules of Engagement

By reporting a vulnerability you agree to:

- Act in good faith and avoid privacy violations, data destruction, or service disruption
- Not access, modify, or exfiltrate any user data
- Not perform DoS/DDoS attacks
- Not use social engineering against our staff
- Give us a reasonable time to remediate before public disclosure (90 days by default)

---

## Scope

### In Scope

- **Production application** — https://securevault.io
- **API endpoints** — https://api.securevault.io/v1/
- **Authentication flows** — Login, OAuth2, MFA, password reset
- **File handling pipeline** — Upload, download, access control

### Out of Scope

- Social engineering attacks against employees
- Physical attacks against infrastructure
- Denial of Service (DoS) attacks
- Vulnerabilities in third-party dependencies (report to upstream first)
- Issues requiring physical access to user devices
- Self-XSS with no impact

---

## Bug Bounty

SecureVault operates a private bug bounty program. Rewards are based on CVSS 3.1 severity:

| Severity | CVSS Score | Reward |
|---|---|---|
| Critical | 9.0–10.0 | $2,000 – $5,000 |
| High | 7.0–8.9 | $500 – $2,000 |
| Medium | 4.0–6.9 | $100 – $500 |
| Low | 0.1–3.9 | Recognition + swag |

We do not pay for informational findings or issues that do not represent a real security risk.

---

## Disclosure Timeline

```
Day  0  — Vulnerability reported
Day  1  — Acknowledgement sent to researcher
Day  3  — Triage completed, severity assigned
Day 14  — Fix developed and tested
Day 21  — Fix deployed to production
Day 30  — Researcher notified of remediation
Day 90  — Public disclosure permitted (coordinated with researcher)
```

---

## Hall of Fame

We publicly acknowledge security researchers who responsibly disclose valid vulnerabilities. Contact us to be added.

---

## Legal Safe Harbor

SecureVault will not pursue legal action against researchers who:
- Follow these responsible disclosure guidelines
- Avoid accessing, modifying, or exfiltrating user data
- Act in good faith

We consider responsible security research a valuable contribution to our mission of building trustworthy security infrastructure.
