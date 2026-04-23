"""
SecureVault — Security Headers Middleware
Injects all required security headers on every response.
Reference: docs/architecture/SECURE-DESIGN-DOCUMENT.md Section 7.2
"""

import secrets
from django.conf import settings
from django.utils.deprecation import MiddlewareMixin


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Adds comprehensive security headers to every HTTP response.
    These complement NGINX-level headers for defense-in-depth.
    """

    def process_response(self, request, response):
        # Generate a per-request CSP nonce
        nonce = secrets.token_urlsafe(16)
        request.csp_nonce = nonce

        # Content Security Policy — strict nonce-based
        csp_directives = [
            "default-src 'none'",
            f"script-src 'nonce-{nonce}'",
            f"style-src 'nonce-{nonce}'",
            "img-src 'self' data: blob:",
            "connect-src 'self'",
            "font-src 'self'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "upgrade-insecure-requests",
        ]

        if not settings.DEBUG:
            csp_directives.append("block-all-mixed-content")

        response["Content-Security-Policy"] = "; ".join(csp_directives)

        # Prevent clickjacking
        response["X-Frame-Options"] = "DENY"

        # Prevent MIME-type sniffing
        response["X-Content-Type-Options"] = "nosniff"

        # Referrer control
        response["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions policy — deny access to sensitive browser features
        response["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), "
            "payment=(), usb=(), magnetometer=(), gyroscope=()"
        )

        # Cross-origin isolation headers
        response["Cross-Origin-Embedder-Policy"] = "require-corp"
        response["Cross-Origin-Opener-Policy"] = "same-origin"
        response["Cross-Origin-Resource-Policy"] = "same-origin"

        # Remove server fingerprinting headers
        if "Server" in response:
            del response["Server"]
        if "X-Powered-By" in response:
            del response["X-Powered-By"]

        # HSTS is set in NGINX, but redundantly set here for defense-in-depth
        if not settings.DEBUG:
            response["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # Cache control for API responses (no caching of sensitive data)
        if request.path.startswith("/api/"):
            response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response["Pragma"] = "no-cache"
            response["Expires"] = "0"

        return response
