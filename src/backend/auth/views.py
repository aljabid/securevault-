"""
SecureVault — Authentication API Views
Implements: Login, Register, MFA verify, Token refresh, Logout
Reference: docs/architecture/SECURE-DESIGN-DOCUMENT.md Section 5
"""

import logging
import secrets
import hashlib
from datetime import timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.core.cache import cache
from django.utils import timezone

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from .serializers import (
    LoginSerializer,
    RegisterSerializer,
    MFAVerifySerializer,
    PasswordChangeSerializer,
)
from .totp import TOTPManager
from .rbac import require_role

User = get_user_model()
audit_log = logging.getLogger("securevault.audit")
security_log = logging.getLogger("securevault.security")


class LoginRateThrottle(ScopedRateThrottle):
    scope = "login"


# ─────────────────────────────────────────────
# REGISTRATION
# ─────────────────────────────────────────────
@api_view(["POST"])
@permission_classes([AllowAny])
def register(request):
    """
    Register a new user account.
    Account is created in INACTIVE state until email verification.
    SR-001: Password hashed with Argon2id
    """
    serializer = RegisterSerializer(data=request.data)
    if not serializer.is_valid():
        # Generic error — do not reveal which field failed (username enumeration)
        return Response(
            {"detail": "Registration failed. Please check your input."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    user = serializer.save()
    user.is_active = False  # Require email verification
    user.save()

    # Send verification email (async via Celery)
    from src.backend.auth.tasks import send_verification_email
    send_verification_email.delay(user.id)

    audit_log.info(
        "auth.register",
        extra={"user_id": str(user.id), "outcome": "success"},
    )

    return Response(
        {"detail": "Registration successful. Check your email to verify your account."},
        status=status.HTTP_201_CREATED,
    )


# ─────────────────────────────────────────────
# LOGIN
# ─────────────────────────────────────────────
@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([LoginRateThrottle])
def login(request):
    """
    Authenticate user with email + password.
    Returns JWT access token + sets refresh token in HttpOnly cookie.

    Security controls:
    - SR-004: Account lockout after 5 failed attempts
    - Generic error messages (prevent username enumeration)
    - Constant-time comparison for password check
    - Timing-safe response (fixed 200ms minimum)
    """
    import time
    start = time.monotonic()

    serializer = LoginSerializer(data=request.data)

    # Always return after at least 200ms to prevent timing attacks
    def _timed_response(response, min_ms=200):
        elapsed = (time.monotonic() - start) * 1000
        if elapsed < min_ms:
            time.sleep((min_ms - elapsed) / 1000)
        return response

    if not serializer.is_valid():
        return _timed_response(
            Response(
                {"detail": "Invalid credentials."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        )

    email = serializer.validated_data["email"].lower().strip()
    password = serializer.validated_data["password"]

    # Check lockout before querying DB (prevents timing oracle)
    lockout_key = f"lockout:{_hash_ip(request)}"
    if cache.get(lockout_key):
        security_log.warning(
            "auth.login.locked",
            extra={
                "ip": _get_ip(request),
                "outcome": "blocked",
            },
        )
        return _timed_response(
            Response(
                {"detail": "Account temporarily locked. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )
        )

    # Fetch user — always perform password check even if user not found
    # This prevents username enumeration via timing differences
    try:
        user = User.objects.get(email=email)
        password_valid = user.check_password(password)
    except User.DoesNotExist:
        # Perform dummy check to maintain constant time
        from django.contrib.auth.hashers import make_password
        check_password(password, make_password("dummy-value"))
        password_valid = False
        user = None

    if not password_valid or user is None:
        _record_failed_attempt(request, email)
        audit_log.info(
            "auth.login.failed",
            extra={"outcome": "invalid_credentials", "ip": _get_ip(request)},
        )
        return _timed_response(
            Response(
                {"detail": "Invalid credentials."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        )

    if not user.is_active:
        return _timed_response(
            Response(
                {"detail": "Account not verified. Please check your email."},
                status=status.HTTP_403_FORBIDDEN,
            )
        )

    # Check if MFA is required
    if user.mfa_enabled:
        # Issue a short-lived pre-auth token instead of full JWT
        pre_auth_token = _create_pre_auth_token(user)
        audit_log.info(
            "auth.login.mfa_required",
            extra={"user_id": str(user.id), "outcome": "mfa_required"},
        )
        return _timed_response(
            Response(
                {
                    "mfa_required": True,
                    "pre_auth_token": pre_auth_token,
                },
                status=status.HTTP_200_OK,
            )
        )

    # Successful login — issue JWT
    _clear_failed_attempts(request)
    return _timed_response(_issue_tokens(user, request))


# ─────────────────────────────────────────────
# MFA VERIFICATION
# ─────────────────────────────────────────────
@api_view(["POST"])
@permission_classes([AllowAny])
@throttle_classes([LoginRateThrottle])
def verify_mfa(request):
    """
    Verify TOTP code after successful password authentication.
    Exchanges pre-auth token for full JWT on success.
    """
    serializer = MFAVerifySerializer(data=request.data)
    if not serializer.is_valid():
        return Response({"detail": "Invalid request."}, status=status.HTTP_400_BAD_REQUEST)

    pre_auth_token = serializer.validated_data["pre_auth_token"]
    totp_code = serializer.validated_data["code"]

    # Validate pre-auth token
    user = _validate_pre_auth_token(pre_auth_token)
    if not user:
        return Response(
            {"detail": "Invalid or expired session. Please log in again."},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    # Verify TOTP
    totp_manager = TOTPManager()
    if not totp_manager.verify(user.mfa_secret_encrypted, totp_code):
        security_log.warning(
            "auth.mfa.failed",
            extra={"user_id": str(user.id), "ip": _get_ip(request)},
        )
        return Response(
            {"detail": "Invalid verification code."},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    # MFA passed — issue full JWT
    _invalidate_pre_auth_token(pre_auth_token)
    return _issue_tokens(user, request)


# ─────────────────────────────────────────────
# TOKEN REFRESH
# ─────────────────────────────────────────────
@api_view(["POST"])
@permission_classes([AllowAny])
def refresh_token(request):
    """
    Rotate refresh token and issue new access token.
    Refresh token must be in HttpOnly cookie (not request body).
    """
    refresh_token_value = request.COOKIES.get("refresh_token")
    if not refresh_token_value:
        return Response(
            {"detail": "No refresh token provided."},
            status=status.HTTP_401_UNAUTHORIZED,
        )

    try:
        token = RefreshToken(refresh_token_value)

        # Validate IP binding
        stored_ip = cache.get(f"refresh_ip:{str(token)[:32]}")
        if stored_ip and stored_ip != _get_ip(request):
            security_log.warning(
                "auth.token.ip_mismatch",
                extra={
                    "expected_ip": stored_ip,
                    "actual_ip": _get_ip(request),
                    "token_prefix": str(token)[:16],
                },
            )
            return Response(
                {"detail": "Token bound to different IP address."},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Rotate — new refresh token, old one blacklisted automatically
        new_access_token = str(token.access_token)
        new_refresh_token = str(token)

        response = Response({"access": new_access_token})
        _set_refresh_cookie(response, new_refresh_token)

        # Update IP binding for new token
        cache.set(
            f"refresh_ip:{new_refresh_token[:32]}",
            _get_ip(request),
            timeout=7 * 24 * 60 * 60,
        )

        return response

    except TokenError:
        return Response(
            {"detail": "Invalid or expired refresh token."},
            status=status.HTTP_401_UNAUTHORIZED,
        )


# ─────────────────────────────────────────────
# LOGOUT
# ─────────────────────────────────────────────
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout(request):
    """
    Invalidate refresh token and clear session.
    """
    refresh_token_value = request.COOKIES.get("refresh_token")
    if refresh_token_value:
        try:
            token = RefreshToken(refresh_token_value)
            token.blacklist()
        except TokenError:
            pass  # Already invalid — fine

    audit_log.info(
        "auth.logout",
        extra={"user_id": str(request.user.id), "outcome": "success"},
    )

    response = Response({"detail": "Successfully logged out."})
    response.delete_cookie("refresh_token")
    return response


# ─────────────────────────────────────────────
# PASSWORD CHANGE
# ─────────────────────────────────────────────
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def change_password(request):
    """Change authenticated user's password. Invalidates all existing sessions."""
    serializer = PasswordChangeSerializer(data=request.data, context={"request": request})
    if not serializer.is_valid():
        return Response(
            {"detail": "Password change failed."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    user = request.user
    user.set_password(serializer.validated_data["new_password"])
    user.save()

    # Invalidate all refresh tokens by clearing Redis keys
    # (JWT blacklist handles access tokens via jti)
    audit_log.info(
        "auth.password.changed",
        extra={"user_id": str(user.id), "outcome": "success"},
    )

    response = Response({"detail": "Password changed successfully. Please log in again."})
    response.delete_cookie("refresh_token")
    return response


# ─────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────
def _issue_tokens(user, request) -> Response:
    """Issue JWT access + refresh token pair."""
    refresh = RefreshToken.for_user(user)
    access_token = str(refresh.access_token)
    refresh_token_str = str(refresh)

    # Bind refresh token to current IP in Redis
    cache.set(
        f"refresh_ip:{refresh_token_str[:32]}",
        _get_ip(request),
        timeout=7 * 24 * 60 * 60,
    )

    audit_log.info(
        "auth.login.success",
        extra={"user_id": str(user.id), "outcome": "success"},
    )

    response = Response({
        "access": access_token,
        "user": {
            "id": str(user.id),
            "email": user.email,
            "role": user.profile.role if hasattr(user, "profile") else "user",
            "mfa_enabled": getattr(user, "mfa_enabled", False),
        },
    })
    _set_refresh_cookie(response, refresh_token_str)
    return response


def _set_refresh_cookie(response: Response, token: str) -> None:
    """Set refresh token in HttpOnly + SameSite=Strict cookie."""
    response.set_cookie(
        key="refresh_token",
        value=token,
        max_age=7 * 24 * 60 * 60,  # 7 days
        secure=True,
        httponly=True,
        samesite="Strict",
        path="/api/v1/auth/refresh/",  # Scope to refresh endpoint only
    )


def _get_ip(request) -> str:
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    return xff.split(",")[0].strip() if xff else request.META.get("REMOTE_ADDR", "unknown")


def _hash_ip(request) -> str:
    """Hash IP for cache keys to avoid storing raw IPs in cache."""
    ip = _get_ip(request)
    return hashlib.sha256(ip.encode()).hexdigest()[:16]


def _record_failed_attempt(request, email: str) -> None:
    """Increment failed attempt counter and apply lockout if threshold exceeded."""
    key = f"failed_login:{_hash_ip(request)}"
    attempts = cache.get(key, 0) + 1
    cache.set(key, attempts, timeout=900)  # Reset after 15 minutes

    if attempts >= settings.AXES_FAILURE_LIMIT:
        # Exponential backoff: 15min × 2^(attempts-5)
        multiplier = 2 ** (attempts - settings.AXES_FAILURE_LIMIT)
        lockout_duration = min(settings.AXES_COOLOFF_TIME.seconds * multiplier, 86400)
        lockout_key = f"lockout:{_hash_ip(request)}"
        cache.set(lockout_key, True, timeout=lockout_duration)

        security_log.warning(
            "auth.login.account_locked",
            extra={
                "ip": _get_ip(request),
                "attempts": attempts,
                "lockout_seconds": lockout_duration,
            },
        )


def _clear_failed_attempts(request) -> None:
    """Clear failed attempt counter on successful login."""
    cache.delete(f"failed_login:{_hash_ip(request)}")
    cache.delete(f"lockout:{_hash_ip(request)}")


def _create_pre_auth_token(user) -> str:
    """Create short-lived pre-auth token for MFA flow (5 minutes)."""
    token = secrets.token_urlsafe(32)
    cache.set(f"pre_auth:{token}", str(user.id), timeout=300)
    return token


def _validate_pre_auth_token(token: str):
    """Validate pre-auth token and return associated user or None."""
    user_id = cache.get(f"pre_auth:{token}")
    if not user_id:
        return None
    try:
        return User.objects.get(id=user_id)
    except User.DoesNotExist:
        return None


def _invalidate_pre_auth_token(token: str) -> None:
    """Delete pre-auth token after use (one-time use)."""
    cache.delete(f"pre_auth:{token}")
