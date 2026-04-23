"""
SecureVault — Role-Based Access Control (RBAC)
Implements DB-stored role/permission system.
Reference: docs/architecture/SECURE-DESIGN-DOCUMENT.md Section 4 / SR-006
"""

import logging
from enum import IntEnum
from functools import wraps
from typing import Union, List

from django.core.cache import cache
from rest_framework import status
from rest_framework.response import Response

security_log = logging.getLogger("securevault.security")
audit_log = logging.getLogger("securevault.audit")


class Role(IntEnum):
    """
    5-tier role hierarchy. Higher integer = higher privilege.
    Roles are stored in DB, never trusted from JWT claims alone.
    """
    GUEST = 0
    USER = 1
    MODERATOR = 2
    ADMIN = 3
    SUPERADMIN = 4


# Role → string mapping (for storage and display)
ROLE_NAMES = {
    Role.GUEST: "guest",
    Role.USER: "user",
    Role.MODERATOR: "moderator",
    Role.ADMIN: "admin",
    Role.SUPERADMIN: "superadmin",
}

ROLE_FROM_STRING = {v: k for k, v in ROLE_NAMES.items()}


class Permission:
    """Fine-grained permissions per resource/action."""
    # File permissions
    FILE_UPLOAD = "file.upload"
    FILE_DOWNLOAD = "file.download"
    FILE_DELETE_OWN = "file.delete.own"
    FILE_DELETE_ANY = "file.delete.any"
    FILE_SHARE = "file.share"
    FILE_VIEW_ALL = "file.view.all"

    # User permissions
    USER_VIEW_OWN = "user.view.own"
    USER_VIEW_ANY = "user.view.any"
    USER_EDIT_OWN = "user.edit.own"
    USER_EDIT_ANY = "user.edit.any"
    USER_DELETE_ANY = "user.delete.any"
    USER_ASSIGN_ROLE = "user.assign.role"

    # Admin permissions
    ADMIN_PANEL = "admin.panel"
    ADMIN_AUDIT_LOGS = "admin.audit_logs"
    ADMIN_SYSTEM_CONFIG = "admin.system.config"


# Default permission mapping per role
# NOTE: These are defaults. Fine-grained overrides are stored in DB.
ROLE_PERMISSIONS = {
    Role.GUEST: set(),
    Role.USER: {
        Permission.FILE_UPLOAD,
        Permission.FILE_DOWNLOAD,
        Permission.FILE_DELETE_OWN,
        Permission.FILE_SHARE,
        Permission.USER_VIEW_OWN,
        Permission.USER_EDIT_OWN,
    },
    Role.MODERATOR: {
        Permission.FILE_UPLOAD,
        Permission.FILE_DOWNLOAD,
        Permission.FILE_DELETE_OWN,
        Permission.FILE_DELETE_ANY,
        Permission.FILE_SHARE,
        Permission.FILE_VIEW_ALL,
        Permission.USER_VIEW_OWN,
        Permission.USER_VIEW_ANY,
        Permission.USER_EDIT_OWN,
    },
    Role.ADMIN: {
        Permission.FILE_UPLOAD,
        Permission.FILE_DOWNLOAD,
        Permission.FILE_DELETE_OWN,
        Permission.FILE_DELETE_ANY,
        Permission.FILE_SHARE,
        Permission.FILE_VIEW_ALL,
        Permission.USER_VIEW_OWN,
        Permission.USER_VIEW_ANY,
        Permission.USER_EDIT_OWN,
        Permission.USER_EDIT_ANY,
        Permission.USER_DELETE_ANY,
        Permission.ADMIN_PANEL,
        Permission.ADMIN_AUDIT_LOGS,
    },
    Role.SUPERADMIN: {
        # Superadmin has all permissions
        Permission.FILE_UPLOAD,
        Permission.FILE_DOWNLOAD,
        Permission.FILE_DELETE_OWN,
        Permission.FILE_DELETE_ANY,
        Permission.FILE_SHARE,
        Permission.FILE_VIEW_ALL,
        Permission.USER_VIEW_OWN,
        Permission.USER_VIEW_ANY,
        Permission.USER_EDIT_OWN,
        Permission.USER_EDIT_ANY,
        Permission.USER_DELETE_ANY,
        Permission.USER_ASSIGN_ROLE,
        Permission.ADMIN_PANEL,
        Permission.ADMIN_AUDIT_LOGS,
        Permission.ADMIN_SYSTEM_CONFIG,
    },
}


def get_user_role(user) -> Role:
    """
    Get user's role from DB (not from JWT claims).
    Cached in Redis for 5 minutes.
    SR-006: Roles stored in DB; not trusted from JWT claims alone.
    """
    cache_key = f"user_role:{user.id}"
    cached_role = cache.get(cache_key)
    if cached_role is not None:
        return Role(cached_role)

    try:
        role_str = user.profile.role
        role = ROLE_FROM_STRING.get(role_str, Role.USER)
    except Exception:
        role = Role.USER  # Fail safe to least privilege

    cache.set(cache_key, int(role), timeout=300)
    return role


def get_user_permissions(user) -> set:
    """Get all permissions for a user based on their DB role."""
    role = get_user_role(user)
    return ROLE_PERMISSIONS.get(role, set())


def has_permission(user, permission: str) -> bool:
    """Check if a user has a specific permission."""
    permissions = get_user_permissions(user)
    return permission in permissions


def has_role(user, minimum_role: Role) -> bool:
    """Check if user has at least the specified role level."""
    user_role = get_user_role(user)
    return user_role >= minimum_role


def invalidate_role_cache(user_id) -> None:
    """Call this after any role change to clear cached role."""
    cache.delete(f"user_role:{user_id}")


# ─────────────────────────────────────────────
# DECORATOR-BASED PERMISSION ENFORCEMENT
# ─────────────────────────────────────────────
def require_role(minimum_role: Union[Role, str]):
    """
    Decorator: Require user to have at least the specified role.
    Applied at the route level (not business logic).

    Usage:
        @require_role(Role.ADMIN)
        def admin_endpoint(request):
            ...
    """
    if isinstance(minimum_role, str):
        minimum_role = ROLE_FROM_STRING.get(minimum_role, Role.SUPERADMIN)

    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return Response(
                    {"detail": "Authentication required."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            if not has_role(request.user, minimum_role):
                security_log.warning(
                    "rbac.access_denied",
                    extra={
                        "user_id": str(request.user.id),
                        "required_role": ROLE_NAMES.get(minimum_role),
                        "user_role": ROLE_NAMES.get(get_user_role(request.user)),
                        "path": request.path,
                    },
                )
                audit_log.info(
                    "authorization.denied",
                    extra={
                        "user_id": str(request.user.id),
                        "action": "role_check_failed",
                        "outcome": "denied",
                    },
                )
                return Response(
                    {"detail": "Insufficient permissions."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def require_permission(permission: str):
    """
    Decorator: Require user to have a specific permission.

    Usage:
        @require_permission(Permission.ADMIN_PANEL)
        def admin_view(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return Response(
                    {"detail": "Authentication required."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )

            if not has_permission(request.user, permission):
                security_log.warning(
                    "rbac.permission_denied",
                    extra={
                        "user_id": str(request.user.id),
                        "required_permission": permission,
                        "path": request.path,
                    },
                )
                return Response(
                    {"detail": "Insufficient permissions."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def verify_resource_ownership(resource_owner_id, requesting_user, allow_admin: bool = True) -> bool:
    """
    Verify that the requesting user owns the resource OR is an admin.
    Critical for IDOR prevention (R-002 in risk register).
    SR-005: Every file access must verify ownership/permission server-side.

    Args:
        resource_owner_id: UUID of the resource owner
        requesting_user: The authenticated user making the request
        allow_admin: Whether admins can bypass ownership check

    Returns:
        True if access is permitted, False otherwise
    """
    # Convert to string for comparison
    owner_id = str(resource_owner_id)
    requester_id = str(requesting_user.id)

    # Owner always has access
    if owner_id == requester_id:
        return True

    # Admins can access any resource if allow_admin is True
    if allow_admin and has_role(requesting_user, Role.ADMIN):
        return True

    # Log the IDOR attempt
    security_log.warning(
        "security.idor_attempt",
        extra={
            "requesting_user_id": requester_id,
            "resource_owner_id": owner_id,
            "outcome": "blocked",
        },
    )

    return False
