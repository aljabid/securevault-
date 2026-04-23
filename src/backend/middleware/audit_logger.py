"""
SecureVault — Audit Logging Middleware
Logs every significant request to Elasticsearch SIEM.
Reference: docs/architecture/SECURE-DESIGN-DOCUMENT.md Section 8
"""

import uuid
import json
import time
import logging
import threading
from datetime import datetime, timezone
from typing import Optional

from django.conf import settings
from django.utils.deprecation import MiddlewareMixin

try:
    from elasticsearch import Elasticsearch
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False

# Dedicated audit logger — never uses root logger
audit_logger = logging.getLogger("securevault.audit")
security_logger = logging.getLogger("securevault.security")

# Endpoints that should always be logged regardless of outcome
ALWAYS_LOG_PATHS = {
    "/api/v1/auth/",
    "/api/v1/files/",
    "/api/v1/admin/",
    "/api/v1/users/",
}

# Paths excluded from audit logging (static assets, health checks)
SKIP_LOG_PATHS = {
    "/static/",
    "/favicon.ico",
    "/health/",
    "/metrics/",
}

# HTTP methods that indicate state-changing operations
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class AuditLogMiddleware(MiddlewareMixin):
    """
    Captures request/response metadata and ships structured audit logs.

    Log fields (per docs/architecture/SECURE-DESIGN-DOCUMENT.md Section 8.1):
      - timestamp (UTC ISO8601)
      - event_id (UUID v4, unique per request)
      - user_id (UUID or null for anonymous)
      - session_id (from session or JWT jti)
      - ip_address (real IP, X-Forwarded-For aware)
      - user_agent
      - action (derived from method + path)
      - resource_type
      - resource_id
      - outcome (success | failure | error)
      - duration_ms
      - risk_score (0-100)
    """

    def process_request(self, request):
        # Attach request start time and event ID for correlation
        request._audit_start_time = time.monotonic()
        request._event_id = str(uuid.uuid4())
        return None

    def process_response(self, request, response):
        # Skip non-auditable paths
        path = request.path
        if any(path.startswith(skip) for skip in SKIP_LOG_PATHS):
            return response

        # Only log API paths and mutating operations
        is_api = path.startswith("/api/")
        is_mutating = request.method in MUTATING_METHODS
        is_always_log = any(path.startswith(p) for p in ALWAYS_LOG_PATHS)

        if not (is_api or is_always_log or is_mutating):
            return response

        duration_ms = self._get_duration(request)
        user_id = self._get_user_id(request)
        ip_address = self._get_real_ip(request)

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": getattr(request, "_event_id", str(uuid.uuid4())),
            "user_id": user_id,
            "session_id": self._get_session_id(request),
            "ip_address": ip_address,
            "user_agent": request.META.get("HTTP_USER_AGENT", "")[:512],
            "method": request.method,
            "path": path[:512],
            "action": self._derive_action(request),
            "resource_type": self._derive_resource_type(path),
            "resource_id": self._derive_resource_id(path),
            "status_code": response.status_code,
            "outcome": self._derive_outcome(response.status_code),
            "duration_ms": duration_ms,
            "risk_score": self._calculate_risk_score(request, response),
        }

        # Ship to audit log asynchronously to not block response
        threading.Thread(
            target=self._ship_log,
            args=(log_entry,),
            daemon=True
        ).start()

        # Log security events synchronously (brute force, auth failures)
        if response.status_code in {401, 403} and is_api:
            security_logger.warning(
                "Authorization failure",
                extra={
                    "event_id": log_entry["event_id"],
                    "ip": ip_address,
                    "path": path,
                    "user_id": user_id,
                }
            )

        return response

    def _ship_log(self, log_entry: dict) -> None:
        """Ship log entry to Elasticsearch and local logger."""
        try:
            audit_logger.info("audit_event", extra=log_entry)

            if ES_AVAILABLE and hasattr(settings, "ELASTICSEARCH_HOST"):
                es = Elasticsearch(
                    [f"http://{settings.ELASTICSEARCH_HOST}"],
                    basic_auth=(
                        settings.__dict__.get("ELASTICSEARCH_USERNAME", ""),
                        settings.__dict__.get("ELASTICSEARCH_PASSWORD", ""),
                    ),
                    request_timeout=5,
                )
                index_name = (
                    f"{settings.ELASTICSEARCH_INDEX_PREFIX}-audit-"
                    f"{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"
                )
                es.index(index=index_name, document=log_entry)
        except Exception as e:
            # Never let logging failure affect application — log to console only
            logging.getLogger("django").error(f"Audit log ship failed: {e}")

    @staticmethod
    def _get_duration(request) -> float:
        start = getattr(request, "_audit_start_time", None)
        if start:
            return round((time.monotonic() - start) * 1000, 2)
        return 0.0

    @staticmethod
    def _get_user_id(request) -> Optional[str]:
        if hasattr(request, "user") and request.user.is_authenticated:
            return str(request.user.id)
        return None

    @staticmethod
    def _get_session_id(request) -> Optional[str]:
        if hasattr(request, "session") and request.session.session_key:
            return request.session.session_key[:16] + "..."  # Partial only
        return None

    @staticmethod
    def _get_real_ip(request) -> str:
        """Extract real IP, accounting for proxy headers."""
        xff = request.META.get("HTTP_X_FORWARDED_FOR")
        if xff:
            # Take first IP in chain (client), not the last proxy
            return xff.split(",")[0].strip()
        return request.META.get("REMOTE_ADDR", "unknown")

    @staticmethod
    def _derive_action(request) -> str:
        method = request.method
        path = request.path
        if "/auth/login" in path:
            return "auth.login"
        if "/auth/logout" in path:
            return "auth.logout"
        if "/auth/register" in path:
            return "auth.register"
        if "/files/" in path:
            if method == "POST":
                return "file.upload"
            if method == "GET":
                return "file.download"
            if method == "DELETE":
                return "file.delete"
        if "/admin/" in path:
            return f"admin.{method.lower()}"
        return f"api.{method.lower()}"

    @staticmethod
    def _derive_resource_type(path: str) -> Optional[str]:
        if "/files/" in path:
            return "file"
        if "/users/" in path:
            return "user"
        if "/auth/" in path:
            return "auth"
        if "/admin/" in path:
            return "admin"
        return None

    @staticmethod
    def _derive_resource_id(path: str) -> Optional[str]:
        """Extract UUID from path like /api/v1/files/{uuid}/"""
        parts = [p for p in path.split("/") if p]
        for part in parts:
            if len(part) == 36 and part.count("-") == 4:  # UUID-like
                return part
        return None

    @staticmethod
    def _derive_outcome(status_code: int) -> str:
        if 200 <= status_code < 300:
            return "success"
        if status_code in {401, 403}:
            return "unauthorized"
        if status_code == 404:
            return "not_found"
        if 400 <= status_code < 500:
            return "client_error"
        return "error"

    @staticmethod
    def _calculate_risk_score(request, response) -> int:
        """
        Simple heuristic risk score (0-100).
        High scores trigger alerts in SIEM.
        """
        score = 0
        # Unauthenticated request to authenticated endpoint
        if response.status_code == 401:
            score += 20
        # Authorization failure (attempting to access forbidden resource)
        if response.status_code == 403:
            score += 30
        # Admin endpoint access
        if "/admin/" in request.path:
            score += 20
        # Unusual HTTP methods
        if request.method in {"TRACE", "CONNECT", "OPTIONS"}:
            score += 15
        return min(score, 100)


class ElasticsearchHandler(logging.Handler):
    """Custom logging handler that ships records to Elasticsearch."""

    def __init__(self):
        super().__init__()
        self._es = None

    def _get_client(self):
        if self._es is None and ES_AVAILABLE:
            try:
                self._es = Elasticsearch(
                    [f"http://{settings.ELASTICSEARCH_HOST}"],
                    request_timeout=3,
                )
            except Exception:
                pass
        return self._es

    def emit(self, record):
        try:
            es = self._get_client()
            if es:
                log_entry = {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "level": record.levelname,
                    "logger": record.name,
                    "message": self.format(record),
                }
                index_name = (
                    f"{settings.ELASTICSEARCH_INDEX_PREFIX}-logs-"
                    f"{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"
                )
                es.index(index=index_name, document=log_entry)
        except Exception:
            self.handleError(record)
