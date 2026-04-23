"""
SecureVault — File Management API Views
Implements the complete secure file pipeline:
  Client → Validator → ClamAV → Storage → Pre-signed URL
Reference: docs/architecture/SECURE-DESIGN-DOCUMENT.md Section 3.2 / SR-009 to SR-012
"""

import uuid
import hashlib
import logging
import mimetypes
import os
from datetime import datetime, timezone

from django.conf import settings
from django.core.cache import cache
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle

from .validators import (
    validate_file_extension,
    validate_mime_type_magic_bytes,
    validate_file_size,
    sanitize_filename,
)
from .clamav import scan_file_with_clamav
from .storage import StorageBackend
from .models import FileRecord, FileShare
from .tasks import process_file_async
from src.backend.auth.rbac import (
    Permission,
    require_permission,
    verify_resource_ownership,
)

audit_log = logging.getLogger("securevault.audit")
security_log = logging.getLogger("securevault.security")


class UploadRateThrottle(ScopedRateThrottle):
    scope = "upload"


# ─────────────────────────────────────────────
# FILE UPLOAD
# ─────────────────────────────────────────────
@api_view(["POST"])
@permission_classes([IsAuthenticated])
@throttle_classes([UploadRateThrottle])
@require_permission(Permission.FILE_UPLOAD)
def upload_file(request):
    """
    Secure file upload endpoint.
    Pipeline: validate → MIME check → size check → ClamAV → storage

    Security controls applied:
    - SR-009: ClamAV scan before storage
    - SR-010: MIME type validated via magic bytes
    - SR-011: EXIF metadata stripped (images)
    - SR-012: File size limited to 50MB server-side
    """
    if "file" not in request.FILES:
        return Response(
            {"detail": "No file provided."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    uploaded_file = request.FILES["file"]

    # Step 1: File size validation (server-side, not client)
    size_error = validate_file_size(uploaded_file.size)
    if size_error:
        return Response({"detail": size_error}, status=status.HTTP_400_BAD_REQUEST)

    # Step 2: Filename sanitization (prevent path traversal)
    original_name = uploaded_file.name
    safe_filename = sanitize_filename(original_name)
    if not safe_filename:
        return Response(
            {"detail": "Invalid filename."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Step 3: Extension whitelist check
    ext_error = validate_file_extension(safe_filename)
    if ext_error:
        security_log.warning(
            "file.upload.blocked_extension",
            extra={
                "user_id": str(request.user.id),
                "filename": safe_filename,
                "reason": "blocked_extension",
            },
        )
        return Response({"detail": ext_error}, status=status.HTTP_400_BAD_REQUEST)

    # Step 4: MIME type validation via magic bytes (not file extension)
    file_bytes = uploaded_file.read(8192)  # Read first 8KB for magic bytes
    uploaded_file.seek(0)  # Reset file pointer

    mime_error, detected_mime = validate_mime_type_magic_bytes(file_bytes, safe_filename)
    if mime_error:
        security_log.warning(
            "file.upload.blocked_mime",
            extra={
                "user_id": str(request.user.id),
                "filename": safe_filename,
                "detected_mime": detected_mime,
                "reason": "blocked_mime_type",
            },
        )
        return Response({"detail": mime_error}, status=status.HTTP_400_BAD_REQUEST)

    # Step 5: ClamAV antivirus scan (synchronous — must pass before storage)
    file_data = uploaded_file.read()
    scan_result = scan_file_with_clamav(file_data)

    if not scan_result.is_clean:
        security_log.critical(
            "file.upload.malware_detected",
            extra={
                "user_id": str(request.user.id),
                "filename": safe_filename,
                "threat": scan_result.threat_name,
            },
        )
        return Response(
            {"detail": "File rejected: security threat detected."},
            status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    # Step 6: Generate storage key (UUID-based, no user data in path)
    file_id = str(uuid.uuid4())
    storage_key = f"files/{file_id}/{safe_filename}"

    # Step 7: Calculate file hash for integrity verification
    file_hash = hashlib.sha256(file_data).hexdigest()

    # Step 8: Store file (EXIF stripping and encryption happen in async task)
    storage = StorageBackend()
    try:
        storage.put_object(
            key=storage_key,
            data=file_data,
            content_type=detected_mime,
            metadata={
                "owner": str(request.user.id),
                "original_name": original_name[:256],
                "sha256": file_hash,
            },
        )
    except Exception as e:
        security_log.error(
            "file.upload.storage_error",
            extra={"user_id": str(request.user.id), "error": str(e)},
        )
        return Response(
            {"detail": "Upload failed. Please try again."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Step 9: Create DB record
    file_record = FileRecord.objects.create(
        id=file_id,
        owner=request.user,
        original_filename=safe_filename,
        storage_key=storage_key,
        file_size=len(file_data),
        mime_type=detected_mime,
        sha256_hash=file_hash,
        scan_status="clean",
        uploaded_at=datetime.now(timezone.utc),
    )

    # Step 10: Queue async post-processing (EXIF strip, metadata extraction)
    process_file_async.delay(file_id)

    # Step 11: Generate pre-signed URL (5 minutes expiry)
    presigned_url = storage.generate_presigned_url(
        key=storage_key,
        expiry=settings.PRESIGNED_URL_EXPIRY,
    )

    audit_log.info(
        "file.upload.success",
        extra={
            "user_id": str(request.user.id),
            "file_id": file_id,
            "filename": safe_filename,
            "size": len(file_data),
            "outcome": "success",
        },
    )

    return Response(
        {
            "file_id": file_id,
            "filename": safe_filename,
            "size": len(file_data),
            "mime_type": detected_mime,
            "sha256": file_hash,
            "download_url": presigned_url,
            "url_expires_in": settings.PRESIGNED_URL_EXPIRY,
            "uploaded_at": file_record.uploaded_at.isoformat(),
        },
        status=status.HTTP_201_CREATED,
    )


# ─────────────────────────────────────────────
# FILE DOWNLOAD (PRESIGNED URL)
# ─────────────────────────────────────────────
@api_view(["GET"])
@permission_classes([IsAuthenticated])
@require_permission(Permission.FILE_DOWNLOAD)
def download_file(request, file_id: str):
    """
    Generate a pre-signed download URL for a file.
    SR-005: Ownership verified server-side before generating URL.
    """
    # Validate file_id format (prevent injection in storage path)
    try:
        uuid.UUID(file_id)
    except ValueError:
        return Response(
            {"detail": "Invalid file identifier."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Fetch file record
    try:
        file_record = FileRecord.objects.select_related("owner").get(id=file_id)
    except FileRecord.DoesNotExist:
        # Return 404, not 403, to not reveal file existence to unauthorized users
        return Response(
            {"detail": "File not found."},
            status=status.HTTP_404_NOT_FOUND,
        )

    # IDOR Check: Verify ownership or admin privilege
    # SR-005: CRITICAL — every file access verifies ownership server-side
    if not verify_resource_ownership(
        resource_owner_id=file_record.owner_id,
        requesting_user=request.user,
        allow_admin=True,
    ):
        # Check if file has been shared with this user
        if not FileShare.objects.filter(
            file=file_record,
            shared_with=request.user,
            is_active=True,
        ).exists():
            security_log.warning(
                "file.download.idor_blocked",
                extra={
                    "requesting_user": str(request.user.id),
                    "file_owner": str(file_record.owner_id),
                    "file_id": file_id,
                },
            )
            return Response(
                {"detail": "File not found."},  # Intentionally vague
                status=status.HTTP_404_NOT_FOUND,
            )

    # Generate pre-signed URL
    storage = StorageBackend()
    try:
        presigned_url = storage.generate_presigned_url(
            key=file_record.storage_key,
            expiry=settings.PRESIGNED_URL_EXPIRY,
        )
    except Exception as e:
        security_log.error(
            "file.download.presign_error",
            extra={"file_id": file_id, "error": str(e)},
        )
        return Response(
            {"detail": "Could not generate download link."},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    audit_log.info(
        "file.download",
        extra={
            "user_id": str(request.user.id),
            "file_id": file_id,
            "outcome": "success",
        },
    )

    return Response({
        "file_id": file_id,
        "filename": file_record.original_filename,
        "download_url": presigned_url,
        "url_expires_in": settings.PRESIGNED_URL_EXPIRY,
        "size": file_record.file_size,
        "sha256": file_record.sha256_hash,
    })


# ─────────────────────────────────────────────
# FILE DELETE
# ─────────────────────────────────────────────
@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
@require_permission(Permission.FILE_DELETE_OWN)
def delete_file(request, file_id: str):
    """
    Delete a file. Users can only delete files they own.
    Admins can delete any file.
    """
    try:
        uuid.UUID(file_id)
    except ValueError:
        return Response({"detail": "Invalid file identifier."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        file_record = FileRecord.objects.get(id=file_id)
    except FileRecord.DoesNotExist:
        return Response({"detail": "File not found."}, status=status.HTTP_404_NOT_FOUND)

    if not verify_resource_ownership(file_record.owner_id, request.user):
        return Response({"detail": "File not found."}, status=status.HTTP_404_NOT_FOUND)

    # Delete from storage
    storage = StorageBackend()
    try:
        storage.delete_object(file_record.storage_key)
    except Exception as e:
        security_log.error("file.delete.storage_error", extra={"file_id": file_id, "error": str(e)})

    # Delete DB record (cascade deletes shares)
    file_record.delete()

    audit_log.info(
        "file.delete",
        extra={"user_id": str(request.user.id), "file_id": file_id, "outcome": "success"},
    )

    return Response({"detail": "File deleted successfully."}, status=status.HTTP_200_OK)


# ─────────────────────────────────────────────
# LIST USER'S FILES
# ─────────────────────────────────────────────
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_files(request):
    """
    List files owned by the authenticated user.
    Users only see their own files (IDOR protection by design).
    """
    files = FileRecord.objects.filter(
        owner=request.user
    ).order_by("-uploaded_at").values(
        "id", "original_filename", "file_size", "mime_type", "uploaded_at", "scan_status"
    )

    # Pagination
    page = max(1, int(request.GET.get("page", 1)))
    per_page = min(50, int(request.GET.get("per_page", 20)))
    offset = (page - 1) * per_page

    total = files.count()
    page_data = list(files[offset:offset + per_page])

    return Response({
        "files": page_data,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
    })
