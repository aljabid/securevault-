"""
SecureVault — File Validators
Server-side validation for uploaded files.
SR-010: MIME type validated via magic bytes (not extension)
SR-012: File size limited server-side
"""

import re
import os
import struct
from typing import Optional, Tuple
from django.conf import settings

# ─────────────────────────────────────────────
# MAGIC BYTES SIGNATURES
# Each entry: (offset, bytes_to_match, mime_type, description)
# ─────────────────────────────────────────────
MAGIC_SIGNATURES = [
    # Images
    (0, b"\xff\xd8\xff", "image/jpeg", "JPEG"),
    (0, b"\x89PNG\r\n\x1a\n", "image/png", "PNG"),
    (0, b"GIF87a", "image/gif", "GIF87"),
    (0, b"GIF89a", "image/gif", "GIF89"),
    (0, b"RIFF", "image/webp", "WEBP"),  # Also check offset 8 for WEBP
    (0, b"<svg", "image/svg+xml", "SVG"),

    # Documents
    (0, b"%PDF-", "application/pdf", "PDF"),
    (0, b"PK\x03\x04", "application/zip", "ZIP/DOCX/XLSX/PPTX"),  # Office Open XML
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/msword", "DOC/XLS/PPT"),

    # Archives
    (0, b"\x1f\x8b", "application/gzip", "GZIP"),
    (0, b"BZh", "application/x-bzip2", "BZIP2"),
    (0, b"\x52\x61\x72\x21", "application/x-rar-compressed", "RAR"),

    # Text/data (no magic bytes, detected by content analysis)
    (None, None, "text/plain", "TEXT"),
    (None, None, "text/csv", "CSV"),
    (None, None, "application/json", "JSON"),

    # Executable / dangerous signatures (BLOCKED)
    (0, b"MZ", None, "PE_EXECUTABLE"),           # Windows EXE/DLL
    (0, b"\x7fELF", None, "ELF_EXECUTABLE"),      # Linux ELF
    (0, b"\xca\xfe\xba\xbe", None, "JAVA_CLASS"), # Java class file
    (0, b"PK\x03\x04", None, "JAR_POSSIBLE"),     # Could be JAR
]

# ─────────────────────────────────────────────
# BLOCKED PATTERNS
# ─────────────────────────────────────────────
BLOCKED_EXTENSIONS = {
    # Executables
    ".exe", ".dll", ".so", ".dylib", ".sys", ".com",
    # Scripts
    ".sh", ".bash", ".zsh", ".fish", ".bat", ".cmd", ".ps1", ".psm1",
    # Web scripts
    ".php", ".php3", ".php4", ".php5", ".phtml", ".asp", ".aspx",
    ".jsp", ".jspx", ".cgi", ".pl", ".py", ".rb",
    # Java
    ".jar", ".class", ".war", ".ear",
    # Other dangerous
    ".msi", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".scr", ".pif", ".reg", ".lnk",
}

BLOCKED_MIME_TYPES = {
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-dosexec",
    "application/java-archive",
    "text/x-php",
    "application/x-httpd-php",
    "application/x-sh",
    "text/x-shellscript",
}

# Path traversal patterns
PATH_TRAVERSAL_PATTERN = re.compile(
    r"(\.\.|%2e%2e|%252e|\.%2f|%2f\.)", re.IGNORECASE
)

# Null byte injection
NULL_BYTE_PATTERN = re.compile(r"[\x00]")

# Valid filename characters (strict whitelist)
SAFE_FILENAME_PATTERN = re.compile(r"^[a-zA-Z0-9._\-\s]{1,255}$")


def sanitize_filename(filename: str) -> Optional[str]:
    """
    Sanitize filename to prevent path traversal, null byte injection,
    and other filename-based attacks.

    Returns sanitized filename or None if filename is invalid/dangerous.
    """
    if not filename:
        return None

    # Remove null bytes
    filename = filename.replace("\x00", "")

    # Extract just the basename (no directory components)
    filename = os.path.basename(filename)

    # URL decode to catch encoded traversal
    try:
        from urllib.parse import unquote
        filename = unquote(filename)
    except Exception:
        pass

    # Check for path traversal after decoding
    if PATH_TRAVERSAL_PATTERN.search(filename):
        return None

    # Strip leading/trailing whitespace and dots
    filename = filename.strip(". ")

    # Replace spaces with underscores
    filename = filename.replace(" ", "_")

    # Validate against safe character set
    if not SAFE_FILENAME_PATTERN.match(filename):
        # Remove any character that's not alphanumeric, dot, dash, or underscore
        filename = re.sub(r"[^a-zA-Z0-9._\-]", "_", filename)

    # Ensure it's not empty and not too long
    if not filename or len(filename) > 255:
        return None

    # Ensure there's still an extension
    _, ext = os.path.splitext(filename)
    if not ext:
        return None

    return filename.lower()


def validate_file_extension(filename: str) -> Optional[str]:
    """
    Validate file extension against whitelist.
    Returns error message string or None if valid.
    """
    _, ext = os.path.splitext(filename.lower())

    if not ext:
        return "File must have an extension."

    if ext in BLOCKED_EXTENSIONS:
        return f"File type '{ext}' is not permitted."

    if ext not in settings.ALLOWED_FILE_EXTENSIONS:
        return f"File type '{ext}' is not supported. Allowed types: {', '.join(sorted(settings.ALLOWED_FILE_EXTENSIONS))}"

    return None


def validate_mime_type_magic_bytes(
    file_bytes: bytes,
    filename: str,
) -> Tuple[Optional[str], str]:
    """
    Validate MIME type using magic bytes (file content inspection).
    Does NOT trust file extension or Content-Type header.

    Returns: (error_message or None, detected_mime_type)
    SR-010: Critical security control.
    """
    if not file_bytes:
        return "Empty file is not permitted.", "application/octet-stream"

    # Check for dangerous magic bytes first
    dangerous_checks = [
        (b"MZ", "Windows executable"),
        (b"\x7fELF", "Linux executable"),
        (b"\xca\xfe\xba\xbe", "Java class"),
        (b"#!/", "Script file"),
        (b"<script", "Script content"),
        (b"<?php", "PHP script"),
    ]

    for pattern, description in dangerous_checks:
        if file_bytes.startswith(pattern) or file_bytes[:8192].find(pattern) != -1:
            return f"Dangerous file content detected ({description}).", "application/octet-stream"

    # Detect MIME type from magic bytes
    detected_mime = _detect_mime_from_magic(file_bytes, filename)

    # Check detected MIME against blocklist
    if detected_mime in BLOCKED_MIME_TYPES:
        return f"File type '{detected_mime}' is not permitted.", detected_mime

    # Check for MIME type mismatch (extension says PDF, content says EXE)
    _, ext = os.path.splitext(filename.lower())
    expected_mimes = _get_expected_mimes_for_extension(ext)
    if expected_mimes and detected_mime not in expected_mimes:
        # Allow some flexibility for Office formats (ZIP-based)
        if not (ext in {".docx", ".xlsx", ".pptx"} and detected_mime == "application/zip"):
            return (
                f"File content does not match the file extension. "
                f"Expected: {expected_mimes}, Detected: {detected_mime}",
                detected_mime,
            )

    return None, detected_mime


def validate_file_size(file_size: int) -> Optional[str]:
    """
    Validate file size against configured maximum.
    Returns error message or None if valid.
    SR-012: File size limited to 50MB server-side.
    """
    max_size = settings.MAX_FILE_SIZE_BYTES
    if file_size > max_size:
        max_mb = max_size // (1024 * 1024)
        actual_mb = file_size / (1024 * 1024)
        return f"File size ({actual_mb:.1f}MB) exceeds maximum allowed ({max_mb}MB)."
    if file_size == 0:
        return "Empty files are not permitted."
    return None


def _detect_mime_from_magic(file_bytes: bytes, filename: str) -> str:
    """Detect MIME type from magic bytes."""
    # JPEG
    if file_bytes[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    # PNG
    if file_bytes[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    # GIF
    if file_bytes[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    # PDF
    if file_bytes[:5] == b"%PDF-":
        return "application/pdf"
    # GZIP
    if file_bytes[:2] == b"\x1f\x8b":
        return "application/gzip"
    # ZIP / Office Open XML (DOCX, XLSX, PPTX)
    if file_bytes[:4] == b"PK\x03\x04":
        _, ext = os.path.splitext(filename.lower())
        if ext == ".docx":
            return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        if ext == ".xlsx":
            return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        if ext == ".pptx":
            return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        return "application/zip"
    # Old Office formats
    if file_bytes[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "application/msword"
    # WEBP
    if file_bytes[:4] == b"RIFF" and file_bytes[8:12] == b"WEBP":
        return "image/webp"
    # SVG (text-based)
    if b"<svg" in file_bytes[:256]:
        return "image/svg+xml"

    # Try to detect text types
    try:
        sample = file_bytes[:4096].decode("utf-8", errors="strict")
        if sample.strip().startswith("{") or sample.strip().startswith("["):
            return "application/json"
        if sample.strip().startswith("<?xml") or sample.strip().startswith("<"):
            return "application/xml"
        # Check if it looks like CSV (commas, quotes, newlines)
        if "," in sample and ("\n" in sample or "\r" in sample):
            _, ext = os.path.splitext(filename.lower())
            if ext == ".csv":
                return "text/csv"
        return "text/plain"
    except UnicodeDecodeError:
        pass

    return "application/octet-stream"


def _get_expected_mimes_for_extension(ext: str) -> set:
    """Return expected MIME types for a given extension."""
    mapping = {
        ".jpg": {"image/jpeg"},
        ".jpeg": {"image/jpeg"},
        ".png": {"image/png"},
        ".gif": {"image/gif"},
        ".webp": {"image/webp"},
        ".pdf": {"application/pdf"},
        ".txt": {"text/plain"},
        ".csv": {"text/csv", "text/plain"},
        ".json": {"application/json", "text/plain"},
        ".zip": {"application/zip"},
        ".gz": {"application/gzip"},
        ".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/zip"},
        ".xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/zip"},
        ".pptx": {"application/vnd.openxmlformats-officedocument.presentationml.presentation", "application/zip"},
        ".doc": {"application/msword"},
        ".xls": {"application/vnd.ms-excel", "application/msword"},
    }
    return mapping.get(ext, set())
