"""
SecureVault — ClamAV Antivirus Integration
Scans uploaded files before storage.
SR-009: All uploads scanned with ClamAV before storage.
Reference: docs/architecture/SECURE-DESIGN-DOCUMENT.md Section 3.2 Step 5
"""

import socket
import struct
import logging
from dataclasses import dataclass
from typing import Optional

from django.conf import settings

security_log = logging.getLogger("securevault.security")
audit_log = logging.getLogger("securevault.audit")


@dataclass
class ScanResult:
    """Result of a ClamAV scan."""
    is_clean: bool
    threat_name: Optional[str] = None
    error: Optional[str] = None
    bytes_scanned: int = 0


class ClamAVError(Exception):
    """Raised when ClamAV connection or scan fails."""
    pass


def scan_file_with_clamav(file_data: bytes) -> ScanResult:
    """
    Scan file data using ClamAV daemon (clamd).
    Uses INSTREAM command to scan file content directly without writing to disk.

    Protocol:
    1. Connect to clamd on TCP (host:port from settings)
    2. Send INSTREAM command
    3. Send file data in chunks: 4-byte length + data
    4. Send zero-length chunk to signal end of stream
    5. Receive response: "stream: OK" or "stream: FOUND <threat>"

    Returns ScanResult with is_clean=False and threat_name if malware detected.
    """
    if not file_data:
        return ScanResult(is_clean=False, error="Empty file data")

    host = settings.CLAMAV_HOST
    port = settings.CLAMAV_PORT
    timeout = settings.CLAMAV_TIMEOUT

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)

            # Send INSTREAM command
            sock.sendall(b"zINSTREAM\0")

            # Send file data in chunks of 4096 bytes
            chunk_size = 4096
            total_sent = 0
            for i in range(0, len(file_data), chunk_size):
                chunk = file_data[i:i + chunk_size]
                size_header = struct.pack("!I", len(chunk))  # 4-byte big-endian length
                sock.sendall(size_header + chunk)
                total_sent += len(chunk)

            # Signal end of stream with zero-length chunk
            sock.sendall(struct.pack("!I", 0))

            # Receive response
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
                if b"\x00" in data or b"\n" in data:
                    break

            response_str = response.strip(b"\x00\n ").decode("utf-8", errors="replace")
            return _parse_scan_response(response_str, total_sent)

    except socket.timeout:
        error_msg = f"ClamAV scan timed out after {timeout}s"
        security_log.error("clamav.timeout", extra={"host": host, "port": port})
        # On timeout, REJECT the file (fail-safe)
        return ScanResult(is_clean=False, error=error_msg)

    except ConnectionRefusedError:
        error_msg = f"ClamAV daemon not reachable at {host}:{port}"
        security_log.critical("clamav.unavailable", extra={"host": host, "port": port})
        # On connection failure, REJECT the file (fail-safe — never store unscanned files)
        return ScanResult(is_clean=False, error=error_msg)

    except Exception as e:
        security_log.error("clamav.error", extra={"error": str(e)})
        # Any error = reject (fail-safe)
        return ScanResult(is_clean=False, error=str(e))


def _parse_scan_response(response: str, bytes_scanned: int) -> ScanResult:
    """
    Parse ClamAV response string.
    Response formats:
    - "stream: OK"                    → clean
    - "stream: FOUND Trojan.XYZ"      → malware detected
    - "stream: ERROR <message>"       → scan error
    """
    response = response.strip()

    if response.endswith("OK"):
        return ScanResult(is_clean=True, bytes_scanned=bytes_scanned)

    if "FOUND" in response:
        # Extract threat name: "stream: FOUND Trojan.Generic.XYZ"
        parts = response.split("FOUND", 1)
        threat_name = parts[1].strip() if len(parts) > 1 else "Unknown"
        security_log.critical(
            "clamav.malware_detected",
            extra={"threat": threat_name, "bytes_scanned": bytes_scanned},
        )
        return ScanResult(
            is_clean=False,
            threat_name=threat_name,
            bytes_scanned=bytes_scanned,
        )

    if "ERROR" in response:
        error_msg = response.split("ERROR", 1)[1].strip() if "ERROR" in response else response
        security_log.error("clamav.scan_error", extra={"response": response})
        # Error = reject (fail-safe)
        return ScanResult(is_clean=False, error=error_msg, bytes_scanned=bytes_scanned)

    # Unknown response format — reject (fail-safe)
    security_log.warning("clamav.unknown_response", extra={"response": response[:200]})
    return ScanResult(is_clean=False, error=f"Unknown ClamAV response: {response[:100]}")


def check_clamav_connection() -> dict:
    """
    Health check: verify ClamAV daemon is reachable and responding.
    Used by /health/ endpoint and monitoring.
    """
    host = settings.CLAMAV_HOST
    port = settings.CLAMAV_PORT

    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            sock.sendall(b"PING\n")
            response = sock.recv(100).strip()
            if response == b"PONG":
                return {"status": "healthy", "host": host, "port": port}
            return {"status": "error", "response": response.decode()[:50]}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)}
