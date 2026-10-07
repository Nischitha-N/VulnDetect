"""
Security Guard & Input Hardening Layer for VulnDetect.
Protects the scanner against malicious inputs, Zip Slip, decompression bombs,
oversized files, and parser resource exhaustion.
"""

import os
import zipfile
import tempfile
from typing import List, Tuple, Dict, Any, Optional

# Security Quotas & Hard Limits
MAX_ARCHIVE_SIZE_BYTES = 50 * 1024 * 1024       # 50 MB max zip upload
MAX_TOTAL_UNCOMPRESSED_BYTES = 100 * 1024 * 1024 # 100 MB max total extracted
MAX_SINGLE_FILE_BYTES = 10 * 1024 * 1024         # 10 MB max per source file
MAX_FILE_COUNT = 500                             # 500 files max per archive
MAX_COMPRESSION_RATIO = 100.0                    # 100:1 ratio limit (zip bomb defense)
MAX_LINE_LENGTH_BYTES = 16 * 1024                # 16 KB max per source line (parser crash defense)

VALID_SOURCE_EXTENSIONS = {
    ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx", ".hh", ".i", ".ii"
}


class SecurityValidationError(Exception):
    """Raised when an input archive or file violates scanner safety quotas."""
    pass


class SecurityGuard:
    """Hardened security boundary for scanner inputs."""

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Strip null bytes, control characters, and path separators."""
        if not filename:
            return "unnamed_file"
        # Null-byte injection defense
        cleaned = filename.replace("\0", "").replace("\r", "").replace("\n", "")
        # Remove any path traversal components from filename
        cleaned = os.path.basename(cleaned)
        return cleaned if cleaned else "unnamed_file"

    @staticmethod
    def is_safe_source_file(file_path: str) -> bool:
        """Check if file has an allowed C/C++ extension."""
        ext = os.path.splitext(file_path)[1].lower()
        return ext in VALID_SOURCE_EXTENSIONS

    @staticmethod
    def validate_and_extract_zip(zip_path: str, target_dir: str) -> List[str]:
        """
        Safely extracts an untrusted zip archive with defenses against:
          - Zip Slip (path traversal / symlink escape)
          - Zip Bombs (decompression ratio & total size limits)
          - Excessive file counts
          - Malformed entries
        Returns list of safe extracted file paths.
        """
        if not os.path.exists(zip_path):
            raise SecurityValidationError(f"Archive file does not exist: {zip_path}")

        archive_size = os.path.getsize(zip_path)
        if archive_size > MAX_ARCHIVE_SIZE_BYTES:
            raise SecurityValidationError(
                f"Archive size ({archive_size} bytes) exceeds safety limit ({MAX_ARCHIVE_SIZE_BYTES} bytes)."
            )

        extracted_files: List[str] = []
        total_uncompressed_bytes = 0
        file_count = 0
        canonical_target_dir = os.path.abspath(target_dir)

        with zipfile.ZipFile(zip_path, "r") as zf:
            infolist = zf.infolist()

            if len(infolist) > MAX_FILE_COUNT:
                raise SecurityValidationError(
                    f"Archive contains {len(infolist)} entries, exceeding maximum limit of {MAX_FILE_COUNT} files."
                )

            for member in infolist:
                # 1. Zip Slip Defense: verify destination is strictly inside target_dir
                # Normalize member path
                member_path = member.filename.replace("\\", "/")
                # Strip leading slashes / drive letters
                member_path = member_path.lstrip("/").lstrip("\\")
                if member_path.startswith("../") or "/../" in member_path or member_path == "..":
                    raise SecurityValidationError(
                        f"Zip Slip attack detected in archive entry: '{member.filename}'"
                    )

                dest_path = os.path.abspath(os.path.join(canonical_target_dir, member_path))
                if not dest_path.startswith(canonical_target_dir + os.sep) and dest_path != canonical_target_dir:
                    raise SecurityValidationError(
                        f"Zip Slip path escape attempt: '{member.filename}' -> '{dest_path}'"
                    )

                # Skip directories
                if member.is_dir():
                    continue

                file_count += 1
                uncompressed_size = member.file_size
                compressed_size = member.compress_size or 1
                total_uncompressed_bytes += uncompressed_size

                # 2. Decompression Bomb Defenses
                if total_uncompressed_bytes > MAX_TOTAL_UNCOMPRESSED_BYTES:
                    raise SecurityValidationError(
                        f"Zip bomb defense: Total uncompressed archive size exceeded {MAX_TOTAL_UNCOMPRESSED_BYTES} bytes."
                    )

                ratio = uncompressed_size / compressed_size
                if ratio > MAX_COMPRESSION_RATIO and uncompressed_size > 1024 * 1024:
                    raise SecurityValidationError(
                        f"Zip bomb defense: Entry '{member.filename}' has excessive compression ratio ({ratio:.1f}:1)."
                    )

                if uncompressed_size > MAX_SINGLE_FILE_BYTES:
                    raise SecurityValidationError(
                        f"Single file '{member.filename}' ({uncompressed_size} bytes) exceeds per-file limit of {MAX_SINGLE_FILE_BYTES} bytes."
                    )

                # Only extract valid C/C++ source code or headers
                if SecurityGuard.is_safe_source_file(dest_path):
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    # Extract safely using stream read
                    with zf.open(member) as source_stream, open(dest_path, "wb") as dest_file:
                        bytes_written = 0
                        while chunk := source_stream.read(64 * 1024):
                            bytes_written += len(chunk)
                            if bytes_written > MAX_SINGLE_FILE_BYTES:
                                raise SecurityValidationError(
                                    f"File '{member.filename}' expanded beyond quota during streaming."
                                )
                            dest_file.write(chunk)
                    extracted_files.append(dest_path)

        return extracted_files

    @staticmethod
    def read_safe_source_code(file_path: str) -> str:
        """
        Reads source code with file size and line length limits
        to protect against parser crashes or memory exhaustion.
        """
        if not os.path.exists(file_path):
            return ""

        file_size = os.path.getsize(file_path)
        if file_size > MAX_SINGLE_FILE_BYTES:
            raise SecurityValidationError(
                f"Source file {os.path.basename(file_path)} exceeds safety limit ({file_size} > {MAX_SINGLE_FILE_BYTES} bytes)."
            )

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        # Sanitize overly long single lines that could cause parser backtracking crashes
        lines = content.splitlines()
        sanitized_lines = []
        for line in lines:
            if len(line.encode("utf-8", errors="replace")) > MAX_LINE_LENGTH_BYTES:
                sanitized_lines.append(line[:MAX_LINE_LENGTH_BYTES] + " /* ... truncated by SecurityGuard ... */")
            else:
                sanitized_lines.append(line)

        return "\n".join(sanitized_lines)
