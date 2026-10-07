"""
File scanner: handles uploads, safe zip extraction, and orchestrates multi-layer analysis.
"""

import os
import zipfile
import tempfile
import time
import uuid
from datetime import datetime, timezone
from typing import List, Tuple
from fastapi import HTTPException

from app.core.analyzer import analyze_file, analyze_project
from app.core.security_guard import SecurityGuard, SecurityValidationError
from app.schemas.models import VulnerabilityResult, ScanSummary, ScanResponse

SUPPORTED_EXTENSIONS = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB per file



def _collect_source_files(directory: str) -> List[Tuple[str, str]]:
    """Recursively find all C/C++ source files. Returns (filepath, rel_path) tuples."""
    found = []
    for root, _, files in os.walk(directory):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in SUPPORTED_EXTENSIONS:
                full = os.path.join(root, fname)
                rel = os.path.relpath(full, directory)
                found.append((full, rel))
    return sorted(found)


def _build_summary(results: List[VulnerabilityResult], duration_ms: int) -> ScanSummary:
    vuln_type_counts = {}
    analyzer_breakdown = {}
    high = medium = low = 0

    for r in results:
        vuln_type_counts[r.vulnerability] = vuln_type_counts.get(r.vulnerability, 0) + 1
        src = r.analyzer_source or "ast"
        analyzer_breakdown[src] = analyzer_breakdown.get(src, 0) + 1

        if r.severity in ("CRITICAL", "HIGH"):
            high += 1
        elif r.severity == "MEDIUM":
            medium += 1
        else:
            low += 1

    return ScanSummary(
        total_files=0,  # set by caller
        total_vulnerabilities=len(results),
        high_risk=high,
        medium_risk=medium,
        low_risk=low,
        scan_duration_ms=duration_ms,
        vulnerability_types=vuln_type_counts,
        analyzer_breakdown=analyzer_breakdown,
    )


async def scan_single_file(filename: str, content: bytes) -> ScanResponse:
    """Analyze a single uploaded source file safely."""
    t0 = time.monotonic()
    scan_id = str(uuid.uuid4())

    safe_name = SecurityGuard.sanitize_filename(filename)
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"Security violation: File exceeds maximum allowed size of {MAX_FILE_SIZE} bytes."
        )

    try:
        source = content.decode("utf-8", errors="replace")
    except Exception:
        source = ""

    results = analyze_file(safe_name, source)
    duration_ms = int((time.monotonic() - t0) * 1000)

    summary = _build_summary(results, duration_ms)
    summary.total_files = 1

    return ScanResponse(
        scan_id=scan_id,
        timestamp=datetime.now(timezone.utc),
        results=results,
        summary=summary,
    )


async def scan_zip_folder(zip_content: bytes) -> ScanResponse:
    """Extract zip safely with SecurityGuard quotas and scan all C/C++ files."""
    t0 = time.monotonic()
    scan_id = str(uuid.uuid4())
    all_results: List[VulnerabilityResult] = []

    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, "upload.zip")
        with open(zip_path, "wb") as f:
            f.write(zip_content)

        try:
            extracted_files = SecurityGuard.validate_and_extract_zip(zip_path, tmpdir)
        except SecurityValidationError as e:
            raise HTTPException(status_code=400, detail=str(e))

        total_files = len(extracted_files)

        file_tuples: List[Tuple[str, str]] = []
        for full_path in extracted_files:
            rel_path = os.path.relpath(full_path, tmpdir)
            try:
                source = SecurityGuard.read_safe_source_code(full_path)
                file_tuples.append((rel_path, source))
            except Exception as e:
                print(f"[FileScanner] Warning: failed to read {rel_path}: {e}")
                continue

        all_results = analyze_project(file_tuples)


    duration_ms = int((time.monotonic() - t0) * 1000)
    all_results.sort(key=lambda r: (-r.risk_score, r.file, r.line))

    summary = _build_summary(all_results, duration_ms)
    summary.total_files = total_files

    return ScanResponse(
        scan_id=scan_id,
        timestamp=datetime.now(timezone.utc),
        results=all_results,
        summary=summary,
    )

