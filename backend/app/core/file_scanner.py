"""
File scanner: handles uploads, extracts .c/.cpp files, orchestrates analysis.
"""

import os
import zipfile
import tempfile
import time
import uuid
from datetime import datetime, timezone
from typing import List, Tuple

from app.core.analyzer import analyze_file
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
    high = medium = low = 0

    for r in results:
        vuln_type_counts[r.vulnerability] = vuln_type_counts.get(r.vulnerability, 0) + 1
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
    )


async def scan_single_file(filename: str, content: bytes) -> ScanResponse:
    """Analyze a single uploaded source file."""
    t0 = time.monotonic()
    scan_id = str(uuid.uuid4())

    try:
        source = content.decode("utf-8", errors="replace")
    except Exception:
        source = ""

    results = analyze_file(filename, source)
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
    """Extract zip, recursively scan all C/C++ files."""
    t0 = time.monotonic()
    scan_id = str(uuid.uuid4())
    all_results: List[VulnerabilityResult] = []

    with tempfile.TemporaryDirectory() as tmpdir:
        zip_path = os.path.join(tmpdir, "upload.zip")
        with open(zip_path, "wb") as f:
            f.write(zip_content)

        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(tmpdir)

        source_files = _collect_source_files(tmpdir)
        total_files = len(source_files)

        for full_path, rel_path in source_files:
            file_size = os.path.getsize(full_path)
            if file_size > MAX_FILE_SIZE:
                continue
            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    source = f.read()
                file_results = analyze_file(rel_path, source)
                # Tag with relative path
                for r in file_results:
                    r.file = rel_path
                all_results.extend(file_results)
            except Exception:
                continue

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
