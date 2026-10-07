"""
Cross-File IPA Baseline Experiment Runner.

Uses the PRODUCTION scan pipeline (scan_single_file / scan_zip_folder)
to test whether multi-file vulnerability patterns are detected.

NO PRODUCTION CODE IS MODIFIED.
This script only reads experiment corpus files and invokes the existing pipeline.
"""

import os
import sys
import json
import zipfile
import asyncio
import io
from typing import List, Dict, Any, Optional

# Ensure backend is on the path
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, BACKEND_DIR)

from app.core.file_scanner import scan_single_file, scan_zip_folder
from app.schemas.models import ScanResponse, VulnerabilityResult

EXPERIMENT_DIR = os.path.dirname(os.path.abspath(__file__))


def format_finding(r: VulnerabilityResult) -> Dict[str, Any]:
    """Extract key fields from a VulnerabilityResult for reporting."""
    return {
        "file": r.file,
        "line": r.line,
        "column": getattr(r, "column", None),
        "vulnerability": r.vulnerability,
        "rule_id": r.rule_id,
        "cwe": r.cwe,
        "severity": r.severity,
        "confidence": r.confidence,
        "risk_score": r.risk_score,
        "analyzer_source": r.analyzer_source,
        "analysis_status": getattr(r, "analysis_status", None),
        "explanation": r.explanation,
        "dataflow_path": getattr(r, "dataflow_path", None),
    }


async def run_single_file_scan(filepath: str) -> Dict[str, Any]:
    """Scan a single C/C++ source file through the production pipeline."""
    filename = os.path.basename(filepath)
    with open(filepath, "rb") as f:
        content = f.read()

    try:
        response: ScanResponse = await scan_single_file(filename, content)
        findings = [format_finding(r) for r in response.results]
        return {
            "scan_id": response.scan_id,
            "file": filename,
            "total_findings": response.summary.total_vulnerabilities,
            "high_risk": response.summary.high_risk,
            "medium_risk": response.summary.medium_risk,
            "low_risk": response.summary.low_risk,
            "scan_duration_ms": response.summary.scan_duration_ms,
            "findings": findings,
        }
    except Exception as e:
        return {
            "file": filename,
            "error": str(e),
            "total_findings": 0,
            "findings": [],
        }


async def run_multi_file_zip_scan(experiment_dir: str, experiment_name: str) -> Dict[str, Any]:
    """
    Package a directory of C files into a ZIP and scan through the production
    scan_zip_folder() pipeline — exactly as a user would upload a ZIP project.
    """
    # Build in-memory ZIP
    zip_buffer = io.BytesIO()
    file_list = []
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(experiment_dir):
            for fname in sorted(files):
                full_path = os.path.join(root, fname)
                arc_name = os.path.relpath(full_path, experiment_dir)
                zf.write(full_path, arc_name)
                file_list.append(arc_name)

    zip_bytes = zip_buffer.getvalue()

    try:
        response: ScanResponse = await scan_zip_folder(zip_bytes)
        findings = [format_finding(r) for r in response.results]
        return {
            "scan_id": response.scan_id,
            "experiment": experiment_name,
            "files_in_zip": file_list,
            "total_files_scanned": response.summary.total_files,
            "total_findings": response.summary.total_vulnerabilities,
            "high_risk": response.summary.high_risk,
            "medium_risk": response.summary.medium_risk,
            "low_risk": response.summary.low_risk,
            "scan_duration_ms": response.summary.scan_duration_ms,
            "findings": findings,
        }
    except Exception as e:
        return {
            "experiment": experiment_name,
            "files_in_zip": file_list,
            "error": str(e),
            "total_findings": 0,
            "findings": [],
        }


async def main():
    results = {}
    output_path = os.path.join(EXPERIMENT_DIR, "experiment_results.json")

    # ═══════════════════════════════════════════════════════════════════
    # SINGLE-FILE CONTROLS
    # ═══════════════════════════════════════════════════════════════════
    controls_dir = os.path.join(EXPERIMENT_DIR, "controls")
    control_files = [
        ("control_a_taint", "single_file_taint.c"),
        ("control_b_uaf", "single_file_uaf.c"),
        ("control_c_safe", "single_file_safe.c"),
        ("control_d_alias", "single_file_alias.c"),
        ("control_e_struct", "single_file_struct.c"),
    ]

    print("=" * 70)
    print("PHASE 1: SINGLE-FILE CONTROLS")
    print("=" * 70)

    for key, fname in control_files:
        filepath = os.path.join(controls_dir, fname)
        print(f"\n--- Scanning: {fname} ---")
        result = await run_single_file_scan(filepath)
        results[key] = result
        print(f"  Total findings: {result['total_findings']}")
        for f in result["findings"]:
            print(f"    [{f['rule_id']}] {f['cwe']} | {f['severity']} | "
                  f"conf={f['confidence']} | {f['vulnerability']}")
            print(f"      >> {f['explanation'][:120]}")

    # ═══════════════════════════════════════════════════════════════════
    # MULTI-FILE EXPERIMENTS (via ZIP pipeline)
    # ═══════════════════════════════════════════════════════════════════
    multi_file_experiments = [
        ("exp_a_taint", "exp_a_taint"),
        ("exp_b_uaf", "exp_b_uaf"),
        ("exp_c_safe", "exp_c_safe"),
        ("exp_d_alias", "exp_d_alias"),
        ("exp_e_struct", "exp_e_struct"),
    ]

    print("\n" + "=" * 70)
    print("PHASE 2: MULTI-FILE EXPERIMENTS (ZIP PIPELINE)")
    print("=" * 70)

    for key, dirname in multi_file_experiments:
        exp_dir = os.path.join(EXPERIMENT_DIR, dirname)
        print(f"\n--- Scanning ZIP: {dirname}/ ---")
        result = await run_multi_file_zip_scan(exp_dir, dirname)
        results[key] = result
        print(f"  Files in ZIP: {result.get('files_in_zip', [])}")
        print(f"  Files scanned: {result.get('total_files_scanned', '?')}")
        print(f"  Total findings: {result['total_findings']}")
        if result.get("error"):
            print(f"  ERROR: {result['error']}")
        for f in result["findings"]:
            print(f"    [{f['rule_id']}] {f['cwe']} | {f['severity']} | "
                  f"conf={f['confidence']} | L{f['line']} {f['file']}")
            print(f"      >> {f['vulnerability']}")
            print(f"      >> {f['explanation'][:150]}")

    # ═══════════════════════════════════════════════════════════════════
    # SAVE RAW RESULTS
    # ═══════════════════════════════════════════════════════════════════
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n\n{'=' * 70}")
    print(f"RAW RESULTS SAVED TO: {output_path}")
    print(f"{'=' * 70}")

    # ═══════════════════════════════════════════════════════════════════
    # SUMMARY MATRIX
    # ═══════════════════════════════════════════════════════════════════
    print(f"\n{'=' * 70}")
    print("RESULTS MATRIX")
    print(f"{'=' * 70}\n")

    experiments = [
        ("A: Taint", "control_a_taint", "exp_a_taint", True),
        ("B: UAF", "control_b_uaf", "exp_b_uaf", True),
        ("C: Safe", "control_c_safe", "exp_c_safe", False),
        ("D: Alias", "control_d_alias", "exp_d_alias", True),
        ("E: Struct", "control_e_struct", "exp_e_struct", True),
    ]

    header = f"{'Experiment':<20} {'SF Expect':<12} {'SF Actual':<12} {'SF Count':<10} {'MF Expect':<12} {'MF Actual':<12} {'MF Count':<10} {'Cross-File Gap?'}"
    print(header)
    print("-" * len(header))

    for name, ctrl_key, exp_key, expect_vuln in experiments:
        sf_expected = "VULNERABLE" if expect_vuln else "SAFE"
        mf_expected = "VULNERABLE" if expect_vuln else "SAFE"

        sf_count = results[ctrl_key]["total_findings"]
        mf_count = results[exp_key]["total_findings"]

        sf_actual = "DETECTED" if sf_count > 0 else "CLEAN"
        mf_actual = "DETECTED" if mf_count > 0 else "CLEAN"

        if expect_vuln:
            cross_file_gap = "YES — cross-file miss" if (sf_count > 0 and mf_count == 0) else \
                             "NO — both detect" if (sf_count > 0 and mf_count > 0) else \
                             "BOTH MISS" if (sf_count == 0 and mf_count == 0) else \
                             "UNEXPECTED"
        else:
            cross_file_gap = "FALSE POS (SF)" if (sf_count > 0 and mf_count == 0) else \
                             "FALSE POS (BOTH)" if (sf_count > 0 and mf_count > 0) else \
                             "CORRECT (BOTH)" if (sf_count == 0 and mf_count == 0) else \
                             "FALSE POS (MF)"

        print(f"{name:<20} {sf_expected:<12} {sf_actual:<12} {sf_count:<10} "
              f"{mf_expected:<12} {mf_actual:<12} {mf_count:<10} {cross_file_gap}")


if __name__ == "__main__":
    asyncio.run(main())
