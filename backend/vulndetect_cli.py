#!/usr/bin/env python3
"""
VulnDetect Command Line Interface (CLI).
Industrial-grade C/C++ Static Security Analysis Tool.
"""

import os
import sys
import argparse
import json
import time

# Ensure backend root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.analyzer import analyze_file
from app.core.config_loader import ConfigLoader, ProjectConfig
from app.core.security_guard import SecurityGuard
from app.sarif.sarif import generate_sarif_report
from app.schemas.models import VulnerabilityResult

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
STATUS_ICONS = {"CONFIRMED": "[CONFIRMED]", "LIKELY": "[LIKELY]", "NEEDS_REVIEW": "[NEEDS_REVIEW]"}



def _collect_files(target_path: str, config: ProjectConfig) -> list[str]:
    """Recursively collect C/C++ source files, honoring config ignore patterns."""
    if os.path.isfile(target_path):
        if SecurityGuard.is_safe_source_file(target_path):
            return [target_path]
        return []

    collected = []
    for root, dirs, files in os.walk(target_path):
        # Prune hidden or ignored directories
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "vendor", "build", "dist")]
        for f in files:
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, target_path)
            if SecurityGuard.is_safe_source_file(full_path) and not ConfigLoader.is_path_ignored(rel_path, config.ignore_paths):
                collected.append(full_path)
    return sorted(collected)


def _format_text_report(results: list[VulnerabilityResult], target: str, duration_ms: int, files_count: int) -> str:
    """Render human-readable colorized terminal output with security details."""
    out = []
    out.append("=" * 88)
    out.append(" 🛡️  VulnDetect Static Security Analysis Report")
    out.append(f" Target: {target} | Files Scanned: {files_count} | Duration: {duration_ms}ms")
    out.append(f" Total Findings: {len(results)}")
    out.append("=" * 88)

    if not results:
        out.append("\n  ✅ No vulnerabilities detected. Code passed all active security checks.\n")
        out.append("=" * 88)
        return "\n".join(out)

    for i, r in enumerate(results, 1):
        status_label = STATUS_ICONS.get(r.analysis_status, r.analysis_status or "LIKELY")
        out.append(f"\n[{i}] [{r.severity}] {r.vulnerability}  ({status_label})")
        out.append(f"    Location:   {r.file}:{r.line}")
        out.append(f"    CWE:        {r.cwe or 'N/A'} | Rule: {r.rule_id or 'N/A'} | Source: {r.analyzer_source} | Conf: {r.confidence or 0:.2f}")
        out.append(f"    Risk Score: {r.risk_score:.2f}")
        out.append(f"    Message:    {r.explanation}")

        if r.dataflow_path:
            out.append("    Data-Flow Trace:")
            for st in r.dataflow_path:
                out.append(f"      - {st.get('step_type', 'STEP')} (L{st.get('line', '?')}): {st.get('description', '')}")

        if r.analysis_limitations:
            out.append("    Analysis Limitations:")
            for lim in r.analysis_limitations:
                out.append(f"      ⚠️  {lim}")

        if r.recommended_manual_verification:
            out.append("    Manual Verification Checklist:")
            for step in r.recommended_manual_verification:
                out.append(f"      [ ] {step}")

        out.append(f"    Fix:        {r.fix}")

    out.append("\n" + "=" * 88)
    # Breakdown statistics
    sev_counts = {}
    stat_counts = {}
    for r in results:
        sev_counts[r.severity] = sev_counts.get(r.severity, 0) + 1
        st = r.analysis_status or "LIKELY"
        stat_counts[st] = stat_counts.get(st, 0) + 1

    out.append(f" Severity Breakdown: " + ", ".join(f"{k}: {v}" for k, v in sorted(sev_counts.items())))
    out.append(f" Certainty States:   " + ", ".join(f"{k}: {v}" for k, v in sorted(stat_counts.items())))
    out.append("=" * 88)
    return "\n".join(out)


def run_cli():
    parser = argparse.ArgumentParser(
        prog="vulndetect",
        description="VulnDetect: Multi-layer C/C++ Static Security Analysis Platform",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # `scan` command
    scan_parser = subparsers.add_parser("scan", help="Scan a C/C++ file or directory for security vulnerabilities")
    scan_parser.add_argument("path", help="Path to source file or project directory to analyze")
    scan_parser.add_argument("-f", "--format", choices=["text", "json", "sarif"], default="text", help="Output report format (default: text)")
    scan_parser.add_argument("-o", "--output", help="Write report to specified output file instead of stdout")
    scan_parser.add_argument("-s", "--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], help="Filter by minimum severity threshold")
    scan_parser.add_argument("--status", choices=["CONFIRMED", "LIKELY", "NEEDS_REVIEW"], help="Filter by analysis certainty status")
    scan_parser.add_argument("--cwe", help="Filter findings by specific CWE (e.g. CWE-120)")
    scan_parser.add_argument("-c", "--config", help="Path to custom configuration file (.vulndetect.yml)")
    scan_parser.add_argument("--fail-on", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], help="Exit with code 1 if findings meet or exceed this severity")

    args = parser.parse_args()

    if not args.command or args.command != "scan":
        parser.print_help()
        sys.exit(0)

    target_path = os.path.abspath(args.path)
    if not os.path.exists(target_path):
        print(f"Error: Target path '{target_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    # 1. Load project config
    config = ConfigLoader.load_config(args.config, root_dir=target_path if os.path.isdir(target_path) else os.path.dirname(target_path))

    # 2. Collect files
    files = _collect_files(target_path, config)
    if not files:
        print(f"No C/C++ source files found in '{target_path}'.", file=sys.stderr)
        sys.exit(0)

    # 3. Execute analysis
    t0 = time.monotonic()
    all_findings: list[VulnerabilityResult] = []

    for fpath in files:
        try:
            source = SecurityGuard.read_safe_source_code(fpath)
            rel_file = os.path.relpath(fpath, target_path) if os.path.isdir(target_path) else os.path.basename(fpath)
            file_results = analyze_file(rel_file, source)
            for r in file_results:
                r.file = rel_file
            all_findings.extend(file_results)
        except Exception as e:
            print(f"Warning: Failed to scan {fpath}: {e}", file=sys.stderr)

    duration_ms = int((time.monotonic() - t0) * 1000)

    # 4. Filter findings
    min_sev_str = args.severity or config.severity_threshold or "LOW"
    min_sev_val = SEVERITY_ORDER.get(min_sev_str.upper(), 1)

    filtered_findings = [f for f in all_findings if SEVERITY_ORDER.get(f.severity.upper(), 1) >= min_sev_val]

    if args.status:
        filtered_findings = [f for f in filtered_findings if (f.analysis_status or "LIKELY").upper() == args.status.upper()]

    if args.cwe:
        filtered_findings = [f for f in filtered_findings if f.cwe and f.cwe.upper() == args.cwe.upper()]

    # 5. Render output
    output_str = ""
    if args.format == "json":
        output_data = {
            "target": target_path,
            "duration_ms": duration_ms,
            "total_files": len(files),
            "total_findings": len(filtered_findings),
            "findings": [r.model_dump() for r in filtered_findings],
        }
        output_str = json.dumps(output_data, indent=2)

    elif args.format == "sarif":
        sarif_data = generate_sarif_report(filtered_findings, scan_id="cli-scan")
        output_str = json.dumps(sarif_data, indent=2)

    else:
        output_str = _format_text_report(filtered_findings, target_path, duration_ms, len(files))

    # 6. Write or print
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_str)
        print(f"Report written to {args.output}")
    else:
        print(output_str)

    # 7. CI/CD Quality Gate (Fail-on)
    fail_on_threshold = args.fail_on or config.fail_on_severity
    if fail_on_threshold:
        threshold_val = SEVERITY_ORDER.get(fail_on_threshold.upper(), 3)
        violating = [f for f in filtered_findings if SEVERITY_ORDER.get(f.severity.upper(), 1) >= threshold_val]
        if violating:
            print(f"\n❌ Quality Gate Failed: Found {len(violating)} finding(s) meeting or exceeding '{fail_on_threshold}' severity threshold.", file=sys.stderr)
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    run_cli()
