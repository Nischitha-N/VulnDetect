"""
Finding-Level Feature Extractor for VulnDetect Auxiliary ML Triage.

Extracts a deterministic 12-dimensional numerical feature vector from a static
analysis Finding object or dataset sample dictionary.

Audited Features:
 1. analyzer_confidence        - Float [0.0, 1.0] from detector calibration.
 2. is_multi_layer            - Binary (1.0 if MULTI_ANALYZER or multiple evidence items).
 3. has_dataflow_path         - Binary (1.0 if explicit dataflow/taint path exists).
 4. dataflow_step_count       - Float count of dataflow propagation steps.
 5. has_sanitizer_in_path     - Binary (1.0 if sanitizer step or evidence recorded).
 6. is_interprocedural        - Binary (1.0 if IPA analyzer or IPA rule).
 7. analysis_status_code      - Ordinal float (CONFIRMED=1.0, LIKELY=0.5, NEEDS_REVIEW=0.0).
 8. cwe_family_id             - Categorical float (CWE-78=1.0, CWE-416=2.0, CWE-193=3.0, CWE-134=4.0).
 9. has_guard_in_snippet      - Binary (1.0 if snippet has control guard keyword).
10. is_constant_literal_sink  - Binary (1.0 if snippet has string literal quotes or const qualifier).
11. line_length_norm          - Float normalized snippet length min(1.0, len/120.0).
12. pointer_deref_present     - Binary (1.0 if snippet contains *, ->, or [] operators).
"""

import re
from typing import List, Dict, Any, Union
import numpy as np

from app.engine.base import Finding, AnalyzerSource, AnalysisStatus


FEATURE_NAMES = [
    "analyzer_confidence",
    "is_multi_layer",
    "has_dataflow_path",
    "dataflow_step_count",
    "has_sanitizer_in_path",
    "is_interprocedural",
    "analysis_status_code",
    "cwe_family_id",
    "has_guard_in_snippet",
    "is_constant_literal_sink",
    "line_length_norm",
    "pointer_deref_present",
]

N_FEATURES = len(FEATURE_NAMES)  # Exactly 12

# Regex patterns for snippet inspection
GUARD_PATTERN = re.compile(r"\b(?:if|break|continue|return|assert|sizeof)\b")
STRING_LITERAL_PATTERN = re.compile(r'"[^"]*"')
POINTER_DEREF_PATTERN = re.compile(r'(\*\w+|\w+->|\w+\[)')


def extract_finding_features(item: Union[Finding, Dict[str, Any]]) -> np.ndarray:
    """
    Extracts the audited 12-feature vector from either a Finding dataclass instance
    or a dataset sample dictionary. Returns a 1D numpy array of float32.
    """
    if isinstance(item, Finding):
        # 1. analyzer_confidence
        analyzer_confidence = float(item.confidence if item.confidence is not None else 0.5)

        # 2. is_multi_layer
        is_multi = (
            item.analyzer_source == AnalyzerSource.MULTI_ANALYZER
            or (item.evidence and len(item.evidence) > 1)
        )
        is_multi_layer = 1.0 if is_multi else 0.0

        # 3. has_dataflow_path
        has_df = bool(item.dataflow_path and len(item.dataflow_path) > 0)
        has_dataflow_path = 1.0 if has_df else 0.0

        # 4. dataflow_step_count
        dataflow_step_count = float(len(item.dataflow_path)) if item.dataflow_path else 0.0

        # 5. has_sanitizer_in_path
        has_sanitizer = False
        if item.dataflow_path:
            has_sanitizer = any(
                getattr(step, "step_type", "") == "SANITIZER" for step in item.dataflow_path
            )
        if not has_sanitizer and item.evidence:
            has_sanitizer = any("sanitizer" in getattr(ev, "metadata", {}) for ev in item.evidence)
        has_sanitizer_in_path = 1.0 if has_sanitizer else 0.0

        # 6. is_interprocedural
        is_ipa = (
            item.analyzer_source == AnalyzerSource.IPA
            or (item.rule_id and item.rule_id.startswith("IPA-"))
            or (item.evidence and any(getattr(ev, "analyzer_source", None) == AnalyzerSource.IPA for ev in item.evidence))
        )
        is_interprocedural = 1.0 if is_ipa else 0.0

        # 7. analysis_status_code
        status_map = {
            AnalysisStatus.CONFIRMED: 1.0,
            AnalysisStatus.LIKELY: 0.5,
            AnalysisStatus.NEEDS_REVIEW: 0.0,
        }
        analysis_status_code = status_map.get(item.analysis_status, 0.5)

        # 8. cwe_family_id
        cwe_str = str(item.cwe or "").upper()
        if "CWE-78" in cwe_str and "CWE-787" not in cwe_str:
            cwe_family_id = 1.0
        elif "CWE-416" in cwe_str:
            cwe_family_id = 2.0
        elif "CWE-193" in cwe_str:
            cwe_family_id = 3.0
        elif "CWE-134" in cwe_str:
            cwe_family_id = 4.0
        else:
            cwe_family_id = 0.0

        # Snippet features
        snippet = item.code_snippet or ""

    elif isinstance(item, dict):
        # Dictionary sample representation (e.g. from samples.json)
        ev_meta = item.get("evidence_metadata", {})

        # 1. analyzer_confidence
        analyzer_confidence = float(ev_meta.get("confidence", 0.5))

        # 2. is_multi_layer
        is_multi_layer = 1.0 if ev_meta.get("is_multi_layer", False) else 0.0

        # 3. has_dataflow_path
        df_steps = ev_meta.get("dataflow_steps", 0)
        has_dataflow_path = 1.0 if df_steps > 0 else 0.0

        # 4. dataflow_step_count
        dataflow_step_count = float(df_steps)

        # 5. has_sanitizer_in_path
        has_sanitizer = "sanitizer" in item.get("function_name", "").lower() or "filter" in item.get("function_name", "").lower()
        has_sanitizer_in_path = 1.0 if has_sanitizer else 0.0

        # 6. is_interprocedural
        is_ipa = item.get("analyzer_source") == "ipa" or str(item.get("expected_rule", "")).startswith("IPA-")
        is_interprocedural = 1.0 if is_ipa else 0.0

        # 7. analysis_status_code
        status_str = str(ev_meta.get("analysis_status", "LIKELY")).upper()
        if "CONFIRMED" in status_str:
            analysis_status_code = 1.0
        elif "NEEDS_REVIEW" in status_str:
            analysis_status_code = 0.0
        else:
            analysis_status_code = 0.5

        # 8. cwe_family_id
        cwe_str = str(item.get("cwe", "")).upper()
        if "CWE-78" in cwe_str and "CWE-787" not in cwe_str:
            cwe_family_id = 1.0
        elif "CWE-416" in cwe_str:
            cwe_family_id = 2.0
        elif "CWE-193" in cwe_str:
            cwe_family_id = 3.0
        elif "CWE-134" in cwe_str:
            cwe_family_id = 4.0
        else:
            cwe_family_id = 0.0

        snippet = item.get("code_snippet") or item.get("code") or ""

    else:
        raise TypeError(f"Expected Finding or dict, got {type(item)}")

    # 9. has_guard_in_snippet
    has_guard = bool(GUARD_PATTERN.search(snippet))
    has_guard_in_snippet = 1.0 if has_guard else 0.0

    # 10. is_constant_literal_sink
    is_const = bool(STRING_LITERAL_PATTERN.search(snippet) or "const " in snippet)
    is_constant_literal_sink = 1.0 if is_const else 0.0

    # 11. line_length_norm
    line_length_norm = min(1.0, float(len(snippet.strip())) / 120.0)

    # 12. pointer_deref_present
    pointer_deref = bool(POINTER_DEREF_PATTERN.search(snippet))
    pointer_deref_present = 1.0 if pointer_deref else 0.0

    return np.array([
        analyzer_confidence,
        is_multi_layer,
        has_dataflow_path,
        dataflow_step_count,
        has_sanitizer_in_path,
        is_interprocedural,
        analysis_status_code,
        cwe_family_id,
        has_guard_in_snippet,
        is_constant_literal_sink,
        line_length_norm,
        pointer_deref_present,
    ], dtype=np.float32)


def extract_batch_features(items: List[Union[Finding, Dict[str, Any]]]) -> np.ndarray:
    """Extracts a 2D matrix of shape (N, 12) from a list of Findings or samples."""
    return np.vstack([extract_finding_features(item) for item in items])
