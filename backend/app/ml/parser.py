"""
Feature extraction from C/C++ source code for ML model input.
Extracts numeric features from each line and its surrounding context.
"""

import re
from typing import List, Dict
import numpy as np

# ─── Feature definitions ────────────────────────────────────────────────────

UNSAFE_FUNCS = [
    "gets", "strcpy", "strcat", "sprintf", "scanf", "vsprintf",
    "system", "popen", "memcpy", "memmove", "strncpy",
]

SAFE_ALTERNATIVES = [
    "fgets", "strncpy", "strncat", "snprintf", "fgetc",
    "execve", "memcpy_s", "strlcpy", "strlcat",
]

MEMORY_OPS = ["malloc", "calloc", "realloc", "free", "new", "delete"]

POINTER_PATTERNS = [re.compile(r'\*\w+'), re.compile(r'\w+\[')]

FORMAT_STRINGS = re.compile(r'%[sdifxXo]')
NUMERIC_LITERAL = re.compile(r'\b\d+\b')


def extract_line_features(line: str, context_lines: List[str], line_idx: int) -> Dict[str, float]:
    """Extract ML features for a single line with surrounding context."""
    lower = line.lower()

    # Window of ±3 lines for context
    start = max(0, line_idx - 3)
    end = min(len(context_lines), line_idx + 4)
    context = "\n".join(context_lines[start:end]).lower()

    features = {}

    # Unsafe API presence (binary flags)
    for fn in UNSAFE_FUNCS:
        features[f"has_{fn}"] = float(bool(re.search(rf'\b{fn}\s*\(', lower)))

    # Safe alternatives nearby (reduces risk)
    for fn in SAFE_ALTERNATIVES:
        features[f"safe_{fn}_nearby"] = float(bool(re.search(rf'\b{fn}\s*\(', context)))

    # Memory operations
    for op in MEMORY_OPS:
        features[f"mem_{op}"] = float(bool(re.search(rf'\b{op}\s*[\(\[]', lower)))

    # Pointer operations
    features["ptr_deref"] = float(any(p.search(line) for p in POINTER_PATTERNS))

    # Format string usage
    features["has_format_string"] = float(bool(FORMAT_STRINGS.search(line)))

    # Numeric literals (array indices, sizes)
    numerics = [int(n) for n in NUMERIC_LITERAL.findall(line) if n.isdigit()]
    features["max_numeric_literal"] = float(max(numerics)) if numerics else 0.0
    features["has_large_index"] = float(any(n > 256 for n in numerics))

    # NULL / error check nearby (reduces risk)
    features["has_null_check"] = float("null" in context or "!=" in context)
    features["has_bounds_check"] = float(
        bool(re.search(r'sizeof|strlen|size\s*[<>]|len\s*[<>]', context))
    )

    # Line complexity
    features["line_length"] = float(len(line))
    features["paren_depth"] = float(line.count("(") - line.count(")"))
    features["bracket_depth"] = float(line.count("[") - line.count("]"))
    features["has_cast"] = float(bool(re.search(r'\(\s*(char|int|void)\s*\*\s*\)', line)))
    features["comment_ratio"] = float("//" in line or "/*" in line)

    return features


def features_to_vector(features: Dict[str, float]) -> np.ndarray:
    """Convert feature dict to consistent numpy array."""
    return np.array(list(features.values()), dtype=np.float32)


FEATURE_NAMES = list(extract_line_features("", [], 0).keys())
N_FEATURES = len(FEATURE_NAMES)
