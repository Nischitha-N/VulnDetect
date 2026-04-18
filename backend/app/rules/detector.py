"""
Rule-based vulnerability detection for C/C++ code.
Detects unsafe APIs, buffer overflows, memory misuse patterns.
"""

import re
from dataclasses import dataclass
from typing import List, Tuple

@dataclass
class RuleMatch:
    line_no: int
    line_content: str
    vuln_type: str
    base_risk: float
    explanation: str
    fix: str

# ─── Unsafe API Rules ───────────────────────────────────────────────────────

UNSAFE_API_RULES = [
    {
        "pattern": re.compile(r'\bgets\s*\('),
        "vuln_type": "Unsafe API: gets()",
        "base_risk": 0.95,
        "explanation": (
            "gets() reads input with no bounds checking, allowing attackers to "
            "write beyond the buffer boundary. This was removed from C11."
        ),
        "fix": "Replace gets(buf) with fgets(buf, sizeof(buf), stdin) to limit input length.",
    },
    {
        "pattern": re.compile(r'\bstrcpy\s*\('),
        "vuln_type": "Unsafe API: strcpy()",
        "base_risk": 0.80,
        "explanation": (
            "strcpy() copies without checking destination buffer size. "
            "If source is longer than destination, a buffer overflow occurs."
        ),
        "fix": "Replace strcpy(dst, src) with strncpy(dst, src, sizeof(dst)-1) and ensure null termination.",
    },
    {
        "pattern": re.compile(r'\bsprintf\s*\('),
        "vuln_type": "Unsafe API: sprintf()",
        "base_risk": 0.75,
        "explanation": (
            "sprintf() writes to a buffer without size limits, risking overflow "
            "when format string output exceeds buffer capacity."
        ),
        "fix": "Replace sprintf(buf, fmt, ...) with snprintf(buf, sizeof(buf), fmt, ...).",
    },
    {
        "pattern": re.compile(r'\bstrcat\s*\('),
        "vuln_type": "Unsafe API: strcat()",
        "base_risk": 0.78,
        "explanation": (
            "strcat() appends without checking remaining buffer space, "
            "potentially overflowing the destination buffer."
        ),
        "fix": "Replace strcat(dst, src) with strncat(dst, src, sizeof(dst)-strlen(dst)-1).",
    },
    {
        "pattern": re.compile(r'\bscanf\s*\(\s*"[^"]*%s'),
        "vuln_type": "Unsafe API: scanf() with %s",
        "base_risk": 0.85,
        "explanation": (
            "%s in scanf() reads unbounded input. Attacker-controlled input "
            "can overflow the target buffer."
        ),
        "fix": "Use scanf(\"%255s\", buf) with an explicit width, or use fgets() instead.",
    },
    {
        "pattern": re.compile(r'\bsystem\s*\('),
        "vuln_type": "Command Injection Risk: system()",
        "base_risk": 0.88,
        "explanation": (
            "system() passes a string to the shell. If any part is user-controlled, "
            "it enables arbitrary command injection."
        ),
        "fix": "Use execve() with argument arrays instead of system(), and validate all inputs.",
    },
    {
        "pattern": re.compile(r'\bmalloc\s*\([^)]*\)\s*;(?!\s*(if|NULL))'),
        "vuln_type": "Memory: Unchecked malloc()",
        "base_risk": 0.55,
        "explanation": (
            "malloc() can return NULL on allocation failure. Using the pointer "
            "without checking causes a NULL pointer dereference."
        ),
        "fix": "Always check: if (!ptr) { perror(\"malloc\"); exit(EXIT_FAILURE); }",
    },
    {
        "pattern": re.compile(r'\bfree\s*\([^)]+\)\s*;[\s\S]{0,50}\bfree\s*\('),
        "vuln_type": "Memory: Potential Double Free",
        "base_risk": 0.82,
        "explanation": (
            "Freeing a pointer twice corrupts the heap allocator and can lead "
            "to arbitrary code execution."
        ),
        "fix": "Set pointer to NULL after free: free(ptr); ptr = NULL;",
    },
]

# ─── Buffer Overflow Heuristics ─────────────────────────────────────────────

BUFFER_OVERFLOW_PATTERNS = [
    {
        "pattern": re.compile(r'\bchar\s+\w+\s*\[\s*(\d+)\s*\]'),
        "vuln_type": "Buffer Declaration (Review Required)",
        "base_risk": 0.30,
        "explanation": (
            "Fixed-size char arrays are common overflow targets. "
            "Ensure all writes are bounds-checked."
        ),
        "fix": "Audit all uses of this buffer to ensure writes do not exceed its declared size.",
    },
    {
        "pattern": re.compile(r'memcpy\s*\([^,]+,\s*[^,]+,\s*(\w+)\s*\)'),
        "vuln_type": "Unsafe memcpy() Usage",
        "base_risk": 0.65,
        "explanation": (
            "memcpy() does not validate that the size argument fits within "
            "the destination buffer — if size is user-controlled, overflow is possible."
        ),
        "fix": "Validate that size <= sizeof(destination) before calling memcpy().",
    },
    {
        "pattern": re.compile(r'\bprintf\s*\(\s*\w+\s*\)'),
        "vuln_type": "Format String Vulnerability",
        "base_risk": 0.90,
        "explanation": (
            "Passing a user-controlled string directly as a format argument to printf() "
            "allows format string attacks: reading stack memory or writing arbitrary values."
        ),
        "fix": "Always use printf(\"%s\", user_input) instead of printf(user_input).",
    },
]

ALL_RULES = UNSAFE_API_RULES + BUFFER_OVERFLOW_PATTERNS


def scan_lines(source_lines: List[str]) -> List[RuleMatch]:
    """Apply all rules to each line of source code."""
    matches: List[RuleMatch] = []
    seen: set = set()  # deduplicate same rule on same line

    for line_no, line in enumerate(source_lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
            continue

        for rule in ALL_RULES:
            if rule["pattern"].search(line):
                key = (line_no, rule["vuln_type"])
                if key not in seen:
                    seen.add(key)
                    matches.append(RuleMatch(
                        line_no=line_no,
                        line_content=line.rstrip(),
                        vuln_type=rule["vuln_type"],
                        base_risk=rule["base_risk"],
                        explanation=rule["explanation"],
                        fix=rule["fix"],
                    ))

    return matches
