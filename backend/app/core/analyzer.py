"""
Analyzer: Combines rule-based detection with ML risk scoring.
Produces final VulnerabilityResult objects for each finding.
"""

import os
from typing import List
from app.rules.detector import scan_lines, RuleMatch
from app.ml.model import predict_risk
from app.schemas.models import VulnerabilityResult


def _severity_from_score(score: float) -> str:
    if score >= 0.85:
        return "CRITICAL"
    elif score >= 0.65:
        return "HIGH"
    elif score >= 0.40:
        return "MEDIUM"
    return "LOW"


def _fuse_risk(rule_base: float, ml_score: float) -> float:
    """
    Weighted fusion of rule-based risk and ML risk score.
    Rule-based knowledge takes 60%, ML contextual understanding 40%.
    """
    fused = (0.60 * rule_base) + (0.40 * ml_score)
    # Boost if both agree on high risk
    if rule_base > 0.7 and ml_score > 0.7:
        fused = min(1.0, fused * 1.15)
    return round(float(fused), 3)


def analyze_file(filepath: str, source_code: str) -> List[VulnerabilityResult]:
    """
    Full analysis pipeline for one C/C++ source file.
    Returns a list of vulnerability findings sorted by line number.
    """
    lines = source_code.splitlines()
    rule_matches: List[RuleMatch] = scan_lines(lines)

    results: List[VulnerabilityResult] = []

    for match in rule_matches:
        line_idx = match.line_no - 1  # 0-indexed for context lookup
        ml_score = predict_risk(match.line_content, lines, line_idx)
        final_risk = _fuse_risk(match.base_risk, ml_score)

        # Extract code snippet (±2 lines for context display)
        start = max(0, line_idx - 2)
        end = min(len(lines), line_idx + 3)
        snippet_lines = lines[start:end]
        snippet = "\n".join(
            f"{start + i + 1}: {l}" for i, l in enumerate(snippet_lines)
        )

        results.append(VulnerabilityResult(
            file=os.path.basename(filepath),
            line=match.line_no,
            vulnerability=match.vuln_type,
            risk_score=final_risk,
            explanation=match.explanation,
            fix=match.fix,
            code_snippet=snippet,
            severity=_severity_from_score(final_risk),
        ))

    results.sort(key=lambda r: (-r.risk_score, r.line))
    return results
