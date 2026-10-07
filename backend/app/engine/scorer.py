"""
Layer 7: Risk Prioritization & Finding Scoring Engine.
Decouples deterministic detection from risk prioritization and severity calibration.
"""

from typing import List
from app.engine.base import Finding, Severity, AnalyzerSource, AnalysisStatus


class FindingScorer:
    """Computes calibrated risk scores and severity classifications."""

    @staticmethod
    def score_findings(findings: List[Finding]) -> List[Finding]:
        for f in findings:
            base_score = f.risk_score

            # Multi-factor adjustments
            if f.analyzer_source == AnalyzerSource.MULTI_ANALYZER:
                base_score = min(1.0, base_score * 1.08)

            if f.dataflow_path:
                # Confirmed taint propagation with source and sink
                base_score = min(1.0, base_score + 0.05)

            # Factor certainty status
            if f.analysis_status == AnalysisStatus.CONFIRMED:
                base_score = min(1.0, base_score * 1.05)
            elif f.analysis_status == AnalysisStatus.NEEDS_REVIEW:
                # Ambiguous findings are prioritized after confirmed vulnerabilities
                base_score = max(0.20, base_score * 0.85)

            # Factor LLM assessment if available
            if f.llm_assessment and f.llm_assessment.reviewed:
                base_score = min(1.0, max(0.05, base_score + f.llm_assessment.confidence_adjustment))

            # Cap and calibrate
            final_risk = round(float(min(1.0, max(0.05, base_score))), 2)
            f.risk_score = final_risk

            # Calibrate severity according to standard risk thresholds
            if final_risk >= 0.85:
                f.severity = Severity.CRITICAL
            elif final_risk >= 0.65:
                f.severity = Severity.HIGH
            elif final_risk >= 0.40:
                f.severity = Severity.MEDIUM
            else:
                f.severity = Severity.LOW

        # Sort findings by status urgency (CONFIRMED first, then LIKELY, then NEEDS_REVIEW) and risk score
        status_rank = {AnalysisStatus.CONFIRMED: 0, AnalysisStatus.LIKELY: 1, AnalysisStatus.NEEDS_REVIEW: 2}
        findings.sort(key=lambda x: (status_rank.get(x.analysis_status, 1), -x.risk_score, x.line))
        return findings

