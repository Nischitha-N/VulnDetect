"""
Analyzer: Bridges FastAPI core pipeline with the modular multi-layer analysis orchestrator.
Produces final VulnerabilityResult objects.
"""

from typing import List, Tuple
from app.engine.orchestrator import orchestrator
from app.engine.base import Finding
from app.schemas.models import VulnerabilityResult


def _findings_to_results(findings: List[Finding]) -> List[VulnerabilityResult]:
    """Converts internal Finding dataclasses to API VulnerabilityResult schemas."""
    results: List[VulnerabilityResult] = []

    for f in findings:
        ev_dicts = [
            {
                "analyzer_source": ev.analyzer_source.value,
                "description": ev.description,
                "confidence": ev.confidence,
                "metadata": ev.metadata,
            }
            for ev in f.evidence
        ]
        df_dicts = [
            {
                "step_type": step.step_type,
                "line": step.line,
                "column": step.column,
                "code": step.code,
                "description": step.description,
            }
            for step in f.dataflow_path
        ]

        llm_dict = None
        if f.llm_assessment and f.llm_assessment.reviewed:
            llm_dict = {
                "reviewed": f.llm_assessment.reviewed,
                "verdict": f.llm_assessment.verdict,
                "confidence_adjustment": f.llm_assessment.confidence_adjustment,
                "supporting_evidence": f.llm_assessment.supporting_evidence,
                "contradicting_evidence": f.llm_assessment.contradicting_evidence,
                "missing_information": f.llm_assessment.missing_information,
                "human_inspection_advice": f.llm_assessment.human_inspection_advice,
                "raw_explanation": f.llm_assessment.raw_explanation,
            }

        results.append(
            VulnerabilityResult(
                file=f.file,
                line=f.line,
                vulnerability=f.vulnerability_type,
                risk_score=f.risk_score,
                explanation=f.message,
                fix=f.remediation,
                code_snippet=f.code_snippet,
                severity=f.severity.value,
                rule_id=f.rule_id,
                cwe=f.cwe,
                column=f.column,
                analyzer_source=f.analyzer_source.value,
                analysis_status=f.analysis_status.value if hasattr(f, "analysis_status") else "LIKELY",
                confidence=f.confidence,
                dataflow_path=df_dicts if df_dicts else None,
                evidence=ev_dicts if ev_dicts else None,
                assumptions=f.assumptions if f.assumptions else None,
                unknowns=f.unknowns if f.unknowns else None,
                analysis_limitations=f.analysis_limitations if f.analysis_limitations else None,
                recommended_manual_verification=f.recommended_manual_verification if f.recommended_manual_verification else None,
                deterministic_result=f.deterministic_result if f.deterministic_result else None,
                llm_assessment=llm_dict,
                metadata=f.metadata if f.metadata else None,
            )
        )

    return results


def analyze_file(filepath: str, source_code: str) -> List[VulnerabilityResult]:
    """
    Full multi-layer analysis pipeline for one C/C++ source file.
    Executes Tree-sitter AST, Taint, Dataflow, and Rule analyzers with deduplication.
    """
    findings: List[Finding] = orchestrator.analyze_file(filepath, source_code)
    results = _findings_to_results(findings)
    results.sort(key=lambda r: (-r.risk_score, r.line))
    return results


def analyze_project(files: List[Tuple[str, str]]) -> List[VulnerabilityResult]:
    """
    Full multi-file analysis pipeline across multiple translation units.
    Propagates inter-procedural function summaries across files to discover cross-file vulnerabilities.
    """
    findings: List[Finding] = orchestrator.analyze_project(files)
    results = _findings_to_results(findings)
    results.sort(key=lambda r: (-r.risk_score, r.file, r.line))
    return results


