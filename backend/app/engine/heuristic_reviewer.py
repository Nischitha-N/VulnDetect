"""
Heuristic Ambiguity Reviewer for Ambiguous Security Findings.
The deterministic engine remains authoritative for AST facts, CFG facts, dataflow,
taint paths, variable ranges, ownership states, source locations, and function calls.

The heuristic reviewer answers 10 structured triage questions
without ever altering deterministic facts.
"""




from typing import List, Dict, Any, Optional
from app.engine.base import Finding, AnalysisStatus, LLMAssessment, AnalysisContext


class HeuristicAmbiguityReviewer:
    """
    Structured Heuristic Security Reviewer.
    Answers 10 structured triage questions for ambiguous findings (NEEDS_REVIEW / LIKELY):
      1. What does the deterministic analyzer prove?
      2. What does it merely suggest?
      3. Which assumptions are being made?
      4. Which missing code/context could change the conclusion?
      5. Is there evidence that a sanitizer exists?
      6. Is the alleged sink actually security-sensitive in this context?
      7. Could the finding be a false positive?
      8. What additional code should a human inspect?
      9. What remediation would preserve program behavior?
      10. What test should be added to verify the fix?
    """

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def review_findings(self, findings: List[Finding], context: AnalysisContext) -> List[Finding]:
        """Review ambiguous findings without mutating deterministic facts."""
        if not self.enabled:
            return findings

        for finding in findings:
            # ONLY review ambiguous findings (NEEDS_REVIEW or LIKELY)
            if finding.analysis_status in (AnalysisStatus.NEEDS_REVIEW, AnalysisStatus.LIKELY):
                self._review_single_finding(finding, context)

        return findings

    def _review_single_finding(self, finding: Finding, context: AnalysisContext):
        """Construct prompt and generate structured assessment."""
        snippet = finding.code_snippet or ""
        evidence_descriptions = [e.description for e in finding.evidence]
        dataflow_descriptions = [f"{s.step_type} (L{s.line}): {s.description}" for s in finding.dataflow_path]

        # 1. Guard against Insufficient Context (prevent hallucinations)
        if not snippet or len(snippet.strip().splitlines()) <= 1 and not finding.evidence:
            finding.llm_assessment = LLMAssessment(
                reviewed=True,
                verdict="INSUFFICIENT_CONTEXT",
                confidence_adjustment=0.0,
                what_is_proven="Deterministic engine located rule trigger pattern.",
                what_is_suggested="Potential security weakness suggested by token/rule heuristics.",
                assumptions=["Assumes complete function body was provided."],
                missing_context=["Full function definition and surrounding statements are missing."],
                sanitizer_evidence=None,
                sink_sensitive_in_context=True,
                potential_false_positive=False,
                potential_false_positive_reason="",
                human_inspection_targets=[f"{finding.file}:{finding.line}"],
                remediation_advice=finding.remediation or "Provide complete source file for contextual static analysis.",
                recommended_test="Unit test exercising boundary inputs.",
                missing_information=["Full function AST and caller call sites are absent."],
                human_inspection_advice=[f"Inspect definition at {finding.file}:{finding.line}."],
                raw_explanation="INSUFFICIENT_CONTEXT: Code snippet lacks sufficient AST/flow context for contextual verification."
            )
            return

        # 2. Local Structured Reasoning (Always reliable, deterministic-safe)
        finding.llm_assessment = self._generate_structured_assessment(
            finding, snippet, evidence_descriptions, dataflow_descriptions, context
        )

    def _generate_structured_assessment(
        self,
        finding: Finding,
        snippet: str,
        evidence: List[str],
        dataflow: List[str],
        context: AnalysisContext
    ) -> LLMAssessment:
        """
        Synthesizes a structured security assessment answering all 10 reviewer questions.
        """
        # 1. What does the deterministic analyzer prove?
        proven_facts = []
        if evidence:
            proven_facts.extend(evidence)
        if dataflow:
            proven_facts.append(f"Deterministic dataflow trace: {' -> '.join(dataflow)}")
        if not proven_facts:
            proven_facts.append(f"Deterministic pattern match for {finding.vulnerability_type} at {finding.file}:{finding.line}.")
        what_is_proven = " | ".join(proven_facts)

        # 2. What does it merely suggest?
        what_is_suggested = (
            f"Suggests that under certain execution paths, input flows into {finding.vulnerability_type} "
            f"without complete runtime bounds or neutralization."
        )

        # 3. Which assumptions are being made?
        assumptions = list(finding.assumptions) if finding.assumptions else [
            "Assumes caller functions provide attacker-influenced arguments.",
            "Assumes external compiler/platform mitigations do not intercept the payload.",
        ]

        # 4. Which missing code/context could change the conclusion?
        missing_context = list(finding.unknowns) if finding.unknowns else [
            "Caller call-site parameter constraints.",
            "Pre-filter or gateway validation routines outside this compilation unit.",
        ]

        # 5. Is there evidence that a sanitizer exists?
        sanitizer_evidence = None
        for u in finding.unknowns:
            if "sanitizer" in u.lower() or "filter" in u.lower():
                sanitizer_evidence = f"Unverified custom sanitizer detected: {u}"
                break
        if not sanitizer_evidence and any(k in snippet for k in ("sanitize", "validate", "escape", "clean", "filter")):
            sanitizer_evidence = "Potential custom validation helper invoked in snippet."

        # 6. Is the alleged sink actually security-sensitive in this context?
        is_sink_sensitive = True
        if "printf(" in snippet and "\"%s\"" in snippet:
            is_sink_sensitive = False
        elif "system(" in snippet and ("\"" in snippet and not any(v in snippet for v in ("+", "%s", "cmd", "input"))):
            is_sink_sensitive = False

        # 7. Could the finding be a false positive?
        potential_false_positive = False
        fp_reason = ""
        if not is_sink_sensitive:
            potential_false_positive = True
            fp_reason = "Sink argument appears to be a compile-time constant string literal."
        elif sanitizer_evidence:
            potential_false_positive = True
            fp_reason = "Sanitizer routine is present before sink invocation."
        elif "if (" in snippet and any(b in snippet for b in ("<", ">", "==", "!=", "NULL", "nullptr")):
            potential_false_positive = True
            fp_reason = "Conditional guard in snippet may enforce necessary safety bounds."

        # 8. What additional code should a human inspect?
        inspection_targets = list(finding.recommended_manual_verification) if finding.recommended_manual_verification else [
            f"Inspect all call sites passing data to line {finding.line}.",
            "Verify input validation against strict allowlist before reaching this function.",
        ]

        # 9. What remediation would preserve program behavior?
        remediation_advice = finding.remediation or "Use bounded APIs (e.g. snprintf, strncpy) and validate inputs."

        # 10. What test should be added to verify the fix?
        recommended_test = (
            f"Add regression test passing edge-case/oversized input to {finding.vulnerability_type} "
            f"trigger at line {finding.line} to confirm safe error handling."
        )

        # Verdict & bounded confidence adjustment [-0.20, +0.10]
        if potential_false_positive and not finding.evidence:
            verdict = "likely_benign"
            raw_adj = -0.15
        elif finding.analysis_status == AnalysisStatus.NEEDS_REVIEW:
            verdict = "inconclusive"
            raw_adj = -0.05
        else:
            verdict = "likely_vulnerable"
            raw_adj = 0.05

        confidence_adj = max(-0.20, min(0.10, raw_adj))

        supporting = list(proven_facts)
        contradicting = []
        if sanitizer_evidence:
            contradicting.append(sanitizer_evidence)
        if fp_reason:
            contradicting.append(fp_reason)

        raw_expl = (
            f"Heuristic Reviewer Assessment: Deterministic analysis identified {finding.vulnerability_type} ({finding.cwe}). "
            f"Verdict: {verdict.upper()}. "
            f"Proven: {what_is_proven[:100]}... "
            f"Missing context: {', '.join(missing_context)}."
        )

        return LLMAssessment(
            reviewed=True,
            verdict=verdict,
            confidence_adjustment=confidence_adj,
            what_is_proven=what_is_proven,
            what_is_suggested=what_is_suggested,
            assumptions=assumptions,
            missing_context=missing_context,
            sanitizer_evidence=sanitizer_evidence,
            sink_sensitive_in_context=is_sink_sensitive,
            potential_false_positive=potential_false_positive,
            potential_false_positive_reason=fp_reason,
            human_inspection_targets=inspection_targets,
            remediation_advice=remediation_advice,
            recommended_test=recommended_test,
            supporting_evidence=supporting,
            contradicting_evidence=contradicting,
            missing_information=missing_context,
            human_inspection_advice=inspection_targets,
            raw_explanation=raw_expl,
        )
