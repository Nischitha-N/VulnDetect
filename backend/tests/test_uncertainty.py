"""
Unit tests for VulnDetect Explicit Uncertainty Layer & Ambiguity Reasoning.
Demonstrates that the system does NOT incorrectly classify uncertain cases as CONFIRMED.
"""

import pytest
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.engine.base import AnalysisStatus, AnalyzerSource
from app.engine.orchestrator import orchestrator
from app.engine.uncertainty_analyzer import UncertaintyAnalyzer
from app.engine.parser import parse_source


class TestUncertaintyLayer:

    def test_confirmed_local_vulnerability(self):
        """Conclusive local defect in same scope should be classified as CONFIRMED."""
        code = """
        #include <stdlib.h>
        void test_uaf() {
            char *p = malloc(64);
            if (!p) return;
            free(p);
            *p = 'A';
        }
        """
        findings = orchestrator.analyze_file("uaf.c", code)
        uaf_findings = [f for f in findings if f.cwe == "CWE-416"]
        assert len(uaf_findings) >= 1
        finding = uaf_findings[0]
        assert finding.analysis_status == AnalysisStatus.CONFIRMED
        assert len(finding.assumptions) > 0
        assert "deterministic_result" in dir(finding)

    def test_uncertain_due_to_external_sanitizer(self):
        """
        When an external sanitizer function is present, the analyzer must NOT mark
        the finding as CONFIRMED. It must surface NEEDS_REVIEW with explicit limitations.
        """
        code = """
        #include <stdio.h>
        // Prototype only - implementation is external
        void sanitize_input(char *str);

        void run_user_cmd(char *user_input) {
            sanitize_input(user_input);
            system(user_input);
        }
        """
        findings = orchestrator.analyze_file("cmd.c", code)
        cmd_findings = [f for f in findings if f.cwe == "CWE-78"]
        assert len(cmd_findings) >= 1
        finding = cmd_findings[0]

        # Must NOT be CONFIRMED
        assert finding.analysis_status != AnalysisStatus.CONFIRMED
        assert finding.analysis_status == AnalysisStatus.NEEDS_REVIEW

        # Must surface explicit unknowns and limitations
        assert any("sanitize_input" in u for u in finding.unknowns)
        assert any("sanitize_input" in lim for lim in finding.analysis_limitations)
        assert any("sanitize_input" in st for st in finding.recommended_manual_verification)

    def test_uncertain_due_to_function_pointer(self):
        """
        Indirect calls through function pointers obscure call targets,
        preventing static certainty.
        """
        code = """
        #include <stdio.h>
        #include <stdlib.h>

        typedef void (*dispatch_fn)(char *);

        void execute_handler(dispatch_fn handler, char *data) {
            (*handler)(data);
            printf(data);
        }
        """
        findings = orchestrator.analyze_file("dispatch.c", code)
        fmt_findings = [f for f in findings if f.cwe == "CWE-134"]
        assert len(fmt_findings) >= 1
        finding = fmt_findings[0]

        # Should be classified as NEEDS_REVIEW due to indirect call
        assert finding.analysis_status == AnalysisStatus.NEEDS_REVIEW
        assert any("function pointer" in lim.lower() for lim in finding.analysis_limitations)

    def test_uncertain_due_to_inline_assembly(self):
        """
        Inline assembly introduces unanalyzable CPU register and memory side-effects.
        """
        code = """
        #include <stdlib.h>
        void test_asm(int n) {
            int *p = malloc(n * sizeof(int));
            __asm__ volatile ("nop");
            p[0] = 42;
        }
        """
        findings = orchestrator.analyze_file("asm.c", code)
        assert len(findings) >= 1
        # Any finding in this function must be marked NEEDS_REVIEW
        for f in findings:
            assert f.analysis_status == AnalysisStatus.NEEDS_REVIEW
            assert any("inline assembly" in u.lower() for u in f.unknowns)

    def test_heuristic_reviewer_preserves_deterministic_facts(self):
        """
        Heuristic review must attach structured assessments while preserving
        deterministic findings unchanged.
        """
        code = """
        #include <stdio.h>
        void custom_clean(char *s);

        void display(char *msg) {
            custom_clean(msg);
            printf(msg);
        }
        """
        findings = orchestrator.analyze_file("display.c", code)
        assert len(findings) >= 1
        finding = findings[0]

        # Deterministic result preserved
        assert finding.deterministic_result is not None
        assert finding.deterministic_result["cwe"] == "CWE-134"

        # LLM assessment populated
        assert finding.llm_assessment is not None
        assert finding.llm_assessment.reviewed is True
        assert finding.llm_assessment.verdict in ("likely_vulnerable", "likely_benign", "inconclusive")
        assert len(finding.llm_assessment.supporting_evidence) > 0
        assert len(finding.llm_assessment.human_inspection_advice) > 0
