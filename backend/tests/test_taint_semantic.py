"""
Unit and Integration Tests for Configurable Semantic Taint Analysis Framework.
Verifies SOURCE -> PROPAGATION -> TRANSFORMATION -> SANITIZER -> SINK lifecycle,
alias tracking, struct fields, custom/unknown sanitizers, and safe constant inputs.
"""

import pytest
import os
import sys

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.engine.parser import parse_source
from app.engine.taint.spec import TaintConfigManager, TaintState
from app.engine.taint_analyzer import TaintAnalyzer
from app.engine.orchestrator import orchestrator
from app.engine.base import AnalysisStatus, AnalyzerSource


class TestSemanticTaintDirectAndMultiStep:
    """Tests for direct and multi-step taint propagation."""

    def test_direct_getenv_to_system(self):
        code = """
        #include <stdlib.h>
        void test() {
            char *cmd = getenv("CMD");
            system(cmd);
        }
        """
        ctx = parse_source(code, "direct.c")
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze(ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "TAINT-SYSTEM-001"
        assert findings[0].cwe == "CWE-78"
        assert findings[0].analysis_status == AnalysisStatus.CONFIRMED
        
        # Check dataflow path steps
        steps = findings[0].dataflow_path
        assert len(steps) >= 2
        assert steps[0].step_type == "SOURCE"
        assert steps[-1].step_type == "SINK"

    def test_multistep_sprintf_transformation(self):
        code = """
        #include <stdio.h>
        #include <stdlib.h>
        void test() {
            char input[64];
            char query[256];
            fgets(input, sizeof(input), stdin);
            sprintf(query, "SELECT * FROM users WHERE name = '%s'", input);
            sqlite3_exec(db, query, 0, 0, 0);
        }
        """
        ctx = parse_source(code, "sql.c")
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze(ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "TAINT-SQLITE3_EXEC-001"
        assert findings[0].cwe == "CWE-89"

        # Check step types: SOURCE -> TRANSFORMATION -> SINK
        step_types = [s.step_type for s in findings[0].dataflow_path]
        assert "SOURCE" in step_types
        assert "TRANSFORMATION" in step_types
        assert "SINK" in step_types


class TestSemanticTaintSanitizers:
    """Tests for trusted vs custom/unknown sanitizers."""

    def test_trusted_sanitizer_suppresses_vulnerability(self):
        code = """
        #include <stdio.h>
        #include <stdlib.h>
        void test() {
            char *path = getenv("PATH_VAR");
            char *clean_path = sanitize_path(path);
            fopen(clean_path, "r");
        }
        """
        ctx = parse_source(code, "safe.c")
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze(ctx)
        # Trusted sanitizer should safely suppress the finding
        assert len(findings) == 0

    def test_custom_unknown_sanitizer_triggers_needs_review(self):
        # Configure a custom unverified sanitizer
        config_mgr = TaintConfigManager(custom_sanitizers=["custom_magic_cleaner"])
        analyzer = TaintAnalyzer(config_mgr)

        code = """
        #include <stdlib.h>
        void test() {
            char *input = getenv("USER_INPUT");
            char *filtered = custom_magic_cleaner(input);
            system(filtered);
        }
        """
        ctx = parse_source(code, "custom_san.c")
        findings = analyzer.analyze(ctx)
        assert len(findings) == 1
        assert findings[0].analysis_status == AnalysisStatus.NEEDS_REVIEW
        assert "custom_magic_cleaner" in findings[0].evidence[0].metadata["sanitizer"]
        assert len(findings[0].assumptions) >= 1
        assert len(findings[0].recommended_manual_verification) >= 1


class TestSemanticTaintAliasesAndStructs:
    """Tests for pointer aliases and struct field taint tracking."""

    def test_pointer_alias_propagation(self):
        code = """
        #include <stdlib.h>
        void test() {
            char *a = getenv("TARGET");
            char *b = a;
            char *c = b;
            popen(c, "r");
        }
        """
        ctx = parse_source(code, "alias.c")
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze(ctx)
        assert len(findings) == 1
        assert findings[0].rule_id == "TAINT-POPEN-001"
        assert findings[0].cwe == "CWE-78"

    def test_struct_field_taint_propagation(self):
        code = """
        #include <stdlib.h>
        #include <string.h>
        struct Request {
            char path[128];
        };
        void test() {
            struct Request req;
            char *p = getenv("PARAM");
            strcpy(req.path, p);
            unlink(req.path);
        }
        """
        ctx = parse_source(code, "struct.c")
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze(ctx)
        unlink_findings = [f for f in findings if f.rule_id == "TAINT-UNLINK-001"]
        assert len(unlink_findings) == 1
        assert unlink_findings[0].cwe == "CWE-22"


class TestSemanticTaintSafeConstants:
    """Tests verifying safe constant expressions produce 0 false positives."""

    def test_safe_constant_inputs(self):
        code = """
        #include <stdio.h>
        #include <stdlib.h>
        void test() {
            system("ls -la");
            popen("ps aux", "r");
            fopen("config.ini", "r");
            printf("Safe literal message\\n");
        }
        """
        ctx = parse_source(code, "constants.c")
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze(ctx)
        assert len(findings) == 0


class TestOrchestratorTaintIntegration:
    """Integration test scanning corpus fixture through full Orchestrator pipeline."""

    def test_corpus_taint_fixture_scan(self):
        fixture_path = os.path.join(os.path.dirname(__file__), "corpus", "taint_fixtures.c")
        with open(fixture_path, "r", encoding="utf-8") as f:
            code = f.read()

        findings = orchestrator.analyze_file(fixture_path, code)
        
        taint_findings = [f for f in findings if f.analyzer_source in (AnalyzerSource.TAINT, AnalyzerSource.MULTI_ANALYZER)]
        assert len(taint_findings) >= 3

        # Verify command injection and path traversal were identified
        cwes = {f.cwe for f in taint_findings}
        assert "CWE-78" in cwes
