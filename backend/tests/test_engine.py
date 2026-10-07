"""
Unit and integration tests for VulnDetect multi-layer static analysis engine.
"""

import pytest
import os
import sys

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.engine.base import AnalyzerSource, Severity
from app.engine.parser import parse_source, get_call_expressions, get_function_definitions
from app.engine.rule_analyzer import RuleAnalyzer
from app.engine.ast_analyzer import ASTAnalyzer
from app.engine.advanced_ast_analyzer import AdvancedASTAnalyzer
from app.engine.taint_analyzer import TaintAnalyzer
from app.engine.deduplicator import FindingDeduplicator
from app.engine.scorer import FindingScorer
from app.engine.orchestrator import orchestrator
from app.sarif.sarif import generate_sarif_report
from app.schemas.models import VulnerabilityResult


class TestParser:
    def test_c_parsing(self):
        code = "int main() { printf(\"hello\\n\"); return 0; }"
        ctx = parse_source(code, "test.c")
        assert ctx.ast_root is not None
        assert not ctx.is_cpp
        assert len(ctx.lines) == 1
        calls = get_call_expressions(ctx.ast_root)
        assert len(calls) == 1

    def test_cpp_parsing(self):
        code = "#include <iostream>\nint main() { std::cout << 42; return 0; }"
        ctx = parse_source(code, "test.cpp")
        assert ctx.ast_root is not None
        assert ctx.is_cpp
        funcs = get_function_definitions(ctx.ast_root)
        assert len(funcs) == 1


class TestASTAnalyzers:
    def test_format_string_ast(self):
        code = 'void f(char *s) { printf(s); }'
        ctx = parse_source(code, "vuln.c")
        analyzer = ASTAnalyzer()
        findings = analyzer.analyze(ctx)
        assert any(f.rule_id == "AST-FORMAT-001" and f.cwe == "CWE-134" for f in findings)

    def test_dynamic_command_exec(self):
        code = 'void f(char *cmd) { system(cmd); }'
        ctx = parse_source(code, "vuln.c")
        analyzer = ASTAnalyzer()
        findings = analyzer.analyze(ctx)
        assert any(f.rule_id == "AST-CMD-002" and f.cwe == "CWE-78" for f in findings)

    def test_alloc_missing_null_term(self):
        code = 'char *f(const char *s) { char *p = malloc(strlen(s)); return p; }'
        ctx = parse_source(code, "vuln.c")
        analyzer = ASTAnalyzer()
        findings = analyzer.analyze(ctx)
        assert any(f.rule_id == "AST-ALLOC-003" and f.cwe == "CWE-131" for f in findings)

    def test_unchecked_setuid(self):
        code = 'void f() { setuid(0); }'
        ctx = parse_source(code, "vuln.c")
        analyzer = ASTAnalyzer()
        findings = analyzer.analyze(ctx)
        assert any(f.rule_id == "AST-UNCHECKED-005" and f.cwe == "CWE-252" for f in findings)


class TestAdvancedASTAnalyzer:
    def test_null_pointer_dereference(self):
        code = """
        void f(int n) {
            int *p = malloc(n * sizeof(int));
            p[0] = 42;
        }
        """
        ctx = parse_source(code, "vuln.c")
        analyzer = AdvancedASTAnalyzer()
        findings = analyzer.analyze(ctx)
        assert any(f.rule_id == "ADV-NULL-001" and f.cwe == "CWE-476" for f in findings)

    def test_null_pointer_safe_guard(self):
        code = """
        void f(int n) {
            int *p = malloc(n * sizeof(int));
            if (!p) return;
            p[0] = 42;
        }
        """
        ctx = parse_source(code, "safe.c")
        analyzer = AdvancedASTAnalyzer()
        findings = analyzer.analyze(ctx)
        # Should not flag null deref because guard exists
        assert not any(f.rule_id == "ADV-NULL-001" for f in findings)

    def test_use_after_free(self):
        code = """
        void f() {
            char *buf = malloc(64);
            if (!buf) return;
            free(buf);
            printf("%s", buf);
        }
        """
        ctx = parse_source(code, "vuln.c")
        analyzer = AdvancedASTAnalyzer()
        findings = analyzer.analyze(ctx)
        assert any(f.rule_id == "ADV-UAF-001" and f.cwe == "CWE-416" for f in findings)

    def test_double_free(self):
        code = """
        void f() {
            char *buf = malloc(64);
            if (!buf) return;
            free(buf);
            free(buf);
        }
        """
        ctx = parse_source(code, "vuln.c")
        analyzer = AdvancedASTAnalyzer()
        findings = analyzer.analyze(ctx)
        assert any(f.rule_id == "ADV-DOUBLE-FREE-001" and f.cwe == "CWE-415" for f in findings)

    def test_integer_overflow_allocation(self):
        code = """
        void f(int n) {
            int *p = malloc(n * sizeof(int));
        }
        """
        ctx = parse_source(code, "vuln.c")
        analyzer = AdvancedASTAnalyzer()
        findings = analyzer.analyze(ctx)
        assert any(f.rule_id == "ADV-INTOVFL-002" and f.cwe == "CWE-190" for f in findings)

    def test_resource_leak(self):
        code = """
        void f(const char *path) {
            FILE *f = fopen(path, "r");
            if (!f) return;
            char buf[64];
            fgets(buf, sizeof(buf), f);
        }
        """
        ctx = parse_source(code, "vuln.c")
        analyzer = AdvancedASTAnalyzer()
        findings = analyzer.analyze(ctx)
        assert any(f.rule_id == "ADV-LEAK-001" and f.cwe == "CWE-775" for f in findings)

    def test_toctou_race_condition(self):
        code = """
        void f(const char *path) {
            if (access(path, 0) == 0) {
                FILE *fp = fopen(path, "w");
                if (fp) fclose(fp);
            }
        }
        """
        ctx = parse_source(code, "vuln.c")
        analyzer = AdvancedASTAnalyzer()
        findings = analyzer.analyze(ctx)
        assert any(f.rule_id == "ADV-TOCTOU-001" and f.cwe == "CWE-367" for f in findings)


class TestTaintAnalyzer:
    def test_direct_taint_propagation(self):
        code = """
        void f(char *user_input) {
            system(user_input);
        }
        """
        ctx = parse_source(code, "taint.c")
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze(ctx)
        assert any(f.cwe == "CWE-78" and f.analyzer_source == AnalyzerSource.TAINT for f in findings)
        taint_finding = [f for f in findings if f.cwe == "CWE-78"][0]
        assert len(taint_finding.dataflow_path) >= 2

    def test_propagated_taint_sprintf(self):
        code = """
        void f(char *user_input) {
            char cmd[256];
            sprintf(cmd, "ls %s", user_input);
            system(cmd);
        }
        """
        ctx = parse_source(code, "taint.c")
        analyzer = TaintAnalyzer()
        findings = analyzer.analyze(ctx)
        assert any("TAINT-SYSTEM-001" in f.rule_id for f in findings)


class TestDeduplicationAndScoring:
    def test_multi_analyzer_promotion(self):
        code = """
        void f(char *user_input) {
            system(user_input);
        }
        """
        findings = orchestrator.analyze_file("test.c", code)
        cmd_findings = [f for f in findings if f.cwe == "CWE-78"]
        assert len(cmd_findings) == 1
        top = cmd_findings[0]
        assert top.analyzer_source == AnalyzerSource.MULTI_ANALYZER
        assert len(top.evidence) >= 2
        assert top.confidence >= 0.95


class TestSARIFExport:
    def test_sarif_schema_generation(self):
        vuln = VulnerabilityResult(
            file="test.c",
            line=10,
            column=1,
            vulnerability="Command Injection",
            severity="CRITICAL",
            risk_score=0.95,
            confidence=0.95,
            cwe="CWE-78",
            rule_id="TAINT-SYSTEM-001",
            analyzer_source="taint",
            explanation="Untrusted input passed to system()",
            fix="Use execve()",
            code_snippet="system(user_input);",
        )
        sarif = generate_sarif_report([vuln], "scan-123")
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "VulnDetect"
        assert len(sarif["runs"][0]["results"]) == 1
        assert sarif["runs"][0]["results"][0]["ruleId"] == "TAINT-SYSTEM-001"
        assert sarif["runs"][0]["results"][0]["level"] == "error"
