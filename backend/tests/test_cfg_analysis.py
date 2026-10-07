"""
Unit and Integration Tests for Control-Flow Graph and Path-Sensitive Static Analysis.
Verifies BasicBlock construction, branching edges, lattice state joins,
guarded early returns, path-dependent UAF, resource leaks, and uninitialized reads.
"""

import pytest
import os
import sys

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.engine.parser import parse_source, get_function_definitions
from app.engine.cfg.builder import CFGBuilder
from app.engine.cfg.graph import EdgeKind
from app.engine.cfg_analyzer import CFGAnalyzer
from app.engine.orchestrator import orchestrator
from app.engine.base import AnalysisStatus, AnalyzerSource


class TestCFGConstruction:
    """Tests verifying accurate CFG graph construction, basic blocks, and edge kinds."""

    def test_linear_function_cfg(self):
        code = """
        void linear() {
            int a = 1;
            int b = 2;
            int c = a + b;
        }
        """
        ctx = parse_source(code, "test.c")
        funcs = get_function_definitions(ctx.ast_root)
        builder = CFGBuilder(funcs[0], code)
        cfg = builder.build()

        assert cfg.entry_block is not None
        assert cfg.exit_block is not None
        assert len(cfg.blocks) >= 2
        succs = cfg.get_successors(cfg.entry_block)
        assert len(succs) >= 1

    def test_if_else_branching_edges(self):
        code = """
        void branch(int x) {
            if (x > 0) {
                int a = 1;
            } else {
                int b = 2;
            }
            int c = 3;
        }
        """
        ctx = parse_source(code, "test.c")
        funcs = get_function_definitions(ctx.ast_root)
        cfg = CFGBuilder(funcs[0], code).build()

        edge_kinds = {e.kind for b in cfg.blocks.values() for e in b.outgoing_edges}
        assert EdgeKind.TRUE_BRANCH in edge_kinds
        assert EdgeKind.FALSE_BRANCH in edge_kinds

    def test_loop_and_break_edges(self):
        code = """
        void loop_test(int n) {
            for (int i = 0; i < n; i++) {
                if (i == 5) break;
                if (i == 2) continue;
            }
        }
        """
        ctx = parse_source(code, "test.c")
        funcs = get_function_definitions(ctx.ast_root)
        cfg = CFGBuilder(funcs[0], code).build()

        edge_kinds = {e.kind for b in cfg.blocks.values() for e in b.outgoing_edges}
        assert EdgeKind.LOOP_BODY in edge_kinds
        assert EdgeKind.LOOP_EXIT in edge_kinds
        assert EdgeKind.BREAK_TO_EXIT in edge_kinds
        assert EdgeKind.CONTINUE_LOOP in edge_kinds


class TestPathSensitiveNullDereference:
    """Tests verifying path-sensitive null dereference and early-return guard reasoning."""

    def test_early_return_null_guard_is_safe(self):
        code = """
        void test_guarded(char *p) {
            if (p == NULL)
                return;

            *p = 'A'; // MUST NOT report null dereference
        }
        """
        ctx = parse_source(code, "safe.c")
        analyzer = CFGAnalyzer()
        findings = analyzer.analyze(ctx)
        null_findings = [f for f in findings if f.cwe == "CWE-476"]
        assert len(null_findings) == 0

    def test_non_returning_error_log_is_unsafe(self):
        code = """
        void test_unguarded_log(char *p) {
            if (p == NULL)
                log_error();

            *p = 'A'; // POTENTIALLY UNSAFE along the NULL path
        }
        """
        ctx = parse_source(code, "vuln.c")
        analyzer = CFGAnalyzer()
        findings = analyzer.analyze(ctx)
        null_findings = [f for f in findings if f.cwe == "CWE-476"]
        assert len(null_findings) >= 1
        assert null_findings[0].analysis_status in (AnalysisStatus.LIKELY, AnalysisStatus.CONFIRMED)

    def test_malloc_safe_with_null_guard(self):
        code = """
        #include <stdlib.h>
        void test_safe_malloc() {
            char *p = malloc(64);
            if (!p)
                return;

            *p = 'B'; // SAFE
        }
        """
        ctx = parse_source(code, "safe.c")
        analyzer = CFGAnalyzer()
        findings = analyzer.analyze(ctx)
        null_findings = [f for f in findings if f.cwe == "CWE-476"]
        assert len(null_findings) == 0

    def test_malloc_unsafe_without_exit(self):
        code = """
        #include <stdlib.h>
        void test_unsafe_malloc() {
            char *p = malloc(64);
            if (!p)
                log_error();

            *p = 'B'; // LIKELY null dereference
        }
        """
        ctx = parse_source(code, "vuln.c")
        analyzer = CFGAnalyzer()
        findings = analyzer.analyze(ctx)
        null_findings = [f for f in findings if f.cwe == "CWE-476"]
        assert len(null_findings) >= 1


class TestPathSensitiveMemoryLifecycle:
    """Tests for Use-After-Free and Double-Free along specific execution paths."""

    def test_confirmed_uaf_linear(self):
        code = """
        #include <stdlib.h>
        void test_uaf() {
            char *p = malloc(32);
            free(p);
            *p = 'X';
        }
        """
        ctx = parse_source(code, "vuln.c")
        analyzer = CFGAnalyzer()
        findings = analyzer.analyze(ctx)
        uaf_findings = [f for f in findings if f.rule_id == "CFG-UAF-CONFIRMED-001"]
        assert len(uaf_findings) == 1
        assert uaf_findings[0].analysis_status == AnalysisStatus.CONFIRMED

    def test_path_dependent_uaf_branch(self):
        code = """
        #include <stdlib.h>
        void test_uaf_branch(int cond) {
            char *p = malloc(32);
            if (cond) {
                free(p);
            }
            *p = 'Y'; // POTENTIAL UAF on cond=True path
        }
        """
        ctx = parse_source(code, "vuln.c")
        analyzer = CFGAnalyzer()
        findings = analyzer.analyze(ctx)
        uaf_findings = [f for f in findings if "CFG-UAF" in f.rule_id]
        assert len(uaf_findings) >= 1
        assert uaf_findings[0].analysis_status == AnalysisStatus.LIKELY

    def test_confirmed_double_free(self):
        code = """
        #include <stdlib.h>
        void test_double_free() {
            char *p = malloc(32);
            free(p);
            free(p);
        }
        """
        ctx = parse_source(code, "vuln.c")
        analyzer = CFGAnalyzer()
        findings = analyzer.analyze(ctx)
        df_findings = [f for f in findings if f.rule_id == "CFG-DOUBLE-FREE-CONFIRMED-001"]
        assert len(df_findings) == 1
        assert df_findings[0].analysis_status == AnalysisStatus.CONFIRMED


class TestPathSensitiveResourcesAndUninit:
    """Tests for resource leaks on error exit paths and uninitialized variable reads."""

    def test_resource_leak_on_error_path(self):
        code = """
        #include <stdio.h>
        void test_leak(int err) {
            FILE *f = fopen("data.txt", "r");
            if (err) {
                return; // LEAK on err=True path
            }
            fclose(f);
        }
        """
        ctx = parse_source(code, "vuln.c")
        analyzer = CFGAnalyzer()
        findings = analyzer.analyze(ctx)
        leak_findings = [f for f in findings if f.cwe == "CWE-775"]
        assert len(leak_findings) >= 1
        assert "f" in leak_findings[0].message

    def test_uninitialized_variable_read(self):
        code = """
        int test_uninit(int cond) {
            int x;
            if (cond) {
                x = 42;
            }
            return x + 1; // UNINIT on cond=False path
        }
        """
        ctx = parse_source(code, "vuln.c")
        analyzer = CFGAnalyzer()
        findings = analyzer.analyze(ctx)
        uninit_findings = [f for f in findings if f.cwe == "CWE-457"]
        assert len(uninit_findings) >= 1


class TestPathSensitiveAdvancedConstructs:
    """Tests for switch-case, goto jumps, and while loop paths."""

    def test_switch_case_break_vs_fallthrough(self):
        code = """
        #include <stdlib.h>
        void test_switch(int mode) {
            char *p = malloc(16);
            switch (mode) {
                case 1:
                    free(p);
                    break;
                case 2:
                    *p = 'A';
                    break;
                default:
                    free(p);
                    break;
            }
        }
        """
        ctx = parse_source(code, "switch.c")
        analyzer = CFGAnalyzer()
        findings = analyzer.analyze(ctx)
        # In case 2, p is accessed safely without free; no UAF in case 2
        uaf_in_case2 = [f for f in findings if f.rule_id == "CFG-UAF-CONFIRMED-001" and f.line == 11]
        assert len(uaf_in_case2) == 0

    def test_goto_cleanup_pattern_is_safe(self):
        code = """
        #include <stdlib.h>
        int test_goto(int err) {
            char *p = malloc(16);
            if (!p)
                goto error;

            *p = 'Z'; // SAFE

            free(p);
            return 0;

        error:
            return -1;
        }
        """
        ctx = parse_source(code, "goto.c")
        analyzer = CFGAnalyzer()
        findings = analyzer.analyze(ctx)
        null_findings = [f for f in findings if f.cwe == "CWE-476"]
        assert len(null_findings) == 0


class TestOrchestratorCFGIntegration:
    """Integration test verifying CFG findings pass through the full multi-analyzer pipeline."""

    def test_orchestrator_multi_analyzer_with_cfg(self):
        code = """
        #include <stdlib.h>
        void execute_task() {
            char *buf = malloc(16);
            free(buf);
            *buf = 'K';
        }
        """
        findings = orchestrator.analyze_file("orchestrator_cfg.c", code)
        uaf = [f for f in findings if f.cwe == "CWE-416"]
        assert len(uaf) >= 1
        assert any(f.analysis_status == AnalysisStatus.CONFIRMED for f in uaf)

