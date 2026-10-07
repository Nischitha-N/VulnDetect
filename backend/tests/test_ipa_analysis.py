"""
Unit and Integration Tests for Inter-Procedural Static Analysis (IPA).
Verifies CallGraph construction, FunctionSummary derivation, cross-function
command injection, helper-driven UAF, and double free detection.
"""

import pytest
import os
import sys

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.engine.parser import parse_source, get_function_definitions
from app.engine.ipa.callgraph import CallGraph
from app.engine.ipa.summarizer import FunctionSummarizer
from app.engine.ipa_analyzer import InterProceduralAnalyzer
from app.engine.orchestrator import orchestrator
from app.engine.base import AnalysisStatus, AnalyzerSource


class TestFunctionSummariesAndCallGraph:
    """Tests for CallGraph topological ordering and FunctionSummary extraction."""

    def test_callgraph_bottom_up_order(self):
        code = """
        void leaf() {}
        void mid() { leaf(); }
        void root() { mid(); }
        """
        ctx = parse_source(code, "cg.c")
        cg = CallGraph()
        cg.build_from_ast(ctx.ast_root, code)
        order = cg.bottom_up_order()
        
        # 'leaf' must appear before 'mid', and 'mid' before 'root'
        assert order.index("leaf") < order.index("mid")
        assert order.index("mid") < order.index("root")

    def test_free_helper_summary_extraction(self):
        code = """
        #include <stdlib.h>
        void my_free(char *buf) {
            free(buf);
        }
        """
        ctx = parse_source(code, "sum.c")
        funcs = get_function_definitions(ctx.ast_root)
        summarizer = FunctionSummarizer()
        summary = summarizer.summarize("my_free", funcs[0], code)

        assert 0 in summary.freed_params
        assert summary.param_names == ["buf"]

    def test_source_helper_summary_extraction(self):
        code = """
        #include <stdlib.h>
        char *get_env_val() {
            return getenv("SECRET");
        }
        """
        ctx = parse_source(code, "sum.c")
        funcs = get_function_definitions(ctx.ast_root)
        summarizer = FunctionSummarizer()
        summary = summarizer.summarize("get_env_val", funcs[0], code)

        assert summary.return_is_source is True
        assert "getenv" in summary.return_source_desc


class TestInterProceduralTaint:
    """Tests for cross-function taint and command injection chains."""

    def test_cross_function_command_injection(self):
        code = """
        #include <stdlib.h>
        char *get_input() {
            return getenv("CMD");
        }

        void execute(char *x) {
            system(x);
        }

        void run() {
            char *cmd = get_input();
            execute(cmd);
        }
        """
        ctx = parse_source(code, "chain.c")
        analyzer = InterProceduralAnalyzer()
        findings = analyzer.analyze(ctx)
        
        taint_findings = [f for f in findings if f.cwe == "CWE-78"]
        assert len(taint_findings) >= 1
        assert taint_findings[0].analysis_status == AnalysisStatus.CONFIRMED
        assert "execute()" in taint_findings[0].message
        assert "get_input()" in taint_findings[0].evidence[0].description

    def test_multihop_propagation_chain(self):
        code = """
        #include <stdlib.h>
        char *step_a() { return getenv("INPUT"); }
        char *step_b() { return step_a(); }
        void step_c(char *p) { popen(p, "r"); }

        void test() {
            char *data = step_b();
            step_c(data);
        }
        """
        ctx = parse_source(code, "multihop.c")
        analyzer = InterProceduralAnalyzer()
        findings = analyzer.analyze(ctx)

        assert len(findings) >= 1
        assert any("step_c" in f.message for f in findings)


class TestInterProceduralMemoryLifecycle:
    """Tests for Use-After-Free and Double-Free across function helpers."""

    def test_interprocedural_uaf(self):
        code = """
        #include <stdlib.h>
        void release(char *ptr) {
            free(ptr);
        }

        void caller() {
            char *p = malloc(10);
            release(p);
            *p = 42;
        }
        """
        ctx = parse_source(code, "uaf.c")
        analyzer = InterProceduralAnalyzer()
        findings = analyzer.analyze(ctx)

        uaf_findings = [f for f in findings if f.rule_id == "IPA-UAF-001"]
        assert len(uaf_findings) == 1
        assert uaf_findings[0].analysis_status == AnalysisStatus.CONFIRMED
        assert "release()" in uaf_findings[0].message

    def test_interprocedural_double_free(self):
        code = """
        #include <stdlib.h>
        void release(char *ptr) {
            free(ptr);
        }

        void caller() {
            char *p = malloc(10);
            release(p);
            release(p);
        }
        """
        ctx = parse_source(code, "df.c")
        analyzer = InterProceduralAnalyzer()
        findings = analyzer.analyze(ctx)

        df_findings = [f for f in findings if f.rule_id == "IPA-DOUBLE-FREE-001"]
        assert len(df_findings) == 1
        assert df_findings[0].analysis_status == AnalysisStatus.CONFIRMED


class TestOrchestratorIPAIntegration:
    """Integration test scanning corpus fixture through full Orchestrator pipeline."""

    def test_corpus_ipa_fixture_scan(self):
        fixture_path = os.path.join(os.path.dirname(__file__), "corpus", "ipa_fixtures.c")
        with open(fixture_path, "r", encoding="utf-8") as f:
            code = f.read()

        findings = orchestrator.analyze_file(fixture_path, code)

        ipa_uaf = [f for f in findings if f.cwe == "CWE-416"]
        assert len(ipa_uaf) >= 1

        ipa_taint = [f for f in findings if f.cwe == "CWE-78"]
        assert len(ipa_taint) >= 1


class TestCrossFileIPA:
    """Tests for cross-file inter-procedural summary collection and vulnerability detection."""

    def test_cross_file_taint_detection(self):
        input_c = """
        #include <stdlib.h>
        char *get_input(void) {
            return getenv("USER_INPUT");
        }
        """
        wrapper_c = """
        #include <stdlib.h>
        void wrapper(char *x) {
            system(x);
        }
        """
        main_c = """
        char *get_input(void);
        void wrapper(char *x);

        int main(void) {
            char *x = get_input();
            wrapper(x);
            return 0;
        }
        """
        from app.core.analyzer import analyze_project
        results = analyze_project([
            ("input.c", input_c),
            ("wrapper.c", wrapper_c),
            ("main.c", main_c),
        ])

        ipa_findings = [r for r in results if r.rule_id == "IPA-TAINT-SYSTEM-001"]
        assert len(ipa_findings) == 1
        assert ipa_findings[0].file == "main.c"
        assert ipa_findings[0].line == 7
        assert ipa_findings[0].analysis_status == "CONFIRMED"
        assert "wrapper()" in ipa_findings[0].explanation
        assert "get_input()" in ipa_findings[0].evidence[0]["description"]


    def test_static_function_not_accessible_cross_file(self):
        file_a = """
        #include <stdlib.h>
        static char *get_input(void) {
            return getenv("SECRET");
        }
        """
        file_b = """
        char *get_input(void);
        void wrapper(char *x);
        int main(void) {
            char *x = get_input();
            wrapper(x);
            return 0;
        }
        """
        from app.core.analyzer import analyze_project
        results = analyze_project([
            ("file_a.c", file_a),
            ("file_b.c", file_b),
        ])

        # Static get_input must NOT leak to file_b.c
        ipa_findings = [r for r in results if r.rule_id == "IPA-TAINT-SYSTEM-001"]
        assert len(ipa_findings) == 0


class TestAliasAwareIPALifecycle:
    """Step 11: Alias-aware inter-procedural UAF detection via Env/Store model."""

    def test_local_alias_interprocedural_free(self):
        """Case A: p = malloc(); q = p; release(q); p[0] => UAF."""
        code = """
        #include <stdlib.h>
        void release(char *ptr) { free(ptr); }
        void main_func() {
            char *p = malloc(10);
            char *q = p;
            release(q);
            p[0] = 65;
        }
        """
        ctx = parse_source(code, "alias_a.c")
        findings = InterProceduralAnalyzer().analyze(ctx)
        uaf = [f for f in findings if f.rule_id == "IPA-UAF-001"]
        assert len(uaf) == 1

    def test_reverse_alias_interprocedural_free(self):
        """Case B: p = malloc(); q = p; release(p); q[0] => UAF."""
        code = """
        #include <stdlib.h>
        void release(char *ptr) { free(ptr); }
        void main_func() {
            char *p = malloc(10);
            char *q = p;
            release(p);
            q[0] = 65;
        }
        """
        ctx = parse_source(code, "alias_b.c")
        findings = InterProceduralAnalyzer().analyze(ctx)
        uaf = [f for f in findings if f.rule_id == "IPA-UAF-001"]
        assert len(uaf) == 1

    def test_two_level_alias_chain(self):
        """Case C: p = malloc(); q = p; r = q; release(r); p[0] => UAF."""
        code = """
        #include <stdlib.h>
        void release(char *ptr) { free(ptr); }
        void main_func() {
            char *p = malloc(10);
            char *q = p;
            char *r = q;
            release(r);
            p[0] = 65;
        }
        """
        ctx = parse_source(code, "alias_c.c")
        findings = InterProceduralAnalyzer().analyze(ctx)
        uaf = [f for f in findings if f.rule_id == "IPA-UAF-001"]
        assert len(uaf) == 1

    def test_independent_allocation_safety(self):
        """Case D: p = malloc(); q = malloc(); release(q); p[0] => SAFE."""
        code = """
        #include <stdlib.h>
        void release(char *ptr) { free(ptr); }
        void main_func() {
            char *p = malloc(10);
            char *q = malloc(20);
            release(q);
            p[0] = 65;
        }
        """
        ctx = parse_source(code, "alias_d.c")
        findings = InterProceduralAnalyzer().analyze(ctx)
        uaf = [f for f in findings if f.rule_id == "IPA-UAF-001"]
        assert len(uaf) == 0

    def test_reassignment_safety(self):
        """Case E: p = malloc(); q = p; p = malloc(); release(q); p[0] => SAFE."""
        code = """
        #include <stdlib.h>
        void release(char *ptr) { free(ptr); }
        void main_func() {
            char *p = malloc(10);
            char *q = p;
            p = malloc(20);
            release(q);
            p[0] = 65;
        }
        """
        ctx = parse_source(code, "alias_e.c")
        findings = InterProceduralAnalyzer().analyze(ctx)
        uaf = [f for f in findings if f.rule_id == "IPA-UAF-001"]
        assert len(uaf) == 0

    def test_existing_direct_uaf_regression(self):
        """Case F: p = malloc(); release(p); p[0] => UAF (regression guard)."""
        code = """
        #include <stdlib.h>
        void release(char *ptr) { free(ptr); }
        void main_func() {
            char *p = malloc(10);
            release(p);
            p[0] = 65;
        }
        """
        ctx = parse_source(code, "alias_f.c")
        findings = InterProceduralAnalyzer().analyze(ctx)
        uaf = [f for f in findings if f.rule_id == "IPA-UAF-001"]
        assert len(uaf) == 1

    def test_existing_wrapper_regression(self):
        """Case G: release_wrapper(p); p[0] => UAF (wrapper regression guard)."""
        code = """
        #include <stdlib.h>
        void release(char *ptr) { free(ptr); }
        void release_wrapper(char *ptr) { release(ptr); }
        void main_func() {
            char *p = malloc(10);
            release_wrapper(p);
            p[0] = 65;
        }
        """
        ctx = parse_source(code, "alias_g.c")
        findings = InterProceduralAnalyzer().analyze(ctx)
        uaf = [f for f in findings if f.rule_id == "IPA-UAF-001"]
        assert len(uaf) == 1

    def test_cross_file_alias_allocator_free(self):
        """Case H: create() returns malloc; q = p; release(q); p[0] => UAF."""
        code = """
        #include <stdlib.h>
        char *create() { return malloc(64); }
        void release(char *ptr) { free(ptr); }
        void main_func() {
            char *p = create();
            char *q = p;
            release(q);
            p[0] = 65;
        }
        """
        ctx = parse_source(code, "alias_h.c")
        findings = InterProceduralAnalyzer().analyze(ctx)
        uaf = [f for f in findings if f.rule_id == "IPA-UAF-001"]
        assert len(uaf) == 1
