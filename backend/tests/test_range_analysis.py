"""
Unit and Integration Tests for Value and Range Analysis Engine.
Verifies abstract interval reasoning, path sensitivity, loop bounds,
array indexing safety, integer overflow, and signed/unsigned conversion.
"""

import pytest
import os
import sys

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.engine.parser import parse_source
from app.engine.range.interval import Interval, CTypeRange, INT32_MAX, INT32_MIN, UINT32_MAX
from app.engine.range_analyzer import RangeAnalyzer
from app.engine.orchestrator import orchestrator
from app.engine.base import AnalysisStatus, AnalyzerSource


class TestIntervalDomain:
    """Tests for the underlying abstract interval mathematics."""

    def test_interval_basic_arithmetic(self):
        a = Interval(2, 5)
        b = Interval(3, 10)
        
        sum_iv = a.add(b)
        assert sum_iv == Interval(5, 15)
        
        diff_iv = a.sub(b)
        assert diff_iv == Interval(-8, 2)
        
        mul_iv = a.mul(b)
        assert mul_iv == Interval(6, 50)
        
        div_iv = b.div(a)
        assert div_iv == Interval(0, 5)

    def test_interval_refinement(self):
        x = Interval.top()
        upper = Interval(-float("inf"), 9)
        lower = Interval(0, float("inf"))
        
        refined = x.intersect(upper).intersect(lower)
        assert refined == Interval(0, 9)
        assert refined.is_definitely_in_bounds(0, 9)
        assert not refined.could_be_negative()

    def test_interval_branch_join(self):
        branch1 = Interval(0, 5)
        branch2 = Interval(10, 15)
        joined = branch1.union(branch2)
        assert joined == Interval(0, 15)


class TestRangeArrayBounds:
    """Tests for static array bounds and index safety reasoning."""

    def test_definitely_safe_constant_index(self):
        code = """
        void test() {
            int a[10];
            a[0] = 42;
            a[5] = 100;
            a[9] = 200;
        }
        """
        ctx = parse_source(code, "safe.c")
        analyzer = RangeAnalyzer()
        findings = analyzer.analyze(ctx)
        # Definitely safe constant indexing must produce 0 findings
        range_findings = [f for f in findings if f.analyzer_source == AnalyzerSource.RANGE]
        assert len(range_findings) == 0

    def test_definitely_unsafe_constant_index(self):
        code = """
        void test() {
            int a[10];
            a[15] = 42;
        }
        """
        ctx = parse_source(code, "vuln.c")
        analyzer = RangeAnalyzer()
        findings = analyzer.analyze(ctx)
        range_findings = [f for f in findings if f.rule_id == "RANGE-ARRAY-OOB-CONFIRMED"]
        assert len(range_findings) == 1
        assert range_findings[0].analysis_status == AnalysisStatus.CONFIRMED
        assert "15" in range_findings[0].message
        assert range_findings[0].cwe in ("CWE-787", "CWE-125")

    def test_negative_constant_index(self):
        code = """
        void test() {
            int a[10];
            a[-1] = 42;
        }
        """
        ctx = parse_source(code, "vuln.c")
        analyzer = RangeAnalyzer()
        findings = analyzer.analyze(ctx)
        range_findings = [f for f in findings if f.rule_id == "RANGE-ARRAY-OOB-CONFIRMED"]
        assert len(range_findings) == 1
        assert range_findings[0].analysis_status == AnalysisStatus.CONFIRMED
        assert range_findings[0].cwe == "CWE-129"

    def test_conditionally_safe_indexing_with_and(self):
        code = """
        void test(int i) {
            int a[10];
            if (i >= 0 && i < 10) {
                a[i] = 1;
            }
        }
        """
        ctx = parse_source(code, "safe.c")
        analyzer = RangeAnalyzer()
        findings = analyzer.analyze(ctx)
        # Should be proved safe because condition refines i to [0, 9]
        range_findings = [f for f in findings if f.analyzer_source == AnalyzerSource.RANGE]
        assert len(range_findings) == 0

    def test_insufficiently_guarded_index(self):
        code = """
        void test(int i) {
            int a[10];
            if (i >= 0) {
                a[i] = 1;
            }
        }
        """
        ctx = parse_source(code, "vuln.c")
        analyzer = RangeAnalyzer()
        findings = analyzer.analyze(ctx)
        # i is [0, +inf], which does not prove i < 10
        range_findings = [f for f in findings if f.rule_id == "RANGE-ARRAY-POTENTIAL-OOB"]
        assert len(range_findings) >= 1
        assert range_findings[0].analysis_status == AnalysisStatus.LIKELY
        assert "a" in range_findings[0].message

    def test_unconstrained_user_index(self):
        code = """
        void test(int user_idx) {
            int a[10];
            a[user_idx] = 1;
        }
        """
        ctx = parse_source(code, "vuln.c")
        analyzer = RangeAnalyzer()
        findings = analyzer.analyze(ctx)
        # Unconstrained parameter index should surface as NEEDS_REVIEW / LIKELY
        range_findings = [f for f in findings if "RANGE-ARRAY" in f.rule_id]
        assert len(range_findings) >= 1
        assert range_findings[0].analysis_status in (AnalysisStatus.NEEDS_REVIEW, AnalysisStatus.LIKELY)


class TestRangeLoopsAndOffByOne:
    """Tests for loop bounds reasoning and off-by-one detection."""

    def test_safe_loop_bound_less_than(self):
        code = """
        void test() {
            int a[10];
            for (int i = 0; i < 10; i++) {
                a[i] = i;
            }
        }
        """
        ctx = parse_source(code, "safe.c")
        analyzer = RangeAnalyzer()
        findings = analyzer.analyze(ctx)
        range_findings = [f for f in findings if f.analyzer_source == AnalyzerSource.RANGE]
        assert len(range_findings) == 0

    def test_off_by_one_loop_bound_less_or_equal(self):
        code = """
        void test() {
            int a[10];
            for (int i = 0; i <= 10; i++) {
                a[i] = i;
            }
        }
        """
        ctx = parse_source(code, "vuln.c")
        analyzer = RangeAnalyzer()
        findings = analyzer.analyze(ctx)
        range_findings = [f for f in findings if f.rule_id == "RANGE-LOOP-OFFBYONE"]
        assert len(range_findings) == 1
        assert range_findings[0].analysis_status == AnalysisStatus.CONFIRMED
        assert range_findings[0].cwe == "CWE-193"
        assert "Off-by-one" in range_findings[0].message


class TestRangeMemoryTransfers:
    """Tests for buffer overflow detection in memory operations (memcpy, etc.)."""

    def test_safe_memcpy_size(self):
        code = """
        #include <string.h>
        void test(char *src) {
            char dest[32];
            memcpy(dest, src, 16);
        }
        """
        ctx = parse_source(code, "safe.c")
        analyzer = RangeAnalyzer()
        findings = analyzer.analyze(ctx)
        range_findings = [f for f in findings if f.rule_id == "RANGE-MEMCPY-OVERFLOW"]
        assert len(range_findings) == 0

    def test_overflow_memcpy_size(self):
        code = """
        #include <string.h>
        void test(char *src) {
            char dest[16];
            memcpy(dest, src, 64);
        }
        """
        ctx = parse_source(code, "vuln.c")
        analyzer = RangeAnalyzer()
        findings = analyzer.analyze(ctx)
        range_findings = [f for f in findings if f.rule_id == "RANGE-MEMCPY-OVERFLOW"]
        assert len(range_findings) == 1
        assert range_findings[0].analysis_status == AnalysisStatus.CONFIRMED
        assert range_findings[0].cwe == "CWE-120"
        assert "64" in range_findings[0].message
        assert "16" in range_findings[0].message


class TestRangeAllocationsAndConversions:
    """Tests for allocation sizing and signed/unsigned conversion issues."""

    def test_negative_malloc_size(self):
        code = """
        #include <stdlib.h>
        void test() {
            void *p = malloc(-10);
        }
        """
        ctx = parse_source(code, "vuln.c")
        analyzer = RangeAnalyzer()
        findings = analyzer.analyze(ctx)
        range_findings = [f for f in findings if f.rule_id == "RANGE-ALLOC-NEGATIVE"]
        assert len(range_findings) == 1
        assert range_findings[0].analysis_status == AnalysisStatus.CONFIRMED
        assert range_findings[0].cwe == "CWE-131"

    def test_signed_to_unsigned_conversion_hazard(self):
        code = """
        #include <string.h>
        void test(char *src, int len) {
            char dest[64];
            // len is signed and can be negative
            memcpy(dest, src, len);
        }
        """
        ctx = parse_source(code, "vuln.c")
        analyzer = RangeAnalyzer()
        findings = analyzer.analyze(ctx)
        range_findings = [f for f in findings if f.rule_id == "RANGE-SIGNED-UNSIGNED-CONV"]
        assert len(range_findings) == 1
        assert range_findings[0].cwe == "CWE-195"


class TestRangeAdvancedFlowAndArithmetic:
    """Tests for early return guards, constant propagation, and arithmetic bounds."""

    def test_early_return_guard_refinement(self):
        code = """
        void test(int i) {
            int a[10];
            if (i < 0 || i >= 10) {
                return;
            }
            a[i] = 1;
        }
        """
        ctx = parse_source(code, "safe.c")
        analyzer = RangeAnalyzer()
        findings = analyzer.analyze(ctx)
        # Should be proved safe because early exit leaves i in [0, 9]
        range_findings = [f for f in findings if f.analyzer_source == AnalyzerSource.RANGE]
        assert len(range_findings) == 0

    def test_constant_propagation_arithmetic_safe(self):
        code = """
        void test() {
            int a[10];
            int x = 2;
            int y = x * 3 + 1; // 7
            a[y] = 100;
        }
        """
        ctx = parse_source(code, "safe.c")
        analyzer = RangeAnalyzer()
        findings = analyzer.analyze(ctx)
        range_findings = [f for f in findings if f.analyzer_source == AnalyzerSource.RANGE]
        assert len(range_findings) == 0

    def test_arithmetic_overflow_detection(self):
        code = """
        void test(int a) {
            int c = a + 2147483640;
        }
        """
        ctx = parse_source(code, "overflow.c")
        analyzer = RangeAnalyzer()
        findings = analyzer.analyze(ctx)
        ov_findings = [f for f in findings if f.rule_id == "RANGE-INTEGER-OVERFLOW"]
        assert len(ov_findings) >= 1
        assert ov_findings[0].cwe == "CWE-190"


class TestOrchestratorRangeIntegration:
    """Integration test verifying RangeAnalyzer works inside full Orchestrator pipeline."""

    def test_orchestrator_multi_analyzer_with_range(self):
        code = """
        void process() {
            int buffer[5];
            buffer[10] = 99;
        }
        """
        findings = orchestrator.analyze_file("integration.c", code)
        oob_findings = [f for f in findings if f.rule_id == "RANGE-ARRAY-OOB-CONFIRMED"]
        assert len(oob_findings) >= 1
        assert oob_findings[0].analysis_status == AnalysisStatus.CONFIRMED
        assert oob_findings[0].risk_score >= 0.85

    def test_corpus_range_fixture_scan(self):
        fixture_path = os.path.join(os.path.dirname(__file__), "corpus", "cwe_125_787_range_bounds.c")
        with open(fixture_path, "r", encoding="utf-8") as f:
            code = f.read()

        findings = orchestrator.analyze_file(fixture_path, code)
        
        # Check that confirmed vulnerabilities were found
        confirmed_ids = {f.rule_id for f in findings if f.analysis_status == AnalysisStatus.CONFIRMED}
        assert "RANGE-ARRAY-OOB-CONFIRMED" in confirmed_ids
        assert "RANGE-LOOP-OFFBYONE" in confirmed_ids
        assert "RANGE-MEMCPY-OVERFLOW" in confirmed_ids
        assert "RANGE-ALLOC-NEGATIVE" in confirmed_ids


