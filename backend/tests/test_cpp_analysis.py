"""
Unit and Integration Tests for C++ Semantic Analysis Layer.
Verifies Move Semantics, new/delete mismatches, Iterator invalidation,
Dangling local references, Polymorphic destruction, and Safe RAII idioms.
"""

import pytest
import os
import sys

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.engine.parser import parse_source
from app.engine.cpp_analyzer import CppAnalyzer
from app.engine.orchestrator import orchestrator
from app.engine.base import AnalysisStatus, AnalyzerSource


class TestCppMoveSemantics:
    """Tests for std::move and Use-After-Move detection."""

    def test_use_after_move_detected(self):
        code = """
        #include <string>
        #include <iostream>
        void test() {
            std::string s = "hello";
            std::string s2 = std::move(s);
            std::cout << s;
        }
        """
        ctx = parse_source(code, "move.cpp")
        analyzer = CppAnalyzer()
        findings = analyzer.analyze(ctx)

        uam = [f for f in findings if f.rule_id == "CPP-USE-AFTER-MOVE-001"]
        assert len(uam) == 1
        assert uam[0].cwe == "CWE-672"
        assert uam[0].analysis_status == AnalysisStatus.CONFIRMED
        assert "s" in uam[0].message


class TestCppNewDeleteMismatches:
    """Tests for array new[] / scalar delete and scalar new / array delete[] mismatches."""

    def test_array_new_scalar_delete_mismatch(self):
        code = """
        void test() {
            int *buf = new int[50];
            delete buf;
        }
        """
        ctx = parse_source(code, "mismatch1.cpp")
        analyzer = CppAnalyzer()
        findings = analyzer.analyze(ctx)

        mismatch = [f for f in findings if f.rule_id == "CPP-ARRAY-DELETE-MISMATCH-001"]
        assert len(mismatch) == 1
        assert mismatch[0].cwe == "CWE-762"
        assert mismatch[0].analysis_status == AnalysisStatus.CONFIRMED

    def test_scalar_new_array_delete_mismatch(self):
        code = """
        void test() {
            int *val = new int(10);
            delete[] val;
        }
        """
        ctx = parse_source(code, "mismatch2.cpp")
        analyzer = CppAnalyzer()
        findings = analyzer.analyze(ctx)

        mismatch = [f for f in findings if f.rule_id == "CPP-SCALAR-DELETE-MISMATCH-002"]
        assert len(mismatch) == 1
        assert mismatch[0].cwe == "CWE-762"


class TestCppDanglingReferencesAndTemporaries:
    """Tests for returning references to local variables and temporary string pointers."""

    def test_dangling_local_reference_return(self):
        code = """
        int &get_local() {
            int stack_var = 42;
            return stack_var;
        }
        """
        ctx = parse_source(code, "dangling.cpp")
        analyzer = CppAnalyzer()
        findings = analyzer.analyze(ctx)

        dangling = [f for f in findings if f.rule_id == "CPP-DANGLING-LOCAL-RETURN-001"]
        assert len(dangling) == 1
        assert dangling[0].cwe == "CWE-562"
        assert dangling[0].analysis_status == AnalysisStatus.CONFIRMED

    def test_dangling_temporary_c_str_pointer(self):
        code = """
        #include <string>
        void test() {
            const char *p = std::string("test").c_str();
        }
        """
        ctx = parse_source(code, "temp.cpp")
        analyzer = CppAnalyzer()
        findings = analyzer.analyze(ctx)

        temp_findings = [f for f in findings if f.rule_id == "CPP-DANGLING-TEMPORARY-002"]
        assert len(temp_findings) == 1
        assert temp_findings[0].cwe == "CWE-672"


class TestCppIteratorInvalidation:
    """Tests for vector reallocation iterator invalidation."""

    def test_iterator_invalidation_on_vector(self):
        code = """
        #include <vector>
        void test() {
            std::vector<int> v = {1, 2};
            auto it = v.begin();
            v.push_back(3);
            *it = 99;
        }
        """
        ctx = parse_source(code, "iter.cpp")
        analyzer = CppAnalyzer()
        findings = analyzer.analyze(ctx)

        inv = [f for f in findings if f.rule_id == "CPP-ITERATOR-INVALIDATION-001"]
        assert len(inv) == 1
        assert inv[0].cwe == "CWE-825"
        assert inv[0].analysis_status == AnalysisStatus.CONFIRMED


class TestCppPolymorphicDestructors:
    """Tests for polymorphic deletion through base class without virtual destructor."""

    def test_non_virtual_destructor_deletion(self):
        code = """
        class Base {
        public:
            virtual void process();
            ~Base();
        };

        class Derived : public Base {
        public:
            void process() override;
        };

        void test() {
            Base *obj = new Derived();
            delete obj;
        }
        """
        ctx = parse_source(code, "poly.cpp")
        analyzer = CppAnalyzer()
        findings = analyzer.analyze(ctx)

        dtor_findings = [f for f in findings if f.rule_id == "CPP-NON-VIRTUAL-DTOR-001"]
        assert len(dtor_findings) == 1
        assert dtor_findings[0].cwe == "CWE-1079"


class TestCppSafeIdioms:
    """Tests verifying modern idiomatic RAII code produces 0 false positives."""

    def test_safe_raii_no_findings(self):
        code = """
        #include <memory>
        #include <vector>
        void test() {
            auto u = std::make_unique<int>(10);
            std::vector<int> v = {1, 2, 3};
            v.push_back(4);
            int x = v[0];
        }
        """
        ctx = parse_source(code, "safe.cpp")
        analyzer = CppAnalyzer()
        findings = analyzer.analyze(ctx)
        assert len(findings) == 0


class TestOrchestratorCppIntegration:
    """Integration test scanning corpus fixture through full Orchestrator pipeline."""

    def test_corpus_cpp_fixture_scan(self):
        fixture_path = os.path.join(os.path.dirname(__file__), "corpus", "cpp_semantics.cpp")
        with open(fixture_path, "r", encoding="utf-8") as f:
            code = f.read()

        findings = orchestrator.analyze_file(fixture_path, code)

        cpp_findings = [f for f in findings if f.analyzer_source in (AnalyzerSource.CPP, AnalyzerSource.MULTI_ANALYZER)]
        assert len(cpp_findings) >= 4

        cwes = {f.cwe for f in cpp_findings}
        assert "CWE-672" in cwes  # Use-after-move / dangling temporary
        assert "CWE-762" in cwes  # Mismatched deallocation
