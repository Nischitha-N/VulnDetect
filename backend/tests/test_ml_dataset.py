"""
Unit and Integration Tests for VulnDetect ML Finding Triage Dataset & Feature Pipeline.
Verifies:
- 56-sample dataset integrity, schema, and 50/50 class balance.
- Strict isolation from benchmark fixtures (zero contamination).
- Grouped split reproducibility and zero group leakage across train/val/test.
- Feature extraction on live Finding objects produced by the orchestrator.
- Exact 12-dimensional numerical vector output with valid bounds.
"""

import pytest
import os
import sys
import numpy as np
from pathlib import Path

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.ml.dataset.split import load_dataset, get_grouped_split
from app.ml.dataset.validate import validate_dataset, REQUIRED_FIELDS
from app.ml.feature_extractor import (
    extract_finding_features,
    extract_batch_features,
    FEATURE_NAMES,
    N_FEATURES,
)
from app.engine.orchestrator import AnalysisOrchestrator
from app.engine.base import Finding, Severity, AnalyzerSource, AnalysisStatus, DataflowStep


class TestMLDatasetIntegrity:
    """Verifies dataset size, class balance, schema, and benchmark quarantine."""

    def test_dataset_sample_counts_and_balance(self):
        samples = load_dataset()
        assert len(samples) == 56
        pos = [s for s in samples if s["label"] == 1]
        neg = [s for s in samples if s["label"] == 0]
        assert len(pos) == 28
        assert len(neg) == 28

    def test_cwe_coverage(self):
        samples = load_dataset()
        cwe_counts = {}
        for s in samples:
            cwe_counts[s["cwe"]] = cwe_counts.get(s["cwe"], 0) + 1

        assert set(cwe_counts.keys()) == {"CWE-78", "CWE-416", "CWE-193", "CWE-134"}
        for cwe, count in cwe_counts.items():
            assert count == 14

    def test_schema_required_fields(self):
        samples = load_dataset()
        for s in samples:
            for field in REQUIRED_FIELDS:
                assert field in s, f"Sample {s.get('sample_id')} missing {field}"
                assert s[field] is not None
                assert s[field] != ""

    def test_benchmark_fixture_quarantine(self):
        """CRITICAL: Ensure none of the 24 benchmark fixtures leak into ML dataset."""
        samples = load_dataset()
        forbidden_patterns = ["manifest.py", "tests/benchmark", "tests\\benchmark"]
        for s in samples:
            src = s["source_file"].replace("\\", "/")
            for pat in forbidden_patterns:
                assert pat not in src, f"Benchmark fixture leaked in {s['sample_id']}: {src}"

    def test_validate_dataset_utility(self):
        report = validate_dataset()
        assert report["status"] == "PASS"
        assert report["total_samples"] == 56
        assert report["positive_count"] == 28
        assert report["negative_count"] == 28


class TestMLGroupedSplit:
    """Verifies deterministic grouping, zero leakage, and partition distributions."""

    def test_zero_group_leakage(self):
        samples = load_dataset()
        splits = get_grouped_split(samples, seed=42)

        train_groups = set(s["group_id"] for s in splits["train"])
        val_groups = set(s["group_id"] for s in splits["val"])
        test_groups = set(s["group_id"] for s in splits["test"])

        assert len(train_groups.intersection(val_groups)) == 0
        assert len(train_groups.intersection(test_groups)) == 0
        assert len(val_groups.intersection(test_groups)) == 0

    def test_partition_counts_and_balance(self):
        samples = load_dataset()
        splits = get_grouped_split(samples, seed=42)

        # Train: 32 (16 groups), Val: 12 (6 groups), Test: 12 (6 groups)
        assert len(splits["train"]) == 32
        assert len(splits["val"]) == 12
        assert len(splits["test"]) == 12

        for part in ["train", "val", "test"]:
            pos = sum(1 for s in splits[part] if s["label"] == 1)
            neg = sum(1 for s in splits[part] if s["label"] == 0)
            assert pos == neg, f"Split {part} is imbalanced: {pos} pos vs {neg} neg"

    def test_split_reproducibility(self):
        samples = load_dataset()
        split1 = get_grouped_split(samples, seed=42)
        split2 = get_grouped_split(samples, seed=42)

        assert [s["sample_id"] for s in split1["train"]] == [s["sample_id"] for s in split2["train"]]
        assert [s["sample_id"] for s in split1["val"]] == [s["sample_id"] for s in split2["val"]]
        assert [s["sample_id"] for s in split1["test"]] == [s["sample_id"] for s in split2["test"]]


class TestMLFeatureExtractor:
    """Verifies finding-level feature extraction on real Finding objects and sample dicts."""

    def test_feature_count_and_names(self):
        assert len(FEATURE_NAMES) == 12
        assert N_FEATURES == 12

    def test_extract_from_synthetic_finding(self):
        f = Finding(
            rule_id="TAINT-SYSTEM-001",
            cwe="CWE-78",
            vulnerability_type="Command Injection",
            severity=Severity.CRITICAL,
            confidence=0.95,
            file="vuln.c",
            line=10,
            code_snippet='system(user_cmd);',
            analyzer_source=AnalyzerSource.TAINT,
            analysis_status=AnalysisStatus.CONFIRMED,
            dataflow_path=[
                DataflowStep("SOURCE", 5, 0, 'getenv("CMD")', "Environment variable read"),
                DataflowStep("SINK", 10, 0, 'system(user_cmd)', "Command execution sink"),
            ]
        )
        vec = extract_finding_features(f)
        assert isinstance(vec, np.ndarray)
        assert vec.shape == (12,)
        assert vec[0] == pytest.approx(0.95)  # analyzer_confidence
        assert vec[1] == 0.0                  # is_multi_layer
        assert vec[2] == 1.0                  # has_dataflow_path
        assert vec[3] == 2.0                  # dataflow_step_count
        assert vec[4] == 0.0                  # has_sanitizer_in_path
        assert vec[5] == 0.0                  # is_interprocedural
        assert vec[6] == 1.0                  # analysis_status_code (CONFIRMED)
        assert vec[7] == 1.0                  # cwe_family_id (CWE-78)
        assert vec[8] == 0.0                  # has_guard_in_snippet
        assert vec[9] == 0.0                  # is_constant_literal_sink
        assert vec[10] > 0.0                  # line_length_norm
        assert vec[11] == 0.0                 # pointer_deref_present

    def test_extract_from_live_orchestrator_findings(self):
        orch = AnalysisOrchestrator()
        code = """
        #include <stdio.h>
        #include <stdlib.h>
        void vulnerable(char *input) {
            printf(input);
        }
        """
        findings = orch.analyze_file("live_test.c", code)
        assert len(findings) >= 1

        target = next(f for f in findings if f.cwe == "CWE-134")
        vec = extract_finding_features(target)
        assert len(vec) == 12
        assert vec[7] == 4.0  # CWE-134
        assert vec[0] >= 0.8  # high confidence format string rule

    def test_batch_extraction_consistency(self):
        samples = load_dataset()
        batch_matrix = extract_batch_features(samples)
        assert batch_matrix.shape == (56, 12)

        for i, s in enumerate(samples):
            single_vec = extract_finding_features(s)
            np.testing.assert_array_almost_equal(batch_matrix[i], single_vec)
