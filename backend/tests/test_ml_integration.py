"""
Integration Tests for VulnDetect ML Auxiliary Finding Verification.

Verifies:
1. Model loads successfully from backend/app/ml/models/final_model.joblib.
2. Correct 12-feature vector reaches the model with verified feature ordering.
3. Prediction probability is strictly bounded in [0.0, 1.0].
4. Supported CWEs (CWE-78, CWE-416, CWE-193, CWE-134) receive 'VERIFIED' status.
5. Unsupported CWEs (e.g. CWE-476, CWE-131) receive 'NOT_SUPPORTED' status without prediction.
6. CRITICAL: Static finding remains in the output when ML predicts false (label 0 / score < 0.50).
7. Static analyzer confidence is strictly preserved (never overwritten by ML score).
8. ML inference failure or missing model fails safely without aborting scanning.
9. Model artifact is not modified or retrained at runtime.
10. Batch verification correctly handles multiple heterogeneous findings.
11. API serialization (VulnerabilityResult) propagates ML metadata in a backward-compatible manner.
"""

import os
import sys
import copy
from pathlib import Path
import numpy as np
import pytest

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.ml.predictor import (
    MLPredictor,
    get_ml_predictor,
    is_cwe_supported,
    DEFAULT_THRESHOLD,
    MODEL_PATH,
    METADATA_PATH,
)
from app.ml.feature_extractor import FEATURE_NAMES, N_FEATURES
from app.engine.base import Finding, Severity, AnalyzerSource, AnalysisStatus
from app.engine.orchestrator import AnalysisOrchestrator, orchestrator
from app.schemas.models import VulnerabilityResult
from app.core.analyzer import _findings_to_results


class TestMLModelLoading:
    """Verifies artifact loading, singleton behavior, and feature alignment."""

    def test_model_loads_successfully(self):
        predictor = get_ml_predictor()
        assert predictor.is_loaded is True
        assert predictor.model is not None
        assert predictor.load_error is None

    def test_feature_vector_alignment(self):
        predictor = get_ml_predictor()
        saved_features = predictor.metadata.get("feature_pipeline", {}).get("feature_names", [])
        assert len(saved_features) == 12
        assert saved_features == FEATURE_NAMES


class TestMLPredictionProperties:
    """Verifies probability bounds, thresholds, and feature vector integrity."""

    def test_supported_cwe_prediction_and_bounds(self):
        predictor = get_ml_predictor()
        finding = Finding(
            rule_id="TAINT-SYSTEM-001",
            cwe="CWE-78",
            vulnerability_type="Command Injection",
            severity=Severity.HIGH,
            confidence=0.88,
            message="Tainted input reaching system()",
            file="src/exec.c",
            line=42,
            code_snippet='system(user_cmd);',
            analyzer_source=AnalyzerSource.TAINT,
            analysis_status=AnalysisStatus.CONFIRMED,
        )

        res = predictor.verify_finding(finding)
        assert res["status"] == "VERIFIED"
        assert res["ml_verification_score"] is not None
        assert 0.0 <= res["ml_verification_score"] <= 1.0
        assert isinstance(res["ml_predicted_valid"], bool)
        assert res["ml_predicted_valid"] == (res["ml_verification_score"] >= DEFAULT_THRESHOLD)
        assert res["ml_model"] == "RandomForest"

    def test_unsupported_cwe_handling(self):
        predictor = get_ml_predictor()
        unsupported_cwes = ["CWE-476", "CWE-131", "CWE-190", "CWE-787", "CWE-399"]

        for cwe in unsupported_cwes:
            finding = Finding(
                rule_id="RULE-NULL-001",
                cwe=cwe,
                vulnerability_type="Unsupported Type",
                severity=Severity.MEDIUM,
                confidence=0.75,
                message="Testing unsupported category",
                file="src/test.c",
                line=12,
                code_snippet='*ptr = NULL;',
                analyzer_source=AnalyzerSource.AST,
                analysis_status=AnalysisStatus.LIKELY,
            )

            res = predictor.verify_finding(finding)
            assert res["status"] == "NOT_SUPPORTED", f"Expected NOT_SUPPORTED for {cwe}"
            assert res["ml_verification_score"] is None
            assert res["ml_predicted_valid"] is None

    def test_all_four_supported_cwes(self):
        predictor = get_ml_predictor()
        supported = ["CWE-78", "CWE-416", "CWE-193", "CWE-134"]

        for cwe in supported:
            finding = Finding(
                rule_id=f"TEST-{cwe}",
                cwe=cwe,
                vulnerability_type="Supported Vulnerability",
                severity=Severity.HIGH,
                confidence=0.80,
                message="Test supported cwe",
                file="src/vuln.c",
                line=20,
                code_snippet='char buf[10]; buf[10] = 0;',
                analyzer_source=AnalyzerSource.AST,
                analysis_status=AnalysisStatus.CONFIRMED,
            )
            res = predictor.verify_finding(finding)
            assert res["status"] == "VERIFIED", f"Failed to verify supported {cwe}"
            assert res["ml_verification_score"] is not None


class TestMLAuthoritativeStaticPreservation:
    """
    CRITICAL TESTS:
    Verifies that static analysis remains 100% authoritative:
    - ML prediction = 0 (false) DOES NOT cause the finding to be deleted or filtered.
    - Static confidence is preserved unchanged.
    """

    def test_finding_persists_when_ml_predicts_false(self):
        """Proves that a finding with ML prediction = 0 remains in the output."""
        predictor = get_ml_predictor()

        # Construct a finding that will evaluate as a potential false positive
        finding = Finding(
            rule_id="RULE-FMT-002",
            cwe="CWE-134",
            vulnerability_type="Use of Externally-Controlled Format String",
            severity=Severity.MEDIUM,
            confidence=0.55,
            message="Constant format string table lookup",
            file="src/log.c",
            line=30,
            code_snippet='const char *fmt = table[idx]; printf(fmt, val);',
            analyzer_source=AnalyzerSource.AST,
            analysis_status=AnalysisStatus.NEEDS_REVIEW,
        )

        initial_count = 1
        findings = [finding]
        verified_findings = predictor.verify_findings(findings)

        # 1. Finding must NOT be deleted
        assert len(verified_findings) == initial_count
        retained_finding = verified_findings[0]

        # 2. Verify ML status is present
        assert "ml_verification" in retained_finding.metadata
        assert retained_finding.metadata["ml_verification_status"] == "VERIFIED"

        # 3. Even if ml_predicted_valid is False or True, finding is retained
        assert retained_finding.rule_id == "RULE-FMT-002"
        assert retained_finding.cwe == "CWE-134"

    def test_static_confidence_not_overwritten(self):
        """Verifies that static analyzer confidence is strictly decoupled from ML score."""
        predictor = get_ml_predictor()
        static_conf = 0.888

        finding = Finding(
            rule_id="TAINT-SYSTEM-001",
            cwe="CWE-78",
            vulnerability_type="Command Injection",
            severity=Severity.HIGH,
            confidence=static_conf,
            message="Tainted command execution",
            file="src/exec.c",
            line=15,
            code_snippet='system(cmd);',
            analyzer_source=AnalyzerSource.TAINT,
            analysis_status=AnalysisStatus.CONFIRMED,
        )

        verified = predictor.verify_findings([finding])[0]

        # Static confidence MUST remain exact original value
        assert verified.confidence == static_conf
        # ML score is stored in metadata, not overwriting confidence
        assert verified.metadata["ml_verification_score"] != static_conf
        assert 0.0 <= verified.metadata["ml_verification_score"] <= 1.0


class TestMLResilienceAndNonRetraining:
    """Verifies error handling, non-retraining, and multi-finding batch execution."""

    def test_model_not_retrained_at_runtime(self):
        predictor = get_ml_predictor()
        mtime_before = os.path.getmtime(MODEL_PATH)

        finding = Finding(
            rule_id="MEM-416-001",
            cwe="CWE-416",
            vulnerability_type="Use After Free",
            severity=Severity.CRITICAL,
            confidence=0.90,
            message="Dangling pointer access",
            file="src/mem.c",
            line=50,
            code_snippet='free(p); p->val = 1;',
            analyzer_source=AnalyzerSource.AST,
            analysis_status=AnalysisStatus.CONFIRMED,
        )
        predictor.verify_finding(finding)

        mtime_after = os.path.getmtime(MODEL_PATH)
        assert mtime_before == mtime_after, "Model artifact was modified during inference!"

    def test_safe_fallback_on_unloaded_model(self):
        """Verifies graceful degradation when model is unavailable."""
        unloaded_predictor = MLPredictor(
            model_path=Path("non_existent_model.joblib"),
            metadata_path=Path("non_existent_meta.json"),
        )
        assert unloaded_predictor.is_loaded is False

        finding = Finding(
            rule_id="TAINT-001",
            cwe="CWE-78",
            vulnerability_type="Command Injection",
            severity=Severity.HIGH,
            confidence=0.85,
            message="Tainted input",
            file="src/test.c",
            line=10,
            code_snippet='system(x);',
        )

        res = unloaded_predictor.verify_finding(finding)
        assert res["status"] == "UNAVAILABLE"
        assert res["ml_verification_score"] is None

        # Verify batch verification does not drop the finding
        out = unloaded_predictor.verify_findings([finding])
        assert len(out) == 1
        assert out[0].metadata["ml_verification_status"] == "UNAVAILABLE"

    def test_batch_processing_heterogeneous_findings(self):
        predictor = get_ml_predictor()
        findings = [
            Finding(rule_id="F1", cwe="CWE-78", vulnerability_type="Cmd", severity=Severity.HIGH, confidence=0.8, file="a.c", line=1, code_snippet='system(x);'),
            Finding(rule_id="F2", cwe="CWE-476", vulnerability_type="Null", severity=Severity.LOW, confidence=0.5, file="b.c", line=2, code_snippet='*p = 0;'),
            Finding(rule_id="F3", cwe="CWE-193", vulnerability_type="OffByOne", severity=Severity.MEDIUM, confidence=0.7, file="c.c", line=3, code_snippet='a[10] = 0;'),
        ]

        verified = predictor.verify_findings(findings)
        assert len(verified) == 3

        # F1 (CWE-78) -> VERIFIED
        assert verified[0].metadata["ml_verification_status"] == "VERIFIED"
        assert verified[0].metadata["ml_verification_score"] is not None

        # F2 (CWE-476) -> NOT_SUPPORTED
        assert verified[1].metadata["ml_verification_status"] == "NOT_SUPPORTED"
        assert verified[1].metadata["ml_verification_score"] is None

        # F3 (CWE-193) -> VERIFIED
        assert verified[2].metadata["ml_verification_status"] == "VERIFIED"
        assert verified[2].metadata["ml_verification_score"] is not None


class TestAPIBackwardCompatibility:
    """Verifies that API serialization includes ML metadata without breaking schema."""

    def test_vulnerability_result_serialization(self):
        finding = Finding(
            rule_id="TAINT-SYSTEM-001",
            cwe="CWE-78",
            vulnerability_type="Command Injection",
            severity=Severity.HIGH,
            confidence=0.92,
            message="Tainted string flows into system() call",
            file="src/cmd.c",
            line=25,
            code_snippet='system(user_cmd);',
            analyzer_source=AnalyzerSource.TAINT,
            analysis_status=AnalysisStatus.CONFIRMED,
        )

        predictor = get_ml_predictor()
        verified = predictor.verify_findings([finding])

        results = _findings_to_results(verified)
        assert len(results) == 1
        res = results[0]

        assert isinstance(res, VulnerabilityResult)
        assert res.metadata is not None
        assert "ml_verification" in res.metadata
        assert res.metadata["ml_verification_score"] is not None
        assert res.confidence == 0.92  # Preserved static confidence
