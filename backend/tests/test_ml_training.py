"""
Unit and Integration Tests for VulnDetect ML Model Training and Evaluation Pipeline.

Verifies:
- Data preparation matrix shapes and exact class balance across train/val/test splits.
- Candidate classifier instantiation with research hyperparameters.
- Model training, probability bounds, and validation-based model selection.
- Leakage audit integrity (zero group leakage, no trivial single-feature shortcuts).
- Persistence and valid schema of final model and metadata artifacts.
- End-to-end finding triage scoring from Finding object to ML risk probability.
"""

import json
import os
import sys
from pathlib import Path
import numpy as np
import pytest
import joblib

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.ml.train import (
    prepare_datasets,
    instantiate_candidates,
    train_and_evaluate,
    perform_leakage_check,
    compute_metrics,
    MODELS_DIR,
)
from app.ml.feature_extractor import (
    extract_finding_features,
    FEATURE_NAMES,
    N_FEATURES,
)
from app.engine.base import Finding, Severity, AnalyzerSource, AnalysisStatus


class TestMLTrainingDataPreparation:
    """Verifies matrix dimensions and partitions."""

    def test_matrix_shapes_and_balance(self):
        X_dict, y_dict, splits = prepare_datasets(seed=42)

        assert X_dict["train"].shape == (32, 12)
        assert X_dict["val"].shape == (12, 12)
        assert X_dict["test"].shape == (12, 12)

        assert y_dict["train"].shape == (32,)
        assert y_dict["val"].shape == (12,)
        assert y_dict["test"].shape == (12,)

        assert int(np.sum(y_dict["train"] == 1)) == 16
        assert int(np.sum(y_dict["train"] == 0)) == 16
        assert int(np.sum(y_dict["val"] == 1)) == 6
        assert int(np.sum(y_dict["val"] == 0)) == 6
        assert int(np.sum(y_dict["test"] == 1)) == 6
        assert int(np.sum(y_dict["test"] == 0)) == 6


class TestMLModelCandidates:
    """Verifies model instantiation and hyperparameter constraints."""

    def test_candidates_instantiation(self):
        candidates = instantiate_candidates(seed=42)
        assert "RandomForest" in candidates
        assert ("GradientBoosting" in candidates or "XGBoost" in candidates)

        rf = candidates["RandomForest"]
        assert rf["params"]["n_estimators"] == 100
        assert rf["params"]["max_depth"] == 5
        assert rf["params"]["min_samples_split"] == 3
        assert rf["params"]["class_weight"] == "balanced"
        assert rf["params"]["random_state"] == 42


class TestMLTrainingPipeline:
    """Verifies model training, selection, and leakage audit."""

    def test_train_and_evaluate_selection(self):
        res = train_and_evaluate(seed=42, save_artifacts=False)

        assert res["selected_model_name"] in ["RandomForest", "GradientBoosting", "XGBoost"]
        selected_model = res["selected_model"]
        assert hasattr(selected_model, "predict")
        assert hasattr(selected_model, "predict_proba")

        val_metrics = res["eval_results"][res["selected_model_name"]]["val_metrics"]
        assert 0.0 <= val_metrics["f1"] <= 1.0
        assert 0.0 <= val_metrics["accuracy"] <= 1.0

    def test_probability_distribution(self):
        res = train_and_evaluate(seed=42, save_artifacts=False)
        model = res["selected_model"]
        X_dict, _, _ = prepare_datasets(seed=42)

        for split in ["train", "val", "test"]:
            probs = model.predict_proba(X_dict[split])
            assert probs.shape == (len(X_dict[split]), 2)
            assert np.all((probs >= 0.0) & (probs <= 1.0))
            np.testing.assert_allclose(np.sum(probs, axis=1), 1.0, atol=1e-5)

    def test_leakage_audit_cleanliness(self):
        X_dict, y_dict, splits = prepare_datasets(seed=42)
        audit = perform_leakage_check(X_dict, y_dict, splits)

        assert audit["verdict"] == "CLEAN_NO_LEAKAGE"
        assert audit["group_leakage_count"] == 0
        assert len(audit["perfect_separating_features"]) == 0


class TestMLArtifactIntegrity:
    """Verifies persistence, artifact formats, and metadata schemas."""

    def test_saved_model_and_metadata(self):
        # Ensure artifacts are generated
        train_and_evaluate(seed=42, save_artifacts=True)

        model_path = MODELS_DIR / "final_model.joblib"
        metadata_path = MODELS_DIR / "model_metadata.json"

        assert model_path.exists(), f"Missing {model_path}"
        assert metadata_path.exists(), f"Missing {metadata_path}"

        loaded_model = joblib.load(model_path)
        assert hasattr(loaded_model, "predict_proba")

        with open(metadata_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        assert meta["selected_model"] in ["RandomForest", "GradientBoosting", "XGBoost"]
        assert meta["dataset_summary"]["total_samples"] == 56
        assert meta["dataset_summary"]["benchmark_manifest_excluded"] is True
        assert len(meta["feature_pipeline"]["feature_names"]) == 12
        assert "validation" in meta["selected_model_metrics"]
        assert "test" in meta["selected_model_metrics"]
        assert meta["leakage_audit"]["verdict"] == "CLEAN_NO_LEAKAGE"

    def test_end_to_end_finding_scoring(self):
        model_path = MODELS_DIR / "final_model.joblib"
        loaded_model = joblib.load(model_path)

        dummy_finding = Finding(
            rule_id="TAINT-SYSTEM-001",
            cwe="CWE-78",
            vulnerability_type="Command Injection",
            severity=Severity.HIGH,
            confidence=0.9,
            message="Tainted string flows into system() call",
            file="src/cmd.c",
            line=25,
            code_snippet='system(user_cmd);',
            analyzer_source=AnalyzerSource.TAINT,
            analysis_status=AnalysisStatus.CONFIRMED,
        )

        features = extract_finding_features(dummy_finding)
        assert features.shape == (12,)

        prob = loaded_model.predict_proba(features.reshape(1, -1))[0, 1]
        assert 0.0 <= prob <= 1.0
