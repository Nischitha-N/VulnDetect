"""
ML Finding-Level Verification and Triage Predictor.

Applies the trained Random Forest model to static analysis findings as an auxiliary
triage mechanism:
- Static analysis detects findings authoritatively.
- ML estimates P(True Vulnerability | Static Evidence).
- Supported CWE families: CWE-78, CWE-416, CWE-193, CWE-134.
- Unsupported CWEs receive status 'NOT_SUPPORTED' without prediction.
- Findings are NEVER deleted based on ML score.
- Model is loaded once (singleton pattern) and never retrained at runtime.
"""

import os
import sys
import json
import time
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

import numpy as np
import joblib

from app.engine.base import Finding
from app.ml.feature_extractor import (
    extract_finding_features,
    extract_batch_features,
    FEATURE_NAMES,
    N_FEATURES,
)

logger = logging.getLogger("vulndetect.ml.predictor")

MODELS_DIR = Path(__file__).parent / "models"
MODEL_PATH = MODELS_DIR / "final_model.joblib"
METADATA_PATH = MODELS_DIR / "model_metadata.json"

DEFAULT_THRESHOLD = 0.50
SUPPORTED_CWES = {"CWE-78", "CWE-416", "CWE-193", "CWE-134"}


def is_cwe_supported(cwe: Optional[str]) -> bool:
    """
    Checks if a CWE belongs to the ML training scope.
    Strictly accepts CWE-78 (not CWE-787), CWE-416, CWE-193, and CWE-134.
    """
    if not cwe:
        return False
    c = str(cwe).upper().strip()
    if "CWE-78" in c and "CWE-787" not in c:
        return True
    if "CWE-416" in c:
        return True
    if "CWE-193" in c:
        return True
    if "CWE-134" in c:
        return True
    return False


class MLPredictor:
    """
    Inference engine for auxiliary finding-level false positive triage.
    Loads trained artifact once and predicts verification probability.
    """

    def __init__(self, model_path: Path = MODEL_PATH, metadata_path: Path = METADATA_PATH):
        self.model_path = model_path
        self.metadata_path = metadata_path
        self.model = None
        self.metadata: Dict[str, Any] = {}
        self.is_loaded = False
        self.load_error: Optional[str] = None
        self._load_artifacts()

    def _load_artifacts(self):
        """Loads and verifies model binary and metadata."""
        if not self.model_path.exists():
            self.load_error = f"Model artifact not found at {self.model_path}"
            logger.warning(self.load_error)
            return

        if not self.metadata_path.exists():
            self.load_error = f"Metadata artifact not found at {self.metadata_path}"
            logger.warning(self.load_error)
            return

        try:
            with open(self.metadata_path, "r", encoding="utf-8") as f:
                self.metadata = json.load(f)

            # Verify feature alignment
            saved_features = self.metadata.get("feature_pipeline", {}).get("feature_names", [])
            if saved_features != FEATURE_NAMES:
                self.load_error = (
                    f"Feature mismatch: Model metadata features ({len(saved_features)}) "
                    f"differ from current FEATURE_NAMES ({len(FEATURE_NAMES)})."
                )
                logger.error(self.load_error)
                return

            self.model = joblib.load(self.model_path)
            self.is_loaded = True
            self.load_error = None
            logger.info("Successfully loaded ML finding verification model from %s", self.model_path)
        except Exception as e:
            self.load_error = f"Failed to load model artifacts: {str(e)}"
            self.is_loaded = False
            self.model = None
            logger.error(self.load_error, exc_info=True)

    def verify_finding(self, finding: Finding) -> Dict[str, Any]:
        """
        Calculates ML verification score for a single finding.
        Returns a dictionary suitable for finding.metadata['ml_verification'].
        """
        cwe_str = getattr(finding, "cwe", "")
        if not is_cwe_supported(cwe_str):
            return {
                "status": "NOT_SUPPORTED",
                "reason": f"CWE '{cwe_str}' outside ML triage training scope (CWE-78, 416, 193, 134)",
                "ml_verification_score": None,
                "ml_predicted_valid": None,
                "ml_model": None,
                "ml_threshold": DEFAULT_THRESHOLD,
            }

        if not self.is_loaded or self.model is None:
            return {
                "status": "UNAVAILABLE",
                "error": self.load_error or "Model not loaded",
                "ml_verification_score": None,
                "ml_predicted_valid": None,
                "ml_model": None,
                "ml_threshold": DEFAULT_THRESHOLD,
            }

        try:
            t0 = time.perf_counter()
            features = extract_finding_features(finding)
            features_2d = features.reshape(1, -1)

            # P(True Vulnerability | Static Evidence)
            probs = self.model.predict_proba(features_2d)[0]
            score = float(probs[1]) if len(probs) > 1 else float(probs[0])
            score = max(0.0, min(1.0, score))
            predicted_valid = bool(score >= DEFAULT_THRESHOLD)
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 3)

            return {
                "status": "VERIFIED",
                "ml_verification_score": round(score, 4),
                "ml_predicted_valid": predicted_valid,
                "ml_model": self.metadata.get("selected_model", "RandomForest"),
                "ml_threshold": DEFAULT_THRESHOLD,
                "latency_ms": latency_ms,
            }
        except Exception as e:
            logger.error("Error during ML verification of finding on line %s: %s", getattr(finding, "line", 0), e)
            return {
                "status": "ERROR",
                "error": str(e),
                "ml_verification_score": None,
                "ml_predicted_valid": None,
                "ml_model": None,
                "ml_threshold": DEFAULT_THRESHOLD,
            }

    def verify_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Attaches ML verification metadata to all findings in a batch.
        Guarantees:
        - Original findings are never deleted or filtered out.
        - Static confidence (finding.confidence) is never overwritten.
        - Unsupported CWEs receive 'NOT_SUPPORTED' status.
        - Error handling per finding ensures pipeline resilience.
        """
        if not findings:
            return findings

        # Batch prediction for efficiency on supported findings
        supported_indices = []
        supported_findings = []

        for i, f in enumerate(findings):
            if is_cwe_supported(getattr(f, "cwe", "")):
                supported_indices.append(i)
                supported_findings.append(f)
            else:
                cwe_val = getattr(f, "cwe", "")
                unsupported_info = {
                    "status": "NOT_SUPPORTED",
                    "reason": f"CWE '{cwe_val}' outside ML triage training scope (CWE-78, 416, 193, 134)",
                    "ml_verification_score": None,
                    "ml_predicted_valid": None,
                    "ml_model": None,
                    "ml_threshold": DEFAULT_THRESHOLD,
                }
                if not hasattr(f, "metadata") or f.metadata is None:
                    f.metadata = {}
                f.metadata["ml_verification"] = unsupported_info
                f.metadata["ml_verification_status"] = "NOT_SUPPORTED"
                f.metadata["ml_verification_score"] = None
                f.metadata["ml_predicted_valid"] = None

        if not supported_findings:
            return findings

        if not self.is_loaded or self.model is None:
            # Model unavailable: mark supported findings safely as UNAVAILABLE
            for idx in supported_indices:
                f = findings[idx]
                if not hasattr(f, "metadata") or f.metadata is None:
                    f.metadata = {}
                unavail_info = {
                    "status": "UNAVAILABLE",
                    "error": self.load_error or "Model not loaded",
                    "ml_verification_score": None,
                    "ml_predicted_valid": None,
                    "ml_model": None,
                    "ml_threshold": DEFAULT_THRESHOLD,
                }
                f.metadata["ml_verification"] = unavail_info
                f.metadata["ml_verification_status"] = "UNAVAILABLE"
                f.metadata["ml_verification_score"] = None
                f.metadata["ml_predicted_valid"] = None
            return findings

        # Extract features in batch
        try:
            t0 = time.perf_counter()
            X_batch = extract_batch_features(supported_findings)
            probs = self.model.predict_proba(X_batch)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            per_finding_ms = round(elapsed_ms / len(supported_findings), 3)

            for local_idx, global_idx in enumerate(supported_indices):
                f = findings[global_idx]
                p_row = probs[local_idx]
                score = float(p_row[1]) if len(p_row) > 1 else float(p_row[0])
                score = max(0.0, min(1.0, score))
                predicted_valid = bool(score >= DEFAULT_THRESHOLD)

                verif_info = {
                    "status": "VERIFIED",
                    "ml_verification_score": round(score, 4),
                    "ml_predicted_valid": predicted_valid,
                    "ml_model": self.metadata.get("selected_model", "RandomForest"),
                    "ml_threshold": DEFAULT_THRESHOLD,
                    "latency_ms": per_finding_ms,
                }
                if not hasattr(f, "metadata") or f.metadata is None:
                    f.metadata = {}
                f.metadata["ml_verification"] = verif_info
                f.metadata["ml_verification_score"] = round(score, 4)
                f.metadata["ml_predicted_valid"] = predicted_valid
                f.metadata["ml_verification_status"] = "VERIFIED"
                f.metadata["ml_model"] = self.metadata.get("selected_model", "RandomForest")
                f.metadata["ml_threshold"] = DEFAULT_THRESHOLD

        except Exception as e:
            logger.error("Batch ML verification error: %s", e, exc_info=True)
            # Fall back to individual evaluation if batch fails
            for global_idx in supported_indices:
                f = findings[global_idx]
                verif_info = self.verify_finding(f)
                if not hasattr(f, "metadata") or f.metadata is None:
                    f.metadata = {}
                f.metadata["ml_verification"] = verif_info
                f.metadata["ml_verification_status"] = verif_info.get("status", "ERROR")
                if verif_info.get("ml_verification_score") is not None:
                    f.metadata["ml_verification_score"] = verif_info["ml_verification_score"]
                    f.metadata["ml_predicted_valid"] = verif_info["ml_predicted_valid"]
                    f.metadata["ml_model"] = verif_info.get("ml_model")
                    f.metadata["ml_threshold"] = DEFAULT_THRESHOLD

        return findings


# Global singleton instance
_predictor_instance: Optional[MLPredictor] = None


def get_ml_predictor() -> MLPredictor:
    """Returns the cached singleton MLPredictor instance."""
    global _predictor_instance
    if _predictor_instance is None:
        _predictor_instance = MLPredictor()
    return _predictor_instance
