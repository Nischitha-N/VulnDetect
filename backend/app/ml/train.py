"""
Training and Evaluation Pipeline for VulnDetect ML Finding Triage.

Compares Random Forest and XGBoost (or GradientBoosting fallback):
- Partitioning: 32 train, 12 val, 12 test (grouped, zero group leakage).
- Features: 12-dimensional numerical vector extracted from Finding / evidence metadata.
- Preprocessing: No StandardScaler (tree-based models do not require scaling).
- Selection: Selected strictly on validation F1 score (no test data used for selection).
- Evaluation: Comprehensive metrics (Accuracy, Precision, Recall, F1, ROC-AUC, Brier score).
- Artifacts: Saves selected model to backend/app/ml/models/final_model.joblib and
  metadata to backend/app/ml/models/model_metadata.json.
- Transparency: Both models evaluated on test for publication reporting.
"""

import os
import sys
import json
import datetime
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    brier_score_loss,
    confusion_matrix,
)

# Optional XGBoost import with graceful fallback to GradientBoostingClassifier
try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    from sklearn.ensemble import GradientBoostingClassifier
    HAS_XGBOOST = False

from app.ml.dataset.split import load_dataset, get_grouped_split
from app.ml.feature_extractor import (
    extract_batch_features,
    FEATURE_NAMES,
    N_FEATURES,
)


MODELS_DIR = Path(__file__).parent / "models"


def prepare_datasets(seed: int = 42) -> Tuple[Dict[str, np.ndarray], Dict[str, np.ndarray], Dict[str, Any]]:
    """
    Loads dataset, partitions deterministically by group, extracts features and labels.
    Returns:
        X_dict: {"train": X_train, "val": X_val, "test": X_test}
        y_dict: {"train": y_train, "val": y_val, "test": y_test}
        splits_raw: {"train": samples, "val": samples, "test": samples}
    """
    samples = load_dataset()
    splits = get_grouped_split(samples, seed=seed)

    X_dict = {}
    y_dict = {}

    for split_name in ["train", "val", "test"]:
        part_samples = splits[split_name]
        X_dict[split_name] = extract_batch_features(part_samples)
        y_dict[split_name] = np.array([s["label"] for s in part_samples], dtype=np.int32)

    return X_dict, y_dict, splits


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray) -> Dict[str, Any]:
    """Computes comprehensive binary classification metrics."""
    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))

    try:
        auc = float(roc_auc_score(y_true, y_prob))
    except Exception:
        auc = 0.5

    brier = float(brier_score_loss(y_true, y_prob))
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    return {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "roc_auc": round(auc, 4),
        "brier_score": round(brier, 4),
        "confusion_matrix": {
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
        },
    }


def instantiate_candidates(seed: int = 42) -> Dict[str, Any]:
    """
    Instantiates candidate classifiers with research-specified hyperparameters.
    No StandardScaler is applied.
    """
    # Candidate 1: Random Forest
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=5,
        min_samples_split=3,
        class_weight="balanced",
        random_state=seed,
    )

    # Candidate 2: XGBoost or GradientBoostingClassifier fallback
    if HAS_XGBOOST:
        gbm = XGBClassifier(
            n_estimators=100,
            max_depth=3,
            learning_rate=0.05,
            subsample=0.8,
            random_state=seed,
            eval_metric="logloss",
        )
    else:
        gbm = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=3,
            learning_rate=0.05,
            subsample=0.8,
            random_state=seed,
        )

    gbm_name = "XGBoost" if HAS_XGBOOST else "GradientBoosting"

    return {
        "RandomForest": {
            "model": rf,
            "type": "RandomForestClassifier",
            "params": {
                "n_estimators": 100,
                "max_depth": 5,
                "min_samples_split": 3,
                "class_weight": "balanced",
                "random_state": seed,
            },
        },
        gbm_name: {
            "model": gbm,
            "type": type(gbm).__name__,
            "params": {
                "n_estimators": 100,
                "max_depth": 3,
                "learning_rate": 0.05,
                "subsample": 0.8,
                "random_state": seed,
                **({"eval_metric": "logloss"} if HAS_XGBOOST else {}),
            },
        },
    }


def perform_leakage_check(
    X_dict: Dict[str, np.ndarray],
    y_dict: Dict[str, np.ndarray],
    splits_raw: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Audits for potential dataset or feature leakage:
    1. Cross-partition duplicate feature vectors.
    2. Single-feature separation / extreme correlation with label in training set.
    3. Feature distributions across positive vs negative training samples.
    """
    X_tr = X_dict["train"]
    y_tr = y_dict["train"]

    # 1. Cross-split identical feature vectors (feature collisions)
    duplicate_cross_splits = []
    for split_a, split_b in [("train", "val"), ("train", "test"), ("val", "test")]:
        Xa, Xb = X_dict[split_a], X_dict[split_b]
        for i, row_a in enumerate(Xa):
            for j, row_b in enumerate(Xb):
                if np.allclose(row_a, row_b, atol=1e-5):
                    duplicate_cross_splits.append({
                        "pair": f"{split_a}[{i}] vs {split_b}[{j}]",
                        "split_a_sample": splits_raw[split_a][i]["sample_id"],
                        "split_b_sample": splits_raw[split_b][j]["sample_id"],
                        "same_label": bool(y_dict[split_a][i] == y_dict[split_b][j]),
                    })

    # 2. Single-feature predictive power / AUC on training set
    feature_correlations = {}
    perfect_separators = []

    for idx, fname in enumerate(FEATURE_NAMES):
        col = X_tr[:, idx]
        pos_vals = col[y_tr == 1]
        neg_vals = col[y_tr == 0]

        pos_mean = float(np.mean(pos_vals)) if len(pos_vals) > 0 else 0.0
        neg_mean = float(np.mean(neg_vals)) if len(neg_vals) > 0 else 0.0
        pos_std = float(np.std(pos_vals)) if len(pos_vals) > 0 else 0.0
        neg_std = float(np.std(neg_vals)) if len(neg_vals) > 0 else 0.0

        col_std = np.std(col)
        if col_std > 1e-6:
            corr = float(np.corrcoef(col, y_tr)[0, 1])
        else:
            corr = 0.0

        # Check for perfect single-feature separation
        try:
            feat_auc = float(roc_auc_score(y_tr, col))
            if feat_auc < 0.5:
                feat_auc = 1.0 - feat_auc
        except Exception:
            feat_auc = 0.5

        if feat_auc >= 0.99 or abs(corr) >= 0.95:
            perfect_separators.append(fname)

        feature_correlations[fname] = {
            "pos_mean": round(pos_mean, 4),
            "pos_std": round(pos_std, 4),
            "neg_mean": round(neg_mean, 4),
            "neg_std": round(neg_std, 4),
            "correlation_with_label": round(corr, 4),
            "univariate_auc": round(feat_auc, 4),
        }

    # Group leakage is verified at dataset partition time (0 group overlap)
    has_leakage = len(perfect_separators) > 0

    return {
        "group_leakage_count": 0,
        "cross_split_feature_collision_count": len(duplicate_cross_splits),
        "cross_split_feature_collisions": duplicate_cross_splits,
        "perfect_separating_features": perfect_separators,
        "feature_univariate_stats": feature_correlations,
        "verdict": "LEAKAGE_DETECTED" if has_leakage else "CLEAN_NO_LEAKAGE",
    }


def train_and_evaluate(
    seed: int = 42,
    save_artifacts: bool = True,
    output_dir: Path = MODELS_DIR,
) -> Dict[str, Any]:
    """
    Executes the full train -> validate -> select -> test pipeline.
    """
    X_dict, y_dict, splits_raw = prepare_datasets(seed=seed)
    candidates = instantiate_candidates(seed=seed)

    leakage_audit = perform_leakage_check(X_dict, y_dict, splits_raw)

    eval_results = {}
    best_candidate_name = None
    best_val_f1 = -1.0
    best_val_auc = -1.0

    # 1. Train on Train set (32 samples) and evaluate on Validation set (12 samples)
    for name, cinfo in candidates.items():
        model = cinfo["model"]
        model.fit(X_dict["train"], y_dict["train"])

        # Train metrics
        train_pred = model.predict(X_dict["train"])
        train_prob = model.predict_proba(X_dict["train"])[:, 1]
        train_metrics = compute_metrics(y_dict["train"], train_pred, train_prob)

        # Validation metrics (USED FOR SELECTION)
        val_pred = model.predict(X_dict["val"])
        val_prob = model.predict_proba(X_dict["val"])[:, 1]
        val_metrics = compute_metrics(y_dict["val"], val_pred, val_prob)

        # Feature importances
        importances = {
            fname: round(float(imp), 4)
            for fname, imp in zip(FEATURE_NAMES, model.feature_importances_)
        }
        sorted_importances = dict(sorted(importances.items(), key=lambda kv: kv[1], reverse=True))

        eval_results[name] = {
            "model_type": cinfo["type"],
            "params": cinfo["params"],
            "train_metrics": train_metrics,
            "val_metrics": val_metrics,
            "feature_importances": sorted_importances,
            "model_obj": model,
        }

        # Model selection logic based solely on Validation set
        val_f1 = val_metrics["f1"]
        val_auc = val_metrics["roc_auc"]

        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            best_val_auc = val_auc
            best_candidate_name = name
        elif abs(val_f1 - best_val_f1) < 1e-5:
            # Tie breaker: ROC-AUC, then prefer RandomForest
            if val_auc > best_val_auc:
                best_val_auc = val_auc
                best_candidate_name = name
            elif name == "RandomForest":
                best_candidate_name = name

    # 2. Evaluate held-out Test set (12 samples)
    # Both models evaluated on test for transparency, but selection was locked in step 1
    for name, res in eval_results.items():
        model = res["model_obj"]
        test_pred = model.predict(X_dict["test"])
        test_prob = model.predict_proba(X_dict["test"])[:, 1]
        res["test_metrics"] = compute_metrics(y_dict["test"], test_pred, test_prob)

    selected_info = eval_results[best_candidate_name]
    selected_model = selected_info["model_obj"]

    # 3. Package metadata and artifacts
    metadata = {
        "selected_model": best_candidate_name,
        "model_type": selected_info["model_type"],
        "hyperparameters": selected_info["params"],
        "dataset_summary": {
            "total_samples": 56,
            "train_samples": len(y_dict["train"]),
            "validation_samples": len(y_dict["val"]),
            "test_samples": len(y_dict["test"]),
            "train_class_balance": {
                "positive": int(np.sum(y_dict["train"] == 1)),
                "negative": int(np.sum(y_dict["train"] == 0)),
            },
            "val_class_balance": {
                "positive": int(np.sum(y_dict["val"] == 1)),
                "negative": int(np.sum(y_dict["val"] == 0)),
            },
            "test_class_balance": {
                "positive": int(np.sum(y_dict["test"] == 1)),
                "negative": int(np.sum(y_dict["test"] == 0)),
            },
            "group_leakage": "ZERO (enforced by grouped partition)",
            "random_seed": seed,
            "benchmark_manifest_excluded": True,
        },
        "feature_pipeline": {
            "n_features": N_FEATURES,
            "feature_names": FEATURE_NAMES,
            "scaling": "None (Tree-based models consume unscaled continuous/binary features)",
        },
        "selected_model_metrics": {
            "train": selected_info["train_metrics"],
            "validation": selected_info["val_metrics"],
            "test": selected_info["test_metrics"],
        },
        "feature_importances": selected_info["feature_importances"],
        "all_candidates_comparison": {
            cname: {
                "model_type": cdata["model_type"],
                "train": cdata["train_metrics"],
                "validation": cdata["val_metrics"],
                "test": cdata["test_metrics"],
                "feature_importances": cdata["feature_importances"],
            }
            for cname, cdata in eval_results.items()
        },
        "leakage_audit": {
            "verdict": leakage_audit["verdict"],
            "group_leakage_count": leakage_audit["group_leakage_count"],
            "cross_split_feature_collision_count": leakage_audit["cross_split_feature_collision_count"],
            "perfect_separating_features": leakage_audit["perfect_separating_features"],
        },
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "limitations_and_ethics": (
            "Small dataset (N=56). The model is designed solely as an auxiliary finding-level triage "
            "prioritizer, not a primary detector. Results should not be claimed as statistically significant "
            "generalization to arbitrary unseen software without larger-scale corpus evaluation."
        ),
    }

    if save_artifacts:
        output_dir.mkdir(parents=True, exist_ok=True)
        model_path = output_dir / "final_model.joblib"
        metadata_path = output_dir / "model_metadata.json"

        joblib.dump(selected_model, model_path)
        with open(metadata_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

    return {
        "selected_model_name": best_candidate_name,
        "selected_model": selected_model,
        "metadata": metadata,
        "eval_results": eval_results,
        "leakage_audit": leakage_audit,
    }


def print_training_summary(run_result: Dict[str, Any]):
    """Pretty prints the training and evaluation results for CLI or review."""
    meta = run_result["metadata"]
    selected = meta["selected_model"]
    results = meta["all_candidates_comparison"]

    print("=" * 72)
    print("      VulnDetect ML Finding Triage — Model Training & Evaluation")
    print("=" * 72)
    print(f"Dataset: N={meta['dataset_summary']['total_samples']} samples "
          f"({meta['dataset_summary']['train_samples']} train, "
          f"{meta['dataset_summary']['validation_samples']} val, "
          f"{meta['dataset_summary']['test_samples']} test)")
    print(f"Feature count: {meta['feature_pipeline']['n_features']} numerical features")
    print(f"Benchmark quarantine: {meta['dataset_summary']['benchmark_manifest_excluded']}")
    print(f"Leakage status: {meta['leakage_audit']['verdict']}")
    print("-" * 72)

    print("\nCandidate Performance Comparison:")
    header = f"{'Candidate':<20} | {'Split':<5} | {'Acc':<6} | {'Prec':<6} | {'Rec':<6} | {'F1':<6} | {'AUC':<6} | {'Brier':<6}"
    print(header)
    print("-" * len(header))

    for cname, cdata in results.items():
        for split in ["train", "validation", "test"]:
            m = cdata[split]
            star = " *" if (cname == selected and split == "validation") else "  "
            print(f"{cname + star:<20} | {split[:4]:<5} | {m['accuracy']:<6.4f} | {m['precision']:<6.4f} | "
                  f"{m['recall']:<6.4f} | {m['f1']:<6.4f} | {m['roc_auc']:<6.4f} | {m['brier_score']:<6.4f}")
        print("-" * len(header))

    print(f"\n>>> Selected Model: {selected} (Selected on Validation F1: {results[selected]['validation']['f1']:.4f})")
    print(f"    Held-out Test F1: {results[selected]['test']['f1']:.4f} | "
          f"Test Acc: {results[selected]['test']['accuracy']:.4f} | "
          f"Test AUC: {results[selected]['test']['roc_auc']:.4f}")

    print("\nFeature Importances (Top 6 for Selected Model):")
    imps = meta["feature_importances"]
    for i, (fname, val) in enumerate(list(imps.items())[:6], 1):
        print(f"  {i}. {fname:<26}: {val:.4f}")

    print("\nLeakage Audit Details:")
    print(f"  Group leakage count:           {meta['leakage_audit']['group_leakage_count']}")
    print(f"  Feature representation collisions: {meta['leakage_audit']['cross_split_feature_collision_count']}")
    print(f"  Perfect separating features:   {meta['leakage_audit']['perfect_separating_features'] or 'None'}")
    print("=" * 72)


if __name__ == "__main__":
    result = train_and_evaluate(seed=42, save_artifacts=True)
    print_training_summary(result)
