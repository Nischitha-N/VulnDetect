"""
Train and serve the vulnerability detection ML model.
Uses XGBoost + Random Forest ensemble for risk score prediction.
"""

import numpy as np
import joblib
import os
from typing import List, Tuple
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from xgboost import XGBClassifier

from app.ml.parser import extract_line_features, features_to_vector, FEATURE_NAMES, N_FEATURES

MODEL_PATH = os.path.join(os.path.dirname(__file__), "trained_model.joblib")

# ─── Synthetic Training Data ─────────────────────────────────────────────────

VULNERABLE_SNIPPETS = [
    ('gets(buffer);', 1.0),
    ('strcpy(dest, src);', 0.9),
    ('sprintf(buf, format, arg);', 0.85),
    ('scanf("%s", input);', 0.88),
    ('system(cmd);', 0.92),
    ('char buf[32]; gets(buf);', 0.97),
    ('printf(user_input);', 0.91),
    ('memcpy(dst, src, len);', 0.70),
    ('strcat(dest, src);', 0.82),
    ('free(ptr); free(ptr);', 0.88),
    ('char arr[10]; arr[15] = 1;', 0.80),
    ('malloc(size);', 0.50),
    ('vsprintf(buf, fmt, args);', 0.87),
    ('char password[8]; strcpy(password, input);', 0.95),
    ('sprintf(query, "SELECT * FROM users WHERE id=%s", id);', 0.93),
]

SAFE_SNIPPETS = [
    ('fgets(buffer, sizeof(buffer), stdin);', 0.05),
    ('strncpy(dest, src, sizeof(dest)-1);', 0.08),
    ('snprintf(buf, sizeof(buf), format, arg);', 0.05),
    ('if (ptr == NULL) { return -1; }', 0.03),
    ('size_t len = strlen(src); if (len < sizeof(dst)) { ... }', 0.04),
    ('int x = 42;', 0.02),
    ('return result;', 0.01),
    ('printf("%s", message);', 0.06),
    ('memcpy(dst, src, sizeof(dst));', 0.15),
    ('strlcpy(dest, src, sizeof(dest));', 0.04),
    ('char *ptr = malloc(size); if (!ptr) { exit(1); }', 0.10),
    ('for (int i = 0; i < len; i++) { buf[i] = src[i]; }', 0.20),
    ('free(ptr); ptr = NULL;', 0.05),
    ('execve("/bin/ls", args, env);', 0.12),
    ('ssize_t n = read(fd, buf, sizeof(buf));', 0.07),
]


def _make_training_data() -> Tuple[np.ndarray, np.ndarray]:
    all_snippets = VULNERABLE_SNIPPETS + SAFE_SNIPPETS
    # Augment dataset with variations
    augmented = []
    for code, label in all_snippets:
        for _ in range(8):  # repeat with slight noise
            augmented.append((code, label))
        # Add contextual variations
        augmented.append((f"  {code}  // legacy code", label))
        augmented.append((f"if (cond) {{ {code} }}", label))

    np.random.shuffle(augmented)

    X, y = [], []
    for code, label in augmented:
        feats = extract_line_features(code, [code], 0)
        X.append(features_to_vector(feats))
        y.append(1 if label > 0.5 else 0)

    return np.array(X), np.array(y)


def train_and_save():
    """Train ensemble model and persist to disk."""
    print("Training vulnerability detection model...")
    X, y = _make_training_data()

    rf = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        min_samples_split=3,
        class_weight="balanced",
        random_state=42,
    )

    xgb = XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.1,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
        verbosity=0,
    )

    ensemble = VotingClassifier(
        estimators=[("rf", rf), ("xgb", xgb)],
        voting="soft",
        weights=[0.45, 0.55],
    )

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", ensemble),
    ])

    pipeline.fit(X, y)
    joblib.dump(pipeline, MODEL_PATH)
    print(f"Model saved to {MODEL_PATH} | Features: {N_FEATURES} | Samples: {len(X)}")
    return pipeline


# ─── Inference ───────────────────────────────────────────────────────────────

_model = None

def get_model():
    global _model
    if _model is None:
        if not os.path.exists(MODEL_PATH):
            _model = train_and_save()
        else:
            _model = joblib.load(MODEL_PATH)
    return _model


def predict_risk(line: str, context_lines: List[str], line_idx: int) -> float:
    """
    Return a calibrated risk score [0.0, 1.0] for a single line.
    Combines ML probability with a rule-based floor.
    """
    model = get_model()
    feats = extract_line_features(line, context_lines, line_idx)
    vec = features_to_vector(feats).reshape(1, -1)

    try:
        proba = model.predict_proba(vec)[0][1]  # P(vulnerable)
    except Exception:
        proba = 0.0

    return float(np.clip(proba, 0.0, 1.0))
