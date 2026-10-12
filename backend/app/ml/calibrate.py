"""Calibrator."""

import numpy as np
from sklearn.linear_model import LogisticRegression


def fit_calibrator(y_val, raw_scores):
    """
    Fit Platt scaling calibrator using Logistic Regression.
    
    Transforms raw ensemble risk scores into smooth, monotonic calibrated probabilities
    spanning the [0, 1] interval without step-function dead zones.
    """
    # Binary risk label: 0 for SAFE, 1 for non-safe (SUSPICIOUS or HIGH-RISK)
    # If y_val is already binary (0/1), use directly; if string labels, map SAFE->0, non-SAFE->1
    if isinstance(y_val, (list, np.ndarray)) and len(y_val) > 0 and isinstance(y_val[0], str):
        y_binary = (np.array(y_val) != "SAFE").astype(int)
    elif hasattr(y_val, "iloc") and isinstance(y_val.iloc[0], str):
        y_binary = (y_val != "SAFE").astype(int).values
    else:
        y_binary = np.array(y_val).astype(int)

    method = "platt"
    cal = LogisticRegression(C=2.5, random_state=42)
    cal.fit(raw_scores.reshape(-1, 1), y_binary)
    return cal, method


def apply_calibrator(calibrator, method, raw_scores):
    """Apply fitted calibrator to raw risk score array."""
    if not isinstance(raw_scores, np.ndarray):
        raw_scores = np.array([raw_scores], dtype=float)
    if method == "isotonic":
        return calibrator.predict(raw_scores.reshape(-1, 1))
    else:  # platt / logistic
        if hasattr(calibrator, "__dict__") and "multi_class" not in calibrator.__dict__:
            calibrator.__dict__["multi_class"] = "auto"
        return calibrator.predict_proba(raw_scores.reshape(-1, 1))[:, 1]


