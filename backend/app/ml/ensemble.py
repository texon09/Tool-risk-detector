"""Ensemble evaluation combining supervised tree models and anomaly detection."""

from __future__ import annotations

from typing import Any, Dict

import numpy as np

try:
    from app.ml.calibrate import apply_calibrator
except ImportError:
    from backend.app.ml.calibrate import apply_calibrator


def normalize_iso_score(
    raw_decision: float,
    min_ref: float = -0.25,
    max_ref: float = 0.15,
) -> float:
    """
    Normalize Isolation Forest anomaly score to [0, 1] risk spectrum.
    
    In scikit-learn's Isolation Forest, more negative values indicate greater anomaly
    (higher risk), whereas positive values indicate nominal / benign behavior.
    We invert and scale so that:
      - nominal (>= max_ref) -> 0.0
      - highly anomalous (<= min_ref) -> 1.0
    Clamped to [0.0, 1.0].
    """
    if max_ref == min_ref:
        return 0.0
    val = (max_ref - float(raw_decision)) / (max_ref - min_ref)
    return float(np.clip(val, 0.0, 1.0))


def risk_score(
    p_dt: float | np.ndarray,
    p_rf: float | np.ndarray,
    p_xgb: float | np.ndarray,
    iso_score: float | np.ndarray,
    weights: Dict[str, float] | None = None,
    calibrator: Any = None,
    cal_method: str = "isotonic",
) -> np.ndarray:
    """
    Compute ensemble risk score using weighted combination of all 4 models.
    
    raw = w_dt * p_dt + w_rf * p_rf + w_xgb * p_xgb + w_iso * iso_score
    """
    if weights is None:
        weights = {"dt": 0.10, "rf": 0.40, "xgb": 0.40, "iso": 0.10}

    w_dt = float(weights.get("dt", 0.10))
    w_rf = float(weights.get("rf", 0.40))
    w_xgb = float(weights.get("xgb", 0.40))
    w_iso = float(weights.get("iso", 0.10))

    raw = w_dt * p_dt + w_rf * p_rf + w_xgb * p_xgb + w_iso * iso_score

    if not isinstance(raw, np.ndarray):
        raw = np.array([raw])

    if calibrator is not None:
        return apply_calibrator(calibrator, cal_method, raw)
    return raw


# Alias per P4 task specification
score_risk = risk_score


def model_votes(p_rf: float, p_xgb: float, p_dt: float, iso_flag: Any) -> Dict[str, Any]:
    """Compatibility map for model votes and legacy interfaces."""
    return {
        "rf_prob": float(p_rf),
        "xgb_prob": float(p_xgb),
        "dt_prob": float(p_dt),
        "iso_flag": bool(iso_flag) if not isinstance(iso_flag, int) else int(iso_flag),
    }
