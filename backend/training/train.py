"""Train models."""

import argparse
import datetime
import itertools
import json
import os
import sys

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import GroupKFold
from sklearn.tree import DecisionTreeClassifier
from sklearn.utils.class_weight import compute_sample_weight

try:
    from backend.app.ml.calibrate import apply_calibrator, fit_calibrator
    from backend.app.ml.ensemble import normalize_iso_score
    from backend.training.data import CLASS_ORDER, file_sha256, load_feature_list, load_split
    from backend.training.metrics import recall_at_fpr, threshold_at_fpr
except ImportError:
    from app.ml.calibrate import apply_calibrator, fit_calibrator
    from app.ml.ensemble import normalize_iso_score
    from training.data import CLASS_ORDER, file_sha256, load_feature_list, load_split
    from training.metrics import recall_at_fpr, threshold_at_fpr


def get_class_map():
    return {k: v for v, k in enumerate(CLASS_ORDER)}


def run_grid_search(model_class, param_grid, X, y_str, groups, fit_kwargs=None, proba_idx=2):
    y = np.array([get_class_map()[v] for v in y_str])
    best_score = -1.0
    best_params = None

    keys = list(param_grid.keys())
    values = list(param_grid.values())
    combinations = [dict(zip(keys, v, strict=False)) for v in itertools.product(*values)]

    results = []

    for params in combinations:
        gkf = GroupKFold(n_splits=5)
        scores = []
        for train_idx, val_idx in gkf.split(X, y, groups=groups):
            X_tr, y_tr = X.iloc[train_idx], y[train_idx]
            X_v, _y_v = X.iloc[val_idx], y[val_idx]

            model = model_class(**params, random_state=42)
            if fit_kwargs:
                kw = {}
                if "sample_weight" in fit_kwargs:
                    kw["sample_weight"] = compute_sample_weight("balanced", y_tr)
                model.fit(X_tr, y_tr, **kw)
            else:
                model.fit(X_tr, y_tr)

            preds = model.predict_proba(X_v)[:, proba_idx]
            y_v_str = np.array(y_str)[val_idx]
            rec = recall_at_fpr(y_v_str, preds, 0.05)
            scores.append(rec)

        mean_score = np.mean(scores)
        results.append((mean_score, params))

        if mean_score > best_score:
            best_score = mean_score
            best_params = params
        elif mean_score == best_score:
            # tie break - simpler model
            def get_complexity(p):
                c = 0
                if "n_estimators" in p:
                    c += p["n_estimators"]
                if "max_depth" in p and p["max_depth"] is not None:
                    c += p["max_depth"] * 10
                return c

            if get_complexity(params) < get_complexity(best_params):
                best_params = params

    return best_params, results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default="data/processed")
    parser.add_argument("--models-dir", default="artifacts/models")
    parser.add_argument("--metrics-dir", default="artifacts/metrics")
    parser.add_argument("--version", default="v2")
    parser.add_argument("--seeds", nargs="+", type=int, default=[42, 43, 44, 45, 46])
    args = parser.parse_args()

    os.makedirs(args.models_dir, exist_ok=True)
    os.makedirs(args.metrics_dir, exist_ok=True)
    v_dir = os.path.join(args.models_dir, args.version)
    os.makedirs(v_dir, exist_ok=True)

    features = load_feature_list(args.data_dir)
    tr_path = os.path.join(args.data_dir, "train_features.csv")
    val_path = os.path.join(args.data_dir, "val_features.csv")

    X_tr, y_tr_str, meta_tr = load_split(tr_path, features)
    X_val, y_val_str, _meta_val = load_split(val_path, features)

    groups_tr = meta_tr["task_id"]

    # M1 DT
    dt_grid = {"max_depth": [3, 4, 5, 6], "class_weight": ["balanced"]}
    dt_best, dt_res = run_grid_search(
        DecisionTreeClassifier, dt_grid, X_tr, y_tr_str, groups_tr, proba_idx=2
    )

    # M2 RF
    rf_grid = {
        "n_estimators": [200, 400],
        "max_depth": [6, 8, 12, None],
        "min_samples_leaf": [1, 3],
        "class_weight": ["balanced"],
    }
    rf_best, rf_res = run_grid_search(
        RandomForestClassifier, rf_grid, X_tr, y_tr_str, groups_tr, proba_idx=2
    )

    # M3 XGB
    xgb_grid = {
        "n_estimators": [200, 400],
        "max_depth": [3, 5],
        "learning_rate": [0.05, 0.1],
        "subsample": [0.8],
        "colsample_bytree": [0.8],
        "objective": ["multi:softprob"],
        "num_class": [3],
    }
    xgb_best, xgb_res = run_grid_search(
        xgb.XGBClassifier,
        xgb_grid,
        X_tr,
        y_tr_str,
        groups_tr,
        fit_kwargs={"sample_weight": True},
        proba_idx=2,
    )

    # Store grid results
    with open(os.path.join(args.metrics_dir, "grid_search.json"), "w") as f:
        json.dump({"DT": dt_res, "RF": rf_res, "XGB": xgb_res}, f, indent=2)

    # Isolation Forest on TRAIN SAFE rows
    safe_mask = y_tr_str == "SAFE"
    X_tr_safe = X_tr[safe_mask]

    val_results = []
    ens_weights = {"rf": 0.40, "xgb": 0.40, "dt": 0.10, "iso": 0.10}

    for seed in args.seeds:
        dt = DecisionTreeClassifier(**dt_best, random_state=seed)
        y_tr_int = np.array([get_class_map()[v] for v in y_tr_str])
        dt.fit(X_tr, y_tr_int)

        rf = RandomForestClassifier(**rf_best, random_state=seed)
        rf.fit(X_tr, y_tr_int)

        xgb_m = xgb.XGBClassifier(**xgb_best, random_state=seed)
        xgb_m.fit(X_tr, y_tr_int, sample_weight=compute_sample_weight("balanced", y_tr_int))

        iso = IsolationForest(random_state=seed)
        iso.fit(X_tr_safe)

        # VAL evaluation with continuous expected-risk formula
        dt_proba = dt.predict_proba(X_val)
        rf_proba = rf.predict_proba(X_val)
        xgb_proba = xgb_m.predict_proba(X_val)
        iso_dec = iso.decision_function(X_val)

        p_dt = float(0.0) * dt_proba[:, 0] + float(0.5) * dt_proba[:, 1] + float(1.0) * dt_proba[:, 2]
        p_rf = float(0.0) * rf_proba[:, 0] + float(0.5) * rf_proba[:, 1] + float(1.0) * rf_proba[:, 2]
        p_xgb = float(0.0) * xgb_proba[:, 0] + float(0.5) * xgb_proba[:, 1] + float(1.0) * xgb_proba[:, 2]
        iso_scores = np.array([normalize_iso_score(s) for s in iso_dec])

        # Raw 4-model ensemble score
        raw = (
            ens_weights["dt"] * p_dt
            + ens_weights["rf"] * p_rf
            + ens_weights["xgb"] * p_xgb
            + ens_weights["iso"] * iso_scores
        )

        cal, method = fit_calibrator(y_val_str, raw)
        cal_scores = apply_calibrator(cal, method, raw)

        ops = {}
        for fpr_target in [0.01, 0.02, 0.05, 0.10]:
            thresh = threshold_at_fpr(y_val_str, cal_scores, fpr_target)

            safe_val_scores = cal_scores[y_val_str == "SAFE"]
            actual_fpr = (
                float(np.sum(safe_val_scores >= thresh) / len(safe_val_scores))
                if len(safe_val_scores) > 0
                else 0.0
            )

            hr_scores = cal_scores[y_val_str == "HIGH-RISK"]
            rec = float(np.sum(hr_scores >= thresh) / len(hr_scores)) if len(hr_scores) > 0 else 0.0

            susp_scores = cal_scores[y_val_str == "SUSPICIOUS"]
            susp_share = (
                float(np.sum(susp_scores >= thresh) / len(susp_scores))
                if len(susp_scores) > 0
                else 0.0
            )

            ops[f"{fpr_target * 100:.0f}%"] = {
                "threshold": thresh,
                "recall": rec,
                "suspicious_share": susp_share,
                "actual_safe_fpr": actual_fpr,
            }

        # Isolation forest anomaly threshold
        safe_iso_dec = iso_dec[y_val_str == "SAFE"]
        best_t = -float("inf")
        if len(safe_iso_dec) > 0:
            for t in np.sort(np.unique(safe_iso_dec)):
                if np.sum(safe_iso_dec < t) / len(safe_iso_dec) <= 0.05:
                    best_t = t
                else:
                    break
            iso_thresh = float(best_t) if best_t != -float("inf") else float(np.min(safe_iso_dec))
        else:
            iso_thresh = 0.0

        susp_iso = iso_dec[y_val_str == "SUSPICIOUS"]
        hr_iso = iso_dec[y_val_str == "HIGH-RISK"]

        iso_susp_det = (
            float(np.sum(susp_iso < iso_thresh) / len(susp_iso)) if len(susp_iso) > 0 else 0.0
        )
        iso_hr_det = float(np.sum(hr_iso < iso_thresh) / len(hr_iso)) if len(hr_iso) > 0 else 0.0

        val_results.append(
            {
                "seed": seed,
                "w_rf": ens_weights["rf"],
                "cal_method": method,
                "ops": ops,
                "iso_thresh": iso_thresh,
                "iso_susp_det": iso_susp_det,
                "iso_hr_det": iso_hr_det,
            }
        )

        if seed == args.seeds[0]:
            joblib.dump(dt, os.path.join(v_dir, "decision_tree.joblib"))
            joblib.dump(rf, os.path.join(v_dir, "random_forest.joblib"))
            joblib.dump(xgb_m, os.path.join(v_dir, "xgboost.joblib"))
            joblib.dump(iso, os.path.join(v_dir, "isolation_forest.joblib"))
            joblib.dump(cal, os.path.join(v_dir, "calibrator.joblib"))

            # Feature importances
            print("\n--- RF Top 15 Features ---")
            for idx in np.argsort(rf.feature_importances_)[::-1][:15]:
                print(f"{features[idx]}: {rf.feature_importances_[idx]:.4f}")
            print("\n--- XGB Top 15 Features ---")
            for idx in np.argsort(xgb_m.feature_importances_)[::-1][:15]:
                print(f"{features[idx]}: {xgb_m.feature_importances_[idx]:.4f}")

            manifest = {
                "version": args.version,
                "feature_names": features,
                "class_order": CLASS_ORDER,
                "ensemble_weights": ens_weights,
                "calibration_method": method,
                "thresholds": {
                    "t_medium": None,
                    "t_high": None,
                    "t_confirm": None,
                    "t_block": None,
                },
                "thresholds_note": "fitted later on the full hybrid pipeline",
                "operating_points": ops,
                "anomaly_threshold": iso_thresh,
                "hyperparameters": {"dt": dt_best, "rf": rf_best, "xgb": xgb_best},
                "seeds": args.seeds,
                "sha256": {
                    "train_features.csv": file_sha256(tr_path),
                    "val_features.csv": file_sha256(val_path),
                },
                "row_counts": {"train_features.csv": len(X_tr), "val_features.csv": len(X_val)},
                "test_files": "not used in training",
                "constant_feature_names": [c for c in features if X_tr[c].nunique() <= 1],
                "library_versions": {
                    "numpy": np.__version__,
                    "pandas": pd.__version__,
                    "xgboost": xgb.__version__,
                    "joblib": joblib.__version__,
                },
                "created_at": datetime.datetime.utcnow().isoformat() + "Z",
                "joblib_sha256": {},
            }
            for j in [
                "decision_tree.joblib",
                "random_forest.joblib",
                "xgboost.joblib",
                "isolation_forest.joblib",
                "calibrator.joblib",
            ]:
                manifest["joblib_sha256"][j] = file_sha256(os.path.join(v_dir, j))

            with open(os.path.join(v_dir, "manifest.json"), "w") as f:
                json.dump(manifest, f, indent=2)

            card = {
                "data_description": "Training data for risk detection.",
                "val_metrics": val_results[0],
                "limitations": (
                    "synthetic-data shared assumptions, "
                    "per-call baseline not trainable from plan-level data, "
                    "policy thresholds deferred"
                ),
            }
            with open(os.path.join(v_dir, "model_card.json"), "w") as f:
                json.dump(card, f, indent=2)

    with open(os.path.join(args.metrics_dir, "val_results.json"), "w") as f:
        json.dump(val_results, f, indent=2)

    print("\n--- Training Dataset Class Distribution ---")
    print(pd.Series(y_tr_str).value_counts())

    print("\n--- Chosen Hyperparameters ---")
    print(f"DT: {dt_best}")
    print(f"RF: {rf_best}")
    print(f"XGB: {xgb_best}")
    print(f"Ensemble weights: {ens_weights}")
    print(f"Calibration method: {val_results[0]['cal_method']}")
    print(f"Anomaly threshold: {val_results[0]['iso_thresh']}")
    print(
        f"Detection rates (iso): susp={val_results[0]['iso_susp_det']:.2%}, "
        f"hr={val_results[0]['iso_hr_det']:.2%}"
    )
    print("--- VAL metrics (mean/std) ---")
    rec_5 = [r["ops"]["5%"]["recall"] for r in val_results]
    print(f"Recall at 5% FPR: {np.mean(rec_5):.4f} ± {np.std(rec_5):.4f}")

    # Evaluate on test set
    ts_path = os.path.join(args.data_dir, "test_features.csv")
    if os.path.exists(ts_path):
        X_ts, y_ts_str, _ = load_split(ts_path, features)
        y_ts_int = np.array([get_class_map()[v] for v in y_ts_str])
        print("\n--- Test Set Class Distribution ---")
        print(pd.Series(y_ts_str).value_counts())

        for m_name, model in [("Decision Tree", dt), ("Random Forest", rf), ("XGBoost", xgb_m)]:
            preds_int = model.predict(X_ts)
            preds_str = [CLASS_ORDER[i] for i in preds_int]
            print(f"\n--- {m_name} Test Classification Report ---")
            print(classification_report(y_ts_str, preds_str, labels=CLASS_ORDER, zero_division=0))
            print(f"--- {m_name} Test Confusion Matrix ---")
            cm = confusion_matrix(y_ts_str, preds_str, labels=CLASS_ORDER)
            print(pd.DataFrame(cm, index=[f"True_{c}" for c in CLASS_ORDER], columns=[f"Pred_{c}" for c in CLASS_ORDER]))

    print("\n--- Model Artifacts Saved to", v_dir, "---")
    for fname in os.listdir(v_dir):
        print(f"  {fname}: {os.path.getsize(os.path.join(v_dir, fname))} bytes")


if __name__ == "__main__":
    main()
