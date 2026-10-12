import argparse
import json
import os
import sys

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier

try:
    from backend.app.ml.calibrate import apply_calibrator
    from backend.app.ml.loader import load_model
    from backend.training.data import CLASS_ORDER, load_feature_list, load_split
    from backend.training.metrics import group_bootstrap_ci, pr_auc, threshold_at_fpr
except ImportError:
    from app.ml.calibrate import apply_calibrator
    from app.ml.loader import load_model
    from training.data import CLASS_ORDER, load_feature_list, load_split
    from training.metrics import group_bootstrap_ci, pr_auc, threshold_at_fpr



def get_class_map():
    return {k: v for v, k in enumerate(CLASS_ORDER)}


def get_dedup_mask(X_train, X_test):
    train_set = set(tuple(row) for row in X_train.values)
    mask = np.array([tuple(row) not in train_set for row in X_test.values])
    return mask


def eval_model(y_str, probs, thresh, groups):
    if len(y_str) == 0:
        return {}
    y_int = np.array([get_class_map()[v] for v in y_str])
    preds = probs.argmax(axis=1)

    p, r, f, _ = precision_recall_fscore_support(y_int, preds, labels=[0, 1, 2], zero_division=0)
    macro_f1 = float(np.mean(f))

    hr_mask = y_str == "HIGH-RISK"
    hr_scores = probs[:, 2][hr_mask]
    safe_mask = y_str == "SAFE"
    safe_scores = probs[:, 2][safe_mask]
    susp_mask = y_str == "SUSPICIOUS"
    susp_scores = probs[:, 2][susp_mask]

    hr_recall = float(np.sum(hr_scores >= thresh) / len(hr_scores)) if len(hr_scores) > 0 else 0.0
    safe_fpr = (
        float(np.sum(safe_scores >= thresh) / len(safe_scores)) if len(safe_scores) > 0 else 0.0
    )
    susp_flagged = (
        float(np.sum(susp_scores >= thresh) / len(susp_scores)) if len(susp_scores) > 0 else 0.0
    )

    prauc = pr_auc(y_str, probs[:, 2])
    cm = confusion_matrix(y_int, preds, labels=[0, 1, 2]).tolist()

    def recall_fn(y_sub, score_sub):
        h = score_sub[y_sub == "HIGH-RISK"]
        return np.sum(h >= thresh) / len(h) if len(h) > 0 else 0.0

    ci_rec = group_bootstrap_ci(recall_fn, y_str, probs[:, 2], groups, n=1000)

    def fpr_fn(y_sub, score_sub):
        s = score_sub[y_sub == "SAFE"]
        return np.sum(s >= thresh) / len(s) if len(s) > 0 else 0.0

    ci_fpr = group_bootstrap_ci(fpr_fn, y_str, probs[:, 2], groups, n=1000)

    return {
        "precision": p.tolist(),
        "recall": r.tolist(),
        "f1": f.tolist(),
        "macro_f1": macro_f1,
        "hr_pr_auc": prauc,
        "recall_at_thresh": hr_recall,
        "safe_fpr_at_thresh": safe_fpr,
        "share_suspicious_flagged": susp_flagged,
        "confusion_matrix": cm,
        "ci_95_recall": list(ci_rec),
        "ci_95_fpr": list(ci_fpr),
    }


def eval_trivial(y_str):
    if len(y_str) == 0:
        return {}
    y_int = np.array([get_class_map()[v] for v in y_str])
    preds = np.zeros_like(y_int)
    acc = accuracy_score(y_int, preds)
    _, _, f, _ = precision_recall_fscore_support(y_int, preds, labels=[0, 1, 2], zero_division=0)
    return {"accuracy": float(acc), "macro_f1": float(np.mean(f))}


def e1_routine(X, y_str, groups, models, manifest, dt_th, rf_th, xgb_th, ens_th):
    res = {}
    p_dt = models["decision_tree"].predict_proba(X)
    p_rf = models["random_forest"].predict_proba(X)
    p_xgb = models["xgboost"].predict_proba(X)

    w_rf = manifest["ensemble_weights"]["rf"]
    w_xgb = manifest["ensemble_weights"]["xgb"]
    raw = w_rf * p_rf[:, 2] + w_xgb * p_xgb[:, 2]
    cal_scores = apply_calibrator(models["calibrator"], manifest["calibration_method"], raw)

    # We only have binary scores for ensemble, fake 3-class for argmax
    p_ens = np.zeros((len(X), 3))
    p_ens[:, 0] = 1.0 - cal_scores
    p_ens[:, 2] = cal_scores

    res["DT"] = eval_model(y_str, p_dt, dt_th, groups)
    res["RF"] = eval_model(y_str, p_rf, rf_th, groups)
    res["XGB"] = eval_model(y_str, p_xgb, xgb_th, groups)
    ens_res = eval_model(y_str, p_ens, ens_th, groups)
    res["Ensemble"] = {
        "recall_at_thresh": ens_res["recall_at_thresh"],
        "safe_fpr_at_thresh": ens_res["safe_fpr_at_thresh"],
        "share_suspicious_flagged": ens_res["share_suspicious_flagged"],
        "hr_pr_auc": ens_res["hr_pr_auc"],
        "ci_95_recall": ens_res["ci_95_recall"],
        "ci_95_fpr": ens_res["ci_95_fpr"],
    }
    res["Baseline"] = eval_trivial(y_str)

    # E2 partial
    # ML only caught
    hr_mask = y_str == "HIGH-RISK"
    susp_mask = y_str == "SUSPICIOUS"
    safe_mask = y_str == "SAFE"

    np.sum(cal_scores[hr_mask] >= ens_th)
    np.sum(cal_scores[susp_mask] >= ens_th)

    iso_scores = models["isolation_forest"].decision_function(X)
    iso_thresh = manifest["anomaly_threshold"]
    anomaly_flag = iso_scores < iso_thresh

    hr_anom = np.sum((cal_scores[hr_mask] < ens_th) & anomaly_flag[hr_mask])
    susp_anom = np.sum((cal_scores[susp_mask] < ens_th) & anomaly_flag[susp_mask])

    safe_fpr_cost = (
        np.sum((cal_scores[safe_mask] < ens_th) & anomaly_flag[safe_mask]) / np.sum(safe_mask)
        if np.sum(safe_mask) > 0
        else 0.0
    )

    res["E2"] = {
        "extra_hr_caught_by_anomaly": int(hr_anom),
        "extra_susp_caught_by_anomaly": int(susp_anom),
        "safe_fpr_cost_of_anomaly": float(safe_fpr_cost),
        "rules_only": "not computed: rule engine not yet integrated",
        "hybrid": "not computed: rule engine not yet integrated",
    }

    return res


def e5_routine(X, y_str, meta, models, manifest, ens_th):
    p_rf = models["random_forest"].predict_proba(X)
    p_xgb = models["xgboost"].predict_proba(X)
    w_rf = manifest["ensemble_weights"]["rf"]
    w_xgb = manifest["ensemble_weights"]["xgb"]
    raw = w_rf * p_rf[:, 2] + w_xgb * p_xgb[:, 2]
    cal_scores = apply_calibrator(models["calibrator"], manifest["calibration_method"], raw)

    misses = []
    hr_mask = y_str == "HIGH-RISK"
    safe_mask = y_str == "SAFE"

    hr_recall = (
        float(np.sum(cal_scores[hr_mask] >= ens_th) / np.sum(hr_mask))
        if np.sum(hr_mask) > 0
        else 0.0
    )
    safe_fpr = (
        float(np.sum(cal_scores[safe_mask] >= ens_th) / np.sum(safe_mask))
        if np.sum(safe_mask) > 0
        else 0.0
    )

    for i in range(len(y_str)):
        pred_class = "HIGH-RISK" if cal_scores[i] >= ens_th else "SAFE"
        if y_str[i] == "HIGH-RISK" and pred_class == "SAFE":
            misses.append(
                {
                    "plan_id": meta["plan_id"].iloc[i],
                    "label": y_str[i],
                    "family": meta["family"].iloc[i],
                    "predicted_class": pred_class,
                    "score": float(cal_scores[i]),
                }
            )
        elif y_str[i] == "SAFE" and pred_class == "HIGH-RISK":
            misses.append(
                {
                    "plan_id": meta["plan_id"].iloc[i],
                    "label": y_str[i],
                    "family": meta["family"].iloc[i],
                    "predicted_class": pred_class,
                    "score": float(cal_scores[i]),
                }
            )

    return {"recall": hr_recall, "fpr": safe_fpr, "misses": misses}


def get_lofo_families(data_dir: str) -> list:
    import glob
    import os

    test_files = glob.glob(os.path.join(data_dir, "lofo_test_*.csv"))
    fams = [os.path.basename(f).replace("lofo_test_", "").replace(".csv", "") for f in test_files]
    if len(fams) != 5:
        raise ValueError(f"Expected 5 LOFO families, found {len(fams)}")
    return fams


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--model-dir", default="artifacts/models/v2")
    parser.add_argument("--metrics-dir", required=True)
    parser.add_argument("--figures-dir", required=True)
    parser.add_argument("--smoke-split")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--only", choices=["lofo"])
    args = parser.parse_args()

    os.makedirs(args.metrics_dir, exist_ok=True)
    os.makedirs(args.figures_dir, exist_ok=True)

    if args.only == "lofo":
        guard_file = os.path.join(args.metrics_dir, ".lofo_evaluated_v2")
        if not args.force and os.path.exists(guard_file):
            print(f"Error: {guard_file} exists. Use --force to overwrite.")
            sys.exit(1)
        res_file = os.path.join(args.metrics_dir, "results.json")
        backup = os.path.join(args.metrics_dir, "results_before_lofo_fix.json")
        import shutil

        if os.path.exists(res_file):
            shutil.copy(res_file, backup)
        with open(guard_file, "w") as f:
            f.write("ran\n")
        out_file = res_file
    else:
        out_file = os.path.join(
            args.metrics_dir,
            "smoke_val.json" if args.smoke_split == "val" else "results.json",
        )
        if not args.force and not args.smoke_split and os.path.exists(out_file):
            print(f"Error: {out_file} exists. Use --force to overwrite.")
            sys.exit(1)

    manifest, models = load_model(args.model_dir, args.data_dir)
    features = load_feature_list(args.data_dir)

    X_tr, y_tr_str, meta_tr = load_split(
        os.path.join(args.data_dir, "train_features.csv"), features
    )
    X_val, y_val_str, meta_val = load_split(
        os.path.join(args.data_dir, "val_features.csv"), features
    )

    if args.only != "lofo":
        if args.smoke_split == "val":
            test_file = "val_features.csv"
        else:
            test_file = "test_features.csv"
        X_ts, y_ts_str, meta_ts = load_split(os.path.join(args.data_dir, test_file), features)

    # Compute thresholds on VAL
    ens_th = manifest["operating_points"]["5%"]["threshold"]
    p_dt_v = models["decision_tree"].predict_proba(X_val)[:, 2]
    dt_th = threshold_at_fpr(y_val_str, p_dt_v, 0.05)
    p_rf_v = models["random_forest"].predict_proba(X_val)[:, 2]
    rf_th = threshold_at_fpr(y_val_str, p_rf_v, 0.05)
    p_xgb_v = models["xgboost"].predict_proba(X_val)[:, 2]
    xgb_th = threshold_at_fpr(y_val_str, p_xgb_v, 0.05)

    results = {}
    if args.only == "lofo":
        backup = os.path.join(args.metrics_dir, "results_before_lofo_fix.json")
        if os.path.exists(backup):
            with open(backup) as f:
                results = json.load(f)
    warnings = []

    if args.only != "lofo":
        mask = get_dedup_mask(X_tr, X_ts)
        X_ts_nr = X_ts[mask]
        y_ts_str_nr = y_ts_str[mask]
        meta_ts_nr = meta_ts[mask]
        removed = len(X_ts) - len(X_ts_nr)
        nr_counts = {c: int(np.sum(y_ts_str_nr == c)) for c in CLASS_ORDER}

        # How many removed had a train twin with different label?
        # Match vectors
        train_set_labels = {}
        for i, row in enumerate(X_tr.values):
            train_set_labels[tuple(row)] = y_tr_str[i]

        diff_label = 0
        for i, row in enumerate(X_ts.values):
            if not mask[i]:
                tup = tuple(row)
                if tup in train_set_labels and train_set_labels[tup] != y_ts_str[i]:
                    diff_label += 1

        results["dedup_info"] = {
            "removed_rows": removed,
            "remaining_class_mix": nr_counts,
            "removed_with_diff_label": diff_label,
        }

        e1_full = e1_routine(
            X_ts,
            y_ts_str,
            meta_ts["task_id"].values,
            models,
            manifest,
            dt_th,
            rf_th,
            xgb_th,
            ens_th,
        )
        e1_nr = e1_routine(
            X_ts_nr,
            y_ts_str_nr,
            meta_ts_nr["task_id"].values,
            models,
            manifest,
            dt_th,
            rf_th,
            xgb_th,
            ens_th,
        )

        results["E1"] = {"full": e1_full, "non_repeated": e1_nr}

        if (
            abs(
                e1_full["Ensemble"].get("recall_at_thresh", 0)
                - e1_nr["Ensemble"].get("recall_at_thresh", 0)
            )
            > 0.05
            or abs(e1_full["Ensemble"].get("macro_f1", 0) - e1_nr["Ensemble"].get("macro_f1", 0))
            > 0.05
        ):
            w = "TEST SCORES DEPEND ON TRAIN/TEST DUPLICATES"
            print(w)
            warnings.append(w)

        if nr_counts.get("HIGH-RISK", 0) < 50:
            w = "NON-REPEATED VIEW IS SMALL: CIs ARE UNRELIABLE"
            print(w)
            warnings.append(w)

        if (
            e1_full["Ensemble"].get("recall_at_thresh", 0) >= 0.99
            and e1_full["Ensemble"].get("safe_fpr_at_thresh", 1.0) <= 0.01
        ):
            w = "SUSPICIOUSLY PERFECT: check for label leakage or shared generator assumptions"
            print(w)
            warnings.append(w)

        if (
            e1_nr["Ensemble"].get("recall_at_thresh", 0) >= 0.99
            and e1_nr["Ensemble"].get("safe_fpr_at_thresh", 1.0) <= 0.01
        ):
            w = "SUSPICIOUSLY PERFECT: check for label leakage or shared generator assumptions"
            print(w)
            warnings.append(w)

        results["warnings"] = warnings

        results["E2"] = {"full": e1_full["E2"], "non_repeated": e1_nr["E2"]}
        del e1_full["E2"]
        del e1_nr["E2"]

    if args.force:
        results["force_used"] = True

    # E3 LOFO
    # E4 External
    # E5 Adversarial
    if args.only != "lofo":
        results["E3"] = "not computed: smoke split or skipped"
        results["E4"] = "not computed: smoke split or skipped"
        results["E5"] = "not computed: smoke split or skipped"

    if not args.smoke_split and (args.only == "lofo" or not args.only):
        # E3
        fams = get_lofo_families(args.data_dir)
        e3_res = {}
        for fam in fams:
            tr_path = os.path.join(args.data_dir, f"lofo_train_{fam}.csv")
            ts_path = os.path.join(args.data_dir, f"lofo_test_{fam}.csv")
            if not os.path.exists(tr_path) or not os.path.exists(ts_path):
                raise ValueError(f"Missing LOFO files for family {fam}")
            X_l_tr, y_l_tr_str, _ = load_split(tr_path, features)
            X_l_ts, y_l_ts_str, _ = load_split(ts_path, features)

            print(f"Encoding labels with manifest class_order: {manifest['class_order']}")
            y_l_tr_int = np.array([manifest["class_order"].index(v) for v in y_l_tr_str])
            dt = DecisionTreeClassifier(**manifest["hyperparameters"]["dt"], random_state=42)
            dt.fit(X_l_tr, y_l_tr_int)
            rf = RandomForestClassifier(**manifest["hyperparameters"]["rf"], random_state=42)
            rf.fit(X_l_tr, y_l_tr_int)
            xgb_m = XGBClassifier(**manifest["hyperparameters"]["xgb"], random_state=42)
            from sklearn.utils.class_weight import compute_sample_weight

            xgb_m.fit(
                X_l_tr, y_l_tr_int, sample_weight=compute_sample_weight("balanced", y_l_tr_int)
            )

            iso = IsolationForest(random_state=42)
            iso.fit(X_l_tr[y_l_tr_str == "SAFE"])
            s_iso = iso.decision_function(X_l_tr[y_l_tr_str == "SAFE"])
            # tie-aware threshold for iso
            l_iso_thresh = 0.0
            if len(s_iso) > 0:
                best_t = -float("inf")
                for t in np.sort(np.unique(s_iso)):
                    if np.sum(s_iso < t) / len(s_iso) <= 0.05:
                        best_t = t
                    else:
                        break
                l_iso_thresh = float(best_t) if best_t != -float("inf") else float(np.min(s_iso))

            assert list(dt.classes_) == [0, 1, 2], f"dt classes: {dt.classes_}"
            assert list(rf.classes_) == [0, 1, 2], f"rf classes: {rf.classes_}"
            hr_idx = manifest["class_order"].index("HIGH-RISK")

            p_rf_ts = rf.predict_proba(X_l_ts)[:, hr_idx]
            p_xgb_ts = xgb_m.predict_proba(X_l_ts)[:, hr_idx]
            raw = (
                manifest["ensemble_weights"]["rf"] * p_rf_ts
                + manifest["ensemble_weights"]["xgb"] * p_xgb_ts
            )
            cal_scores = apply_calibrator(models["calibrator"], manifest["calibration_method"], raw)

            pred_hr = cal_scores >= ens_th
            pred_not_safe = (
                cal_scores > manifest["operating_points"]["10%"]["threshold"]
            )  # let's use argmax not safe
            p_ens = np.zeros((len(X_l_ts), 3))
            p_ens[:, 0] = 1.0 - cal_scores
            p_ens[:, 2] = cal_scores
            pred_not_safe = p_ens.argmax(axis=1) != 0

            iso_ts = iso.decision_function(X_l_ts)
            anom = iso_ts < l_iso_thresh
            pred_ns_anom = pred_not_safe | anom

            hr_mask = y_l_ts_str == "HIGH-RISK"
            a_rec = (
                float(np.sum(pred_hr[hr_mask]) / np.sum(hr_mask)) if np.sum(hr_mask) > 0 else 0.0
            )
            b_rec = (
                float(np.sum(pred_not_safe[hr_mask]) / np.sum(hr_mask))
                if np.sum(hr_mask) > 0
                else 0.0
            )
            c_rec = (
                float(np.sum(pred_ns_anom[hr_mask]) / np.sum(hr_mask))
                if np.sum(hr_mask) > 0
                else 0.0
            )

            if a_rec < 0.5:
                w = f"LOFO transfer failure on {fam}"
                print(w)
                warnings.append(w)

            l_mask = get_dedup_mask(X_l_tr, X_l_ts)

            a_rec_nr = (
                float(np.sum(pred_hr[hr_mask & l_mask]) / np.sum(hr_mask & l_mask))
                if np.sum(hr_mask & l_mask) > 0
                else 0.0
            )
            b_rec_nr = (
                float(np.sum(pred_not_safe[hr_mask & l_mask]) / np.sum(hr_mask & l_mask))
                if np.sum(hr_mask & l_mask) > 0
                else 0.0
            )
            c_rec_nr = (
                float(np.sum(pred_ns_anom[hr_mask & l_mask]) / np.sum(hr_mask & l_mask))
                if np.sum(hr_mask & l_mask) > 0
                else 0.0
            )

            if args.only == "lofo":
                print(f"--- LOFO: {fam} ---")

                dt_preds = [manifest["class_order"][int(p)] for p in dt.predict(X_l_ts)]
                rf_preds = [manifest["class_order"][int(p)] for p in rf.predict(X_l_ts)]
                xgb_preds = [manifest["class_order"][int(p)] for p in xgb_m.predict(X_l_ts)]

                from collections import Counter

                print(f"  DT class counts: {dict(Counter(dt_preds))}")
                print(f"  RF class counts: {dict(Counter(rf_preds))}")
                print(f"  XGB class counts: {dict(Counter(xgb_preds))}")

                print(
                    f"  Ensemble (Full) - (a) HR: {a_rec:.4f}, (b) NS: {b_rec:.4f}, "
                    f"(c) NS+Anom: {c_rec:.4f}"
                )
                print(
                    f"  Ensemble (NR)   - (a) HR: {a_rec_nr:.4f}, (b) NS: {b_rec_nr:.4f}, "
                    f"(c) NS+Anom: {c_rec_nr:.4f}"
                )

                iso_tr_safe = iso.decision_function(X_l_tr[y_l_tr_str == "SAFE"])
                iso_tr_flag_rate = (
                    np.mean(iso_tr_safe < l_iso_thresh) if len(iso_tr_safe) > 0 else 0.0
                )
                iso_ts_flag_rate = np.mean(iso_ts < l_iso_thresh) if len(iso_ts) > 0 else 0.0
                print(f"  ISO flag rate on train SAFE: {iso_tr_flag_rate:.4f} (max 0.05)")
                print(f"  ISO flag rate on test: {iso_ts_flag_rate:.4f}")

            e3_res[fam] = {
                "full": {"pred_hr": a_rec, "pred_not_safe": b_rec, "pred_ns_or_anom": c_rec},
                "non_repeated": {
                    "pred_hr": a_rec_nr,
                    "pred_not_safe": b_rec_nr,
                    "pred_ns_or_anom": c_rec_nr,
                },
                "note": "FPR is not measurable",
            }
        results["E3"] = e3_res
        if args.only == "lofo":
            results["E3_note"] = "corrected after class-index bug; earlier LOFO values invalid"

    if args.only != "lofo":
        # E4 External
        e4_path = os.path.join(args.data_dir, "kaggle_external_features.csv")
        if os.path.exists(e4_path):
            X_e4, y_e4_str, _ = load_split(e4_path, features)
            e4_mask = get_dedup_mask(X_tr, X_e4)
            p_rf_e4 = models["random_forest"].predict_proba(X_e4)[:, 2]
            p_xgb_e4 = models["xgboost"].predict_proba(X_e4)[:, 2]
            cal_e4 = apply_calibrator(
                models["calibrator"],
                manifest["calibration_method"],
                manifest["ensemble_weights"]["rf"] * p_rf_e4
                + manifest["ensemble_weights"]["xgb"] * p_xgb_e4,
            )

            hr_e4 = y_e4_str == "HIGH-RISK"
            safe_e4 = y_e4_str == "SAFE"

            def get_e4_stats(mask_idx):
                hr_rec = (
                    float(np.sum(cal_e4[hr_e4 & mask_idx] >= ens_th) / np.sum(hr_e4 & mask_idx))
                    if np.sum(hr_e4 & mask_idx) > 0
                    else 0.0
                )
                s_fpr = (
                    float(np.sum(cal_e4[safe_e4 & mask_idx] >= ens_th) / np.sum(safe_e4 & mask_idx))
                    if np.sum(safe_e4 & mask_idx) > 0
                    else 0.0
                )
                return {"recall": hr_rec, "fpr": s_fpr}

            e4_res = {
                "full": get_e4_stats(np.ones(len(X_e4), dtype=bool)),
                "non_repeated": get_e4_stats(e4_mask),
            }

            # Subgroups
            nz_mask = (
                (X_e4["dest_has_ip_literal"] != 0)
                | (X_e4["sens_count_confidential"] != 0)
                | (X_e4["arg_encoded_payload_count"] != 0)
            )
            e4_res["subgroup_any_nz"] = get_e4_stats(nz_mask)
            e4_res["subgroup_all_z"] = get_e4_stats(~nz_mask)

            out_of_range = 0
            for col in features:
                min_v, max_v = X_tr[col].min(), X_tr[col].max()
                out_of_range += np.sum((X_e4[col] < min_v) | (X_e4[col] > max_v))
            e4_res["out_of_range_share"] = float(out_of_range / (len(X_e4) * len(features)))
            results["E4"] = e4_res

        # E5 Adversarial
        e5_path = os.path.join(args.data_dir, "adversarial_features.csv")
        if os.path.exists(e5_path):
            X_e5, y_e5_str, meta_e5 = load_split(e5_path, features)
            results["E5"] = e5_routine(X_e5, y_e5_str, meta_e5, models, manifest, ens_th)

        # Per-family and difficulty recall on test
        results["test_per_family"] = {}
        for fam in meta_ts["family"].unique():
            idx = meta_ts["family"] == fam
            if idx.sum() == 0 or len(X_ts[idx]) == 0:
                continue
            hr_mask = (y_ts_str == "HIGH-RISK") & idx
            p_rf_t = models["random_forest"].predict_proba(X_ts[idx])[:, 2]
            p_xgb_t = models["xgboost"].predict_proba(X_ts[idx])[:, 2]
            cal_t = apply_calibrator(
                models["calibrator"],
                manifest["calibration_method"],
                manifest["ensemble_weights"]["rf"] * p_rf_t
                + manifest["ensemble_weights"]["xgb"] * p_xgb_t,
            )

            hr_rec = (
                float(np.sum(cal_t[y_ts_str[idx] == "HIGH-RISK"] >= ens_th) / np.sum(hr_mask))
                if np.sum(hr_mask) > 0
                else 0.0
            )
            results["test_per_family"][fam] = hr_rec

        results["test_per_difficulty"] = {}
        if "difficulty" in meta_ts.columns:
            for diff in meta_ts["difficulty"].unique():
                idx = meta_ts["difficulty"] == diff
                if idx.sum() == 0 or len(X_ts[idx]) == 0:
                    continue
                hr_mask = (y_ts_str == "HIGH-RISK") & idx
                p_rf_t = models["random_forest"].predict_proba(X_ts[idx])[:, 2]
                p_xgb_t = models["xgboost"].predict_proba(X_ts[idx])[:, 2]
                cal_t = apply_calibrator(
                    models["calibrator"],
                    manifest["calibration_method"],
                    manifest["ensemble_weights"]["rf"] * p_rf_t
                    + manifest["ensemble_weights"]["xgb"] * p_xgb_t,
                )
                hr_rec = (
                    float(np.sum(cal_t[y_ts_str[idx] == "HIGH-RISK"] >= ens_th) / np.sum(hr_mask))
                    if np.sum(hr_mask) > 0
                    else 0.0
                )
                results["test_per_difficulty"][diff] = hr_rec

        # Error cases
        error_cases = []
        p_rf_ts_a = models["random_forest"].predict_proba(X_ts)[:, 2]
        p_xgb_ts_a = models["xgboost"].predict_proba(X_ts)[:, 2]
        cal_ts_a = apply_calibrator(
            models["calibrator"],
            manifest["calibration_method"],
            manifest["ensemble_weights"]["rf"] * p_rf_ts_a
            + manifest["ensemble_weights"]["xgb"] * p_xgb_ts_a,
        )

        for i in range(len(y_ts_str)):
            pred_class = "HIGH-RISK" if cal_ts_a[i] >= ens_th else "SAFE"
            if (y_ts_str[i] == "HIGH-RISK" and pred_class == "SAFE") or (
                y_ts_str[i] == "SAFE" and pred_class == "HIGH-RISK"
            ):
                error_cases.append({"plan_id": meta_ts["plan_id"].iloc[i], "category": None})
        with open(
            os.path.join(
                args.metrics_dir,
                "smoke_error_cases.json" if args.smoke_split else "error_cases.json",
            ),
            "w",
        ) as f:
            json.dump(error_cases, f, indent=2)

    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Evaluation complete. Results saved to {out_file}.")
    for w in warnings:
        print(f"WARNING: {w}")


if __name__ == "__main__":
    main()
