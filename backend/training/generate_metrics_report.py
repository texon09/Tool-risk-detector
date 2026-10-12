"""Generate per-model metrics for API and frontend display."""

import json
import os
import time

from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score

from backend.app.ml.loader import load_model
from backend.training.data import load_feature_list, load_split


def main():
    model_dir = "artifacts/models/v2"
    data_dir = "data/processed"
    metrics_dir = "artifacts/metrics"
    os.makedirs(metrics_dir, exist_ok=True)

    manifest, models = load_model(model_dir, data_dir)
    features = load_feature_list(data_dir)

    test_path = os.path.join(data_dir, "test_features.csv")
    X_ts, y_ts_str, meta_ts = load_split(test_path, features)
    y_binary = (y_ts_str == "HIGH-RISK").astype(int)

    report_models = {}

    for name, model_key in [
        ("decision_tree", "decision_tree"),
        ("random_forest", "random_forest"),
        ("xgboost", "xgboost"),
        ("isolation_forest", "isolation_forest"),
    ]:
        model = models[model_key]

        start_time = time.perf_counter()
        if model_key == "isolation_forest":
            scores = -model.decision_function(X_ts)
            iso_thresh = -float(manifest["anomaly_threshold"])
            preds = (scores >= iso_thresh).astype(int)
            prob_scores = (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
        else:
            probs = model.predict_proba(X_ts)
            prob_scores = probs[:, 2] if probs.shape[1] == 3 else probs[:, 1]
            preds = (prob_scores >= 0.5).astype(int)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0 / len(X_ts)

        f1 = float(f1_score(y_binary, preds, zero_division=0))
        prec = float(precision_score(y_binary, preds, zero_division=0))
        rec = float(recall_score(y_binary, preds, zero_division=0))
        try:
            auc = float(roc_auc_score(y_binary, prob_scores))
        except ValueError:
            auc = 0.5

        report_models[name] = {
            "f1": round(f1, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "auroc": round(auc, 4),
            "latency_ms": round(elapsed_ms, 3),
        }

    results = {
        "models": report_models,
        "test_sample_count": len(X_ts),
        "manifest_version": manifest.get("version", "v2"),
        "operating_points": manifest.get("operating_points", {}),
    }

    out_path = os.path.join(metrics_dir, "results.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("Successfully generated:", out_path)
    print(json.dumps(report_models, indent=2))


if __name__ == "__main__":
    main()
