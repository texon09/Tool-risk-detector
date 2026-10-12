"""Dataset validator."""

import argparse
import json
import os
import sys

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score
from sklearn.tree import DecisionTreeClassifier

try:
    from backend.training.data import CLASS_ORDER, load_feature_list
except ImportError:
    from training.data import CLASS_ORDER, load_feature_list


FAMILIES = [
    "data_exfiltration",
    "credential_harvesting",
    "privilege_escalation",
    "destructive",
    "injection_triggered",
    "read_and_exfil",
]


def hard_assert(cond, msg):
    if not cond:
        print(f"FAIL: {msg}")
        sys.exit(1)


def validate(data_dir: str):
    print("Running Dataset Validator...")
    features = load_feature_list(data_dir)
    hard_assert(
        len(features) == 38 and len(set(features)) == 38,
        "feature_list.json must have exactly 38 unique features.",
    )

    def check_cols(df, fname):
        df_cols = list(df.columns)
        hard_assert(df_cols[: len(features)] == features, f"Features order mismatch in {fname}")
        meta_cols = ["label", "family", "difficulty", "plan_id", "task_id"]
        for m in meta_cols:
            hard_assert(m in df_cols, f"Missing meta col {m} in {fname}")

    splits_expected = {
        "train_features.csv": (3835, {"SAFE": 2430, "SUSPICIOUS": 333, "HIGH-RISK": 1072}),
        "val_features.csv": (567, {"SAFE": 371, "SUSPICIOUS": 59, "HIGH-RISK": 137}),
        "test_features.csv": (1098, {"SAFE": 699, "SUSPICIOUS": 108, "HIGH-RISK": 291}),
    }

    tasks = {}
    plan_ids = {}

    dfs = {}
    for fname, (expected_rows, expected_labels) in splits_expected.items():
        path = os.path.join(data_dir, fname)
        df = pd.read_csv(path)
        dfs[fname] = df

        check_cols(df, fname)

        X = df[features]
        hard_assert(
            not X.isna().any().any() and not np.isinf(X.values.astype(float)).any(),
            f"NaN/inf in {fname}",
        )
        hard_assert(set(df["label"].unique()).issubset(CLASS_ORDER), f"Invalid label in {fname}")

        hard_assert(
            len(df) == expected_rows, f"{fname} row count mismatch: {len(df)} != {expected_rows}"
        )
        label_counts = df["label"].value_counts().to_dict()
        for k, v in expected_labels.items():
            hard_assert(label_counts.get(k, 0) == v, f"{fname} label count mismatch for {k}")

        hr_mask = df["label"] == "HIGH-RISK"
        hard_assert(
            df.loc[~hr_mask, "family"].isna().all(),
            f"family must be blank for non HIGH-RISK in {fname}",
        )
        hard_assert(
            df.loc[hr_mask, "family"].isin(FAMILIES).all(),
            f"family must be valid for HIGH-RISK in {fname}",
        )

        diff_mask = df["difficulty"].notna()
        hard_assert(
            df.loc[diff_mask, "difficulty"].isin(["easy", "medium", "hard"]).all(),
            f"Invalid difficulty in {fname}",
        )
        # report blanks
        blanks = (~diff_mask).sum()
        if blanks > 0:
            print(f"INFO: {blanks} blank difficulties in {fname}")

        hard_assert(df["plan_id"].nunique() == len(df), f"Duplicate plan_ids in {fname}")

        split_name = fname.split("_")[0]
        tasks[split_name] = set(df["task_id"].unique())
        plan_ids[split_name] = set(df["plan_id"].unique())

    for s1 in ["train", "val", "test"]:
        for s2 in ["train", "val", "test"]:
            if s1 < s2:
                hard_assert(len(tasks[s1].intersection(tasks[s2])) == 0, f"Task overlap {s1} {s2}")
                hard_assert(
                    len(plan_ids[s1].intersection(plan_ids[s2])) == 0, f"Plan overlap {s1} {s2}"
                )

    print(
        f"Distinct tasks: train={len(tasks['train'])}, "
        f"val={len(tasks['val'])}, test={len(tasks['test'])}"
    )
    print(
        f"Intersection: train-val={len(tasks['train'] & tasks['val'])}, "
        f"train-test={len(tasks['train'] & tasks['test'])}, "
        f"val-test={len(tasks['val'] & tasks['test'])}"
    )

    for fam in FAMILIES:
        ltrain_path = os.path.join(data_dir, f"lofo_train_{fam}.csv")
        ltest_path = os.path.join(data_dir, f"lofo_test_{fam}.csv")
        df_tr = pd.read_csv(ltrain_path)
        df_te = pd.read_csv(ltest_path)
        check_cols(df_tr, f"lofo_train_{fam}.csv")
        check_cols(df_te, f"lofo_test_{fam}.csv")
        hard_assert(len(df_te) == 300, f"lofo_test_{fam} count mismatch")
        hard_assert(
            (df_te["family"] == fam).all() and (df_te["label"] == "HIGH-RISK").all(),
            f"lofo_test_{fam} content mismatch",
        )
        hard_assert(not (df_tr["family"] == fam).any(), f"lofo_train_{fam} contains the family")
        hard_assert(len(df_tr) + len(df_te) == 5500, f"lofo {fam} total != 5500")
        hard_assert(
            len(set(df_tr["plan_id"]).intersection(set(df_te["plan_id"]))) == 0,
            f"lofo {fam} plan overlap",
        )

    adv = pd.read_csv(os.path.join(data_dir, "adversarial_features.csv"))
    kag = pd.read_csv(os.path.join(data_dir, "kaggle_external_features.csv"))
    check_cols(adv, "adversarial_features.csv")
    check_cols(kag, "kaggle_external_features.csv")
    hard_assert(len(adv) == 30, "adv count mismatch")
    hard_assert(len(kag) == 780, "kag count mismatch")
    kag_counts = kag["label"].value_counts().to_dict()
    hard_assert(
        kag_counts.get("SAFE", 0) == 240 and kag_counts.get("HIGH-RISK", 0) == 540,
        "kag label count mismatch",
    )
    hard_assert(set(kag["label"].unique()).issubset(["SAFE", "HIGH-RISK"]), "kag invalid labels")

    print("\n--- SOFT CHECKS ---")
    train_X = dfs["train_features.csv"][features].astype(float)

    const_feats = train_X.columns[train_X.nunique() <= 1].tolist()
    if const_feats:
        print(f"WARNING: Constant features in train: {const_feats}")

    range_feats = train_X.columns[(train_X.max() - train_X.min()) > 1e6].tolist()
    if range_feats:
        print(f"WARNING: Features with range > 1e6 in train: {range_feats}")

    dfs["test_features.csv"][features].astype(float)
    df_train_sub = dfs["train_features.csv"][features + ["label"]].copy()
    df_test_sub = dfs["test_features.csv"][features + ["label"]].copy()
    df_train_sub["_split"] = "train"
    df_test_sub["_split"] = "test"
    combined = pd.concat([df_train_sub, df_test_sub])
    dup_mask = combined.duplicated(subset=features, keep=False)
    dups = combined[dup_mask]

    # We want duplicates that exist in BOTH train and test.
    # Group by features, and if a group contains both 'train' and 'test',
    # it's a cross-split duplicate.
    cross_dups = 0
    diff_labels = 0
    if not dups.empty:
        groups = dups.groupby(features)
        for _, group in groups:
            splits = group["_split"].unique()
            if "train" in splits and "test" in splits:
                cross_dups += len(group[group["_split"] == "train"])
                if group["label"].nunique() > 1:
                    diff_labels += 1

    if cross_dups > 0:
        print(f"WARNING: {cross_dups} duplicate feature vectors between train and test.")
        print(f"WARNING: {diff_labels} of those exact groups carry a different label.")

    kag_X = kag[features].astype(float)
    t_min = train_X.min()
    t_max = train_X.max()
    kag_oob = ((kag_X < t_min) | (kag_X > t_max)).mean().sort_values(ascending=False)
    print("WARNING: Top 10 features with kaggle values outside train range:")
    for f, v in kag_oob.head(10).items():
        if v > 0:
            print(f"  {f}: {v:.2%}")

    print("\n--- LEAKAGE SCREEN ---")
    y_tr = (dfs["train_features.csv"]["label"] == "HIGH-RISK").astype(int)
    y_val = (dfs["val_features.csv"]["label"] == "HIGH-RISK").astype(int)
    val_X = dfs["val_features.csv"][features].astype(float)

    aucs = {}
    for f in features:
        dt = DecisionTreeClassifier(max_depth=1, random_state=42)
        dt.fit(train_X[[f]], y_tr)
        pred = dt.predict_proba(val_X[[f]])[:, 1]
        try:
            aucs[f] = roc_auc_score(y_val, pred)
        except ValueError:
            aucs[f] = 0.5

    sorted_aucs = sorted(aucs.items(), key=lambda x: x[1], reverse=True)
    for f, auc_val in sorted_aucs[:5]:
        marker = " [SUSPECT]" if auc_val >= 0.98 else ""
        print(f"{f}: AUC={auc_val:.4f}{marker}")

    meta_cols_observed = [c for c in dfs["train_features.csv"].columns if c not in features]
    os.makedirs(os.path.join("artifacts", "metrics"), exist_ok=True)
    with open(os.path.join("artifacts", "metrics", "data_validation.json"), "w") as out:
        json.dump(
            {
                "status": "VALID",
                "top_leakage_auc": sorted_aucs[0][1],
                "meta_columns_observed": meta_cols_observed,
            },
            out,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", default="data/processed")
    args = parser.parse_args()
    validate(args.data_dir)
