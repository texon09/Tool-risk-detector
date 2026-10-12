"""Data loader for training."""

import hashlib
import json
import os
from typing import List, Tuple

import pandas as pd

CLASS_ORDER = ["SAFE", "SUSPICIOUS", "HIGH-RISK"]


def file_sha256(path: str) -> str:
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def load_feature_list(data_dir: str) -> List[str]:
    with open(os.path.join(data_dir, "feature_list.json"), "r", encoding="utf-8") as f:
        return json.load(f)


def load_split(
    path: str, feature_list: List[str] = None
) -> Tuple[pd.DataFrame, pd.Series, pd.DataFrame]:
    df = pd.read_csv(path)
    meta_cols = ["label", "family", "difficulty", "plan_id", "task_id"]
    if feature_list is not None:
        n_feat = len(feature_list)
        if list(df.columns[:n_feat]) != feature_list:
            raise ValueError(f"Features column order differ from feature_list.json in {path}")
        missing_meta = [c for c in meta_cols if c not in df.columns]
        if missing_meta:
            raise ValueError(f"Missing meta columns {missing_meta} in {path}")
        features = feature_list
    else:
        features = [c for c in df.columns if c not in meta_cols]

    X = df[features].copy()
    for col in X.columns:
        if X[col].dtype == bool:
            X[col] = X[col].astype(float)
    X = X.astype(float)

    y = df["label"] if "label" in df.columns else pd.Series(dtype=str)
    meta_cols_exist = [c for c in meta_cols if c in df.columns]
    meta = df[meta_cols_exist]
    return X, y, meta
