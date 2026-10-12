"""Tests for data module."""

import json

import numpy as np
import pandas as pd
import pytest

from backend.training.data import load_split
from backend.training.metrics import recall_at_fpr, threshold_at_fpr


def test_loader_shuffled_meta(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    flist = ["f1", "f2"]
    with open(d / "feature_list.json", "w") as f:
        json.dump(flist, f)

    df = pd.DataFrame(
        {
            "f1": [3.0, 4.0],
            "f2": [1.0, 2.0],
            "plan_id": ["p1", "p2"],
            "label": ["SAFE", "HIGH-RISK"],
            "task_id": ["t1", "t2"],
            "family": ["", "fam"],
            "difficulty": ["easy", "hard"],
        }
    )
    path = d / "test.csv"
    df.to_csv(path, index=False)

    X, y, meta = load_split(str(path), flist)
    assert list(X.columns) == ["f1", "f2"]
    assert "plan_id" in meta.columns
    assert "task_id" in meta.columns


def test_loader_swapped_features(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    flist = ["f1", "f2"]
    with open(d / "feature_list.json", "w") as f:
        json.dump(flist, f)

    df = pd.DataFrame(
        {
            "f2": [1.0, 2.0],
            "f1": [3.0, 4.0],
            "label": ["SAFE", "HIGH-RISK"],
            "family": ["", "fam"],
            "difficulty": ["easy", "hard"],
            "plan_id": ["p1", "p2"],
            "task_id": ["t1", "t2"],
        }
    )
    path = d / "test.csv"
    df.to_csv(path, index=False)

    with pytest.raises(ValueError, match="Features column order differ"):
        load_split(str(path), flist)


def test_metrics():
    y = np.array(["SAFE", "SAFE", "HIGH-RISK", "HIGH-RISK"])
    score = np.array([0.1, 0.4, 0.35, 0.9])
    th = threshold_at_fpr(y, score, 0.5)
    assert np.isclose(th, 0.35)
    rec = recall_at_fpr(y, score, 0.5)
    assert np.isclose(rec, 1.0)
