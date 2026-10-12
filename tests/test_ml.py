import hashlib
import json

import joblib
import pandas as pd
import pytest

pytest.importorskip("sklearn")
from backend.app.ml.loader import (
    ChecksumMismatchError,
    FeatureMismatchError,
    MissingFileError,
    load_model,
)


def test_loader_corrupted_and_feature_mismatch(tmp_path):
    m_dir = tmp_path / "models"
    d_dir = tmp_path / "data"
    m_dir.mkdir()
    d_dir.mkdir()

    flist = ["f1", "f2"]
    with open(d_dir / "feature_list.json", "w") as f:
        json.dump(flist, f)

    jfile = m_dir / "test.joblib"
    joblib.dump({"model": True}, jfile)
    actual_sha = hashlib.sha256(jfile.read_bytes()).hexdigest()

    manifest = {
        "version": "vtest",
        "feature_names": ["f1", "f2"],
        "class_order": ["SAFE", "SUSPICIOUS", "HIGH-RISK"],
        "joblib_sha256": {"test.joblib": actual_sha},
    }
    with open(m_dir / "manifest.json", "w") as f:
        json.dump(manifest, f)

    # Should work
    man, mods = load_model(str(m_dir), str(d_dir))
    assert man["version"] == "vtest"

    # Checksum mismatch
    jfile.write_text("corrupted")
    with pytest.raises(ChecksumMismatchError):
        load_model(str(m_dir), str(d_dir))

    joblib.dump({"model": True}, jfile)

    # Feature mismatch
    with open(d_dir / "feature_list.json", "w") as f:
        json.dump(["f1", "f2", "f3"], f)

    with pytest.raises(FeatureMismatchError):
        load_model(str(m_dir), str(d_dir))

    # Missing file
    with open(d_dir / "feature_list.json", "w") as f:
        json.dump(["f1", "f2"], f)

    manifest["joblib_sha256"]["other.joblib"] = "abc"
    with open(m_dir / "manifest.json", "w") as f:
        json.dump(manifest, f)

    with pytest.raises(MissingFileError):
        load_model(str(m_dir), str(d_dir))


def test_dedup_mask():
    from backend.training.evaluate import get_dedup_mask

    df_train = pd.DataFrame({"f1": [1.0, 2.0], "f2": [0.1, 0.2]})
    df_test = pd.DataFrame({"f1": [1.0, 3.0, 2.0], "f2": [0.1, 0.3, 0.2000001]})
    mask = get_dedup_mask(df_train, df_test)
    assert not mask[0]  # exact match
    assert mask[1]  # completely new
    assert mask[2]  # exact match requested
    pass


def test_dedup_mask_exact():
    from backend.training.evaluate import get_dedup_mask

    df_train = pd.DataFrame({"f1": [1.0, 2.0], "f2": [0.1, 0.2]})
    df_test = pd.DataFrame({"f1": [1.0, 3.0, 2.0], "f2": [0.1, 0.3, 0.2000001]})
    mask = get_dedup_mask(df_train, df_test)
    assert not mask[0]
    assert mask[1]
    assert mask[2]  # different at 7th decimal!


def test_threshold_at_fpr_ties():
    import numpy as np

    from backend.training.metrics import threshold_at_fpr

    y = np.array(["SAFE"] * 10 + ["HIGH-RISK"] * 10)
    # 10 SAFE rows. Target fpr 0.05 -> <= 0.5 rows flagged (so 0 rows).
    # But let's say target fpr is 0.20 (<= 2 rows).
    # Scores: 0.1, 0.1, 0.1, 0.2, 0.2, 0.2, 0.3, 0.3, 0.4, 0.5
    scores = np.array([0.1, 0.1, 0.1, 0.2, 0.2, 0.2, 0.3, 0.3, 0.4, 0.5] + [0.9] * 10)

    # 0.5 -> 1 flagged (10%). 0.4 -> 2 flagged (20%). 0.3 -> 4 flagged (40%)
    t = threshold_at_fpr(y, scores, 0.20)
    assert t == 0.4
    actual_fpr = np.sum(scores[y == "SAFE"] >= t) / 10.0
    assert actual_fpr <= 0.20

    # 0.25 target fpr -> also 0.4, because 0.3 gives 40% which > 0.25
    t2 = threshold_at_fpr(y, scores, 0.25)
    assert t2 == 0.4
    actual_fpr2 = np.sum(scores[y == "SAFE"] >= t2) / 10.0
    assert actual_fpr2 <= 0.25
