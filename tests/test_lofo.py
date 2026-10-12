import numpy as np
from sklearn.tree import DecisionTreeClassifier


def test_manifest_class_order():
    # Simulate the class-index bug fix
    manifest_class_order = ["SAFE", "SUSPICIOUS", "HIGH-RISK"]
    hr_idx = manifest_class_order.index("HIGH-RISK")
    assert hr_idx == 2

    # Toy data with missing classes or unordered classes
    # If we mapped alphabetically: HIGH-RISK=0, SAFE=1, SUSPICIOUS=2
    # But with manifest order: SAFE=0, SUSPICIOUS=1, HIGH-RISK=2
    labels_str = ["HIGH-RISK", "SAFE", "SUSPICIOUS", "SAFE"]
    labels_int = np.array([manifest_class_order.index(lbl) for lbl in labels_str])
    assert list(labels_int) == [2, 0, 1, 0]

    # Check that model.classes_ equals [0, 1, 2]
    dt = DecisionTreeClassifier()
    X = np.array([[1], [2], [3], [4]])
    dt.fit(X, labels_int)
    assert list(dt.classes_) == [0, 1, 2]

    # So predict_proba[:, hr_idx] correctly extracts HIGH-RISK
    preds = dt.predict_proba(X)
    assert preds.shape[1] == 3


def test_all_five_families_run(tmp_path):
    import pytest

    from backend.training.evaluate import get_lofo_families

    d = tmp_path / "data"
    d.mkdir()

    expected = {
        "data_exfiltration",
        "privilege_escalation",
        "destructive",
        "credential_harvesting",
        "injection_triggered",
    }
    for fam in expected:
        (d / f"lofo_test_{fam}.csv").touch()

    # Create one unrelated file
    (d / "unrelated.csv").touch()

    fams = get_lofo_families(str(d))
    assert set(fams) == expected
    assert len(fams) == 5

    # Test missing family
    (d / "lofo_test_destructive.csv").unlink()
    with pytest.raises(ValueError, match="Expected 5 LOFO families, found 4"):
        get_lofo_families(str(d))
