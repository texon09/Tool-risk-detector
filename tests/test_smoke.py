"""Tests for smoke."""

import json
import os

import yaml

import backend.app  # noqa: F401
import backend.app.audit  # noqa: F401
import backend.app.features  # noqa: F401
import backend.app.ml  # noqa: F401
import backend.app.mock_tools  # noqa: F401
import backend.app.policy  # noqa: F401
import backend.app.rules  # noqa: F401


def test_smoke():
    assert os.path.exists("backend/app/rules/rules.yaml")
    assert os.path.exists("backend/app/policy/thresholds.json")
    with open("backend/app/rules/rules.yaml", "r") as f:
        yaml.safe_load(f)
    with open("backend/app/policy/thresholds.json", "r") as f:
        json.load(f)
