import asyncio
import json

from app.api import metrics, scenarios


def test_metrics_missing_report_returns_unavailable(monkeypatch):
    monkeypatch.setenv("MODEL_METRICS_PATH", "missing-metrics-report.json")
    response = asyncio.run(metrics.get_metrics())
    assert response.available is False
    assert response.models == {}


def test_metrics_report_returns_per_model_values(tmp_path, monkeypatch):
    report = tmp_path / "metrics.json"
    report.write_text(
        json.dumps(
            {
                "models": {
                    "rf": {
                        "f1": 0.9,
                        "precision": 0.8,
                        "recall": 0.95,
                        "auroc": 0.97,
                        "latency_ms": 2.5,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("MODEL_METRICS_PATH", str(report))
    response = asyncio.run(metrics.get_metrics())
    assert response.available is True
    assert response.models["rf"].f1 == 0.9


def test_scenario_handler_loads_five_scenarios():
    response = asyncio.run(scenarios.get_scenarios())
    assert {item.name for item in response.scenarios} >= {
        "benign_read",
        "sensitive_read",
        "credential_harvest",
        "exfiltration_chain",
        "borderline_pii",
    }
