"""Read-only scenario endpoint handler (route registration belongs to P4)."""

from __future__ import annotations

import json
from pathlib import Path

from app.schemas import ScenarioResponse
from fastapi import APIRouter

router = APIRouter()
SCENARIOS_PATH = Path(__file__).resolve().parents[1] / "data" / "scenarios.json"


@router.get("/scenarios", response_model=ScenarioResponse)
async def get_scenarios() -> ScenarioResponse:
    """Load the packaged demo scenarios."""
    try:
        payload = json.loads(SCENARIOS_PATH.read_text(encoding="utf-8"))
        return ScenarioResponse.model_validate(payload)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return ScenarioResponse(scenarios=[])
