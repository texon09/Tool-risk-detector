"""Canned, side-effect-free database tool."""

import logging
from typing import Any

logger = logging.getLogger(__name__)


def database_query(args: dict[str, Any]) -> dict[str, Any]:
    logger.info("Mock database_query called")
    return {"status": "success", "rows": [{"id": 1, "data": "mocked row"}]}
