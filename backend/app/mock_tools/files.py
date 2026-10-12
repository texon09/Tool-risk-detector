"""Canned, side-effect-free filesystem tools."""

import logging
from typing import Any

logger = logging.getLogger(__name__)


def file_read(args: dict[str, Any]) -> dict[str, Any]:
    logger.info("Mock file_read called")
    return {"content": "mock file content"}


def file_write(args: dict[str, Any]) -> dict[str, Any]:
    content = str(args.get("content", ""))
    logger.info("Mock file_write called (%d content characters)", len(content))
    return {"status": "simulated", "bytes": len(content)}
