"""Canned, side-effect-free HTTP tool."""

import logging
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)


def http_post(args: dict[str, Any]) -> dict[str, Any]:
    destination = str(args.get("url", ""))
    host = urlsplit(destination).hostname or "unknown"
    logger.info("Mock http_post called for destination host %s", host)
    return {"status": 200, "body": "ok from mock server"}
