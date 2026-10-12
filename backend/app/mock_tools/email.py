"""Canned, side-effect-free email tool."""

import logging
from typing import Any

logger = logging.getLogger(__name__)


def email_send(args: dict[str, Any]) -> dict[str, Any]:
    recipient = str(args.get("to", ""))
    domain = recipient.rsplit("@", 1)[-1].casefold() if "@" in recipient else "unknown"
    logger.info("Mock email_send called for recipient domain %s", domain)
    return {"status": "simulated", "recipient_domain": domain}
