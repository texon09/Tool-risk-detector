"""Canned, side-effect-free shell tool."""

import logging
import shlex
from typing import Any

logger = logging.getLogger(__name__)


def shell_exec(args: dict[str, Any]) -> dict[str, Any]:
    command = str(args.get("cmd", args.get("command", "")))
    try:
        command_name = shlex.split(command)[0] if command else "unknown"
    except ValueError:
        command_name = "unparsed"
    logger.info("Mock shell_exec called for command %s", command_name)
    return {"stdout": "mock output from shell", "code": 0}
