"""Safe dispatcher for the canned mock tool implementations."""

import logging
from typing import Any, Callable

from app.mock_tools.db import database_query
from app.mock_tools.email import email_send
from app.mock_tools.executor import shell_exec
from app.mock_tools.files import file_read, file_write
from app.mock_tools.http import http_post

logger = logging.getLogger(__name__)
TOOL_HANDLERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "database_query": database_query,
    "file_read": file_read,
    "file_write": file_write,
    "http_post": http_post,
    "email_send": email_send,
    "shell_exec": shell_exec,
}


def execute(tool_name: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    """Dispatch a tool call without performing its real-world side effect."""
    handler = TOOL_HANDLERS.get(tool_name)
    if handler is None:
        logger.warning("Unknown mock tool requested: %s", tool_name)
        return {"error": "Unknown tool"}
    try:
        return handler(args or {})
    except Exception:
        logger.error("Mock tool handler failed: %s", tool_name)
        return {"error": "Mock tool failed safely"}


class MockToolRuntime:
    """Compatibility wrapper for integrations using the old runtime class."""

    def execute(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        return execute(tool_name, args)
