"""Mock MCP servers simulating real external tool services."""

from __future__ import annotations

from typing import Any


class MockDatabaseServer:
    """Mock MCP Database Server."""

    name = "database_server"

    def execute_query(self, query: str, limit: int = 10) -> dict[str, Any]:
        return {
            "status": "success",
            "server": self.name,
            "query": query,
            "rows": [{"id": 1, "name": "Test Record", "status": "active"}][:limit],
        }


class MockFilesystemServer:
    """Mock MCP Filesystem Server."""

    name = "filesystem_server"

    def read_file(self, path: str) -> dict[str, Any]:
        return {
            "status": "success",
            "server": self.name,
            "path": path,
            "content": f"[Simulated content of {path}]",
        }

    def write_file(self, path: str, content: str) -> dict[str, Any]:
        return {
            "status": "success",
            "server": self.name,
            "path": path,
            "bytes_written": len(content),
        }


class MockHTTPServer:
    """Mock MCP HTTP Web Client Server."""

    name = "http_server"

    def post(self, url: str, body: Any = None) -> dict[str, Any]:
        return {
            "status": "success",
            "server": self.name,
            "url": url,
            "status_code": 200,
            "response": {"received": True},
        }


class MockEmailServer:
    """Mock MCP Email Dispatcher Server."""

    name = "email_server"

    def send_email(self, to: str, subject: str, body: str) -> dict[str, Any]:
        return {
            "status": "success",
            "server": self.name,
            "recipient": to,
            "subject": subject,
            "delivered": True,
        }


class MockShellServer:
    """Mock MCP Shell Command Runner Server."""

    name = "shell_server"

    def run_command(self, cmd: str) -> dict[str, Any]:
        return {
            "status": "success",
            "server": self.name,
            "command": cmd,
            "exit_code": 0,
            "output": "Command simulated successfully.",
        }


# Global registry of mock MCP servers
SERVERS = {
    "database": MockDatabaseServer(),
    "filesystem": MockFilesystemServer(),
    "http": MockHTTPServer(),
    "email": MockEmailServer(),
    "shell": MockShellServer(),
}


def dispatch_to_mcp_server(tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute an allowed tool call on its corresponding mock MCP server."""
    if tool_name == "database_query":
        return SERVERS["database"].execute_query(
            query=arguments.get("query", ""),
            limit=int(arguments.get("limit", 10)),
        )
    elif tool_name == "file_read":
        return SERVERS["filesystem"].read_file(path=arguments.get("path", ""))
    elif tool_name == "file_write":
        return SERVERS["filesystem"].write_file(
            path=arguments.get("path", ""),
            content=arguments.get("content", ""),
        )
    elif tool_name == "http_post":
        return SERVERS["http"].post(
            url=arguments.get("url", ""),
            body=arguments.get("body"),
        )
    elif tool_name == "email_send":
        return SERVERS["email"].send_email(
            to=arguments.get("to", ""),
            subject=arguments.get("subject", ""),
            body=arguments.get("body", ""),
        )
    elif tool_name == "shell_exec":
        return SERVERS["shell"].run_command(cmd=arguments.get("cmd", ""))
    else:
        return {"status": "success", "tool": tool_name, "executed": True}
