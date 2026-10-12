import logging

from app.mock_tools.runtime import execute


def test_all_mock_tools_return_canned_results_without_side_effects(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    file_target = tmp_path / "must-not-be-written.txt"
    assert execute("database_query", {"query": "sensitive query"})["rows"]
    assert (
        execute("file_read", {"path": str(tmp_path / "secret")})["content"] == "mock file content"
    )
    assert (
        execute("file_write", {"path": str(file_target), "content": "secret body"})["status"]
        == "simulated"
    )
    assert (
        execute("http_post", {"url": "https://example.org/path", "body": "secret body"})["status"]
        == 200
    )
    assert execute("email_send", {"to": "person@example.org"})["recipient_domain"] == "example.org"
    assert execute("shell_exec", {"cmd": "echo secret body"})["code"] == 0

    assert not file_target.exists()
    assert "secret body" not in caplog.text
    assert "sensitive query" not in caplog.text


def test_unknown_mock_tool_is_safe():
    assert execute("not-a-tool", {}) == {"error": "Unknown tool"}
