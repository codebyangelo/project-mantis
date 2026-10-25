"""
Mantis Model Context Protocol (MCP) Server.
Implements a spec-compliant JSON-RPC 2.0 stdio server exposing Mantis DFIR tools
to LLM hosts and agents (Claude, Antigravity, Cursor, Continue).
"""

import json
import sys
from typing import Any

from ..logger import ExecutionLogger
from .tools import MCP_TOOLS, dispatch_tool


class MCPServer:
    """
    Stdio JSON-RPC 2.0 Model Context Protocol (MCP) server.
    """

    SERVER_NAME = "mantis-dfir"
    SERVER_VERSION = "0.5.5"

    def __init__(self, stdin=None, stdout=None):
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """
        Dispatches incoming JSON-RPC requests to protocol methods.
        """
        req_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        # Notifications (no id)
        if req_id is None:
            if method == "notifications/initialized":
                return None
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {
                        "name": self.SERVER_NAME,
                        "version": self.SERVER_VERSION,
                    },
                    "capabilities": {
                        "tools": {
                            "listChanged": False,
                        },
                    },
                },
            }

        if method == "ping":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {},
            }

        if method == "tools/list":
            tools_list = []
            for t in MCP_TOOLS:
                tools_list.append(
                    {
                        "name": t["name"],
                        "description": t["description"],
                        "inputSchema": t["inputSchema"],
                    }
                )
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": tools_list,
                },
            }

        if method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            try:
                result = dispatch_tool(tool_name, arguments)
                result_str = json.dumps(result, indent=2, default=str)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": result_str,
                            }
                        ],
                        "isError": False,
                    },
                }
            except Exception as e:  # noqa: BLE001
                ExecutionLogger.log("MCP_SERVER", f"Error executing {tool_name}: {e}", "ERROR")
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": f"Error: {e}",
                            }
                        ],
                        "isError": True,
                    },
                }

        # Unknown method
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32601,
                "message": f"Method not found: {method}",
            },
        }

    def run_stdio(self) -> None:
        """
        Runs the continuous stdio server loop reading line-delimited JSON-RPC messages.
        """
        for line in self.stdin:
            line_str = line.strip()
            if not line_str:
                continue

            try:
                request = json.loads(line_str)
            except json.JSONDecodeError as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32700,
                        "message": f"Parse error: {e}",
                    },
                }
                self.stdout.write(json.dumps(err_resp) + "\n")
                self.stdout.flush()
                continue

            response = self.handle_request(request)
            if response is not None:
                self.stdout.write(json.dumps(response) + "\n")
                self.stdout.flush()


def run_mcp_server() -> None:
    """Convenience launcher for the stdio MCP server."""
    server = MCPServer()
    server.run_stdio()


if __name__ == "__main__":
    run_mcp_server()
