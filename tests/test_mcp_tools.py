"""
Unit tests for Mantis MCP Subsystem (src/mantis/mcp/).
Verifies typed MCP tool functions, JSON-RPC 2.0 stdio protocol, and error boundaries.
"""

import io
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure src is on sys.path
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from mantis.config import EVIDENCE_DIR
from mantis.exceptions import MantisBoundaryError
from mantis.mcp import (
    MCP_TOOLS,
    MCPServer,
    dispatch_tool,
    mantis_r2_disasm,
    mantis_r2_entropy,
    mantis_rabin_info,
    mantis_rabin_sections,
    mantis_reconstruct_pe,
)
from mantis.r2.parser import EntropyProfile, R2BinaryInfo, R2Opcode, R2Section


class TestMCPTools(unittest.TestCase):
    """Test suite for Mantis typed MCP tools and JSON-RPC server."""

    def test_mcp_tools_definitions(self):
        """Verify MCP_TOOLS list contains 9 tools with valid schemas."""
        self.assertEqual(len(MCP_TOOLS), 9)
        names = [t["name"] for t in MCP_TOOLS]
        self.assertIn("mantis_r2_disasm", names)
        self.assertIn("mantis_r2_entropy", names)
        self.assertIn("mantis_rabin_sections", names)
        self.assertIn("mantis_rabin_info", names)
        self.assertIn("mantis_reconstruct_pe", names)
        self.assertIn("mantis_query_cache", names)

    def test_dispatch_unknown_tool_raises(self):
        """Dispatching an unknown tool raises MantisBoundaryError."""
        with self.assertRaises(MantisBoundaryError):
            dispatch_tool("nonexistent_tool_xyz", {})

    @patch("mantis.mcp.tools.R2Wrapper")
    def test_mantis_r2_disasm(self, mock_wrapper_cls):
        """mantis_r2_disasm parses offset and returns opcode dicts."""
        mock_instance = MagicMock()
        mock_wrapper_cls.return_value = mock_instance
        mock_instance.disassemble.return_value = [
            R2Opcode(offset=0x1000, size=2, opcode="mov eax, 1", disasm="mov eax, 1", bytes_hex="b801000000")
        ]

        # Use file in EVIDENCE_DIR to pass path validation
        test_file = os.path.join(EVIDENCE_DIR, "test_bin.raw")
        with open(test_file, "wb") as f:
            f.write(b"\x90" * 16)

        try:
            res = mantis_r2_disasm(test_file, offset="0x1000", count=5)
            self.assertEqual(len(res), 1)
            self.assertEqual(res[0]["opcode"], "mov eax, 1")
            self.assertEqual(res[0]["offset"], 0x1000)
        finally:
            if os.path.exists(test_file):
                os.remove(test_file)

    @patch("mantis.mcp.tools.R2Wrapper")
    def test_mantis_r2_entropy(self, mock_wrapper_cls):
        """mantis_r2_entropy returns entropy profile dict."""
        mock_instance = MagicMock()
        mock_wrapper_cls.return_value = mock_instance
        mock_instance.calculate_entropy.return_value = EntropyProfile(
            overall_entropy=7.85, block_size=1024, blocks=[7.8, 7.9]
        )

        test_file = os.path.join(EVIDENCE_DIR, "test_entropy.raw")
        with open(test_file, "wb") as f:
            f.write(b"\xff" * 64)

        try:
            res = mantis_r2_entropy(test_file, block_size=512)
            self.assertEqual(res["overall_entropy"], 7.85)
            self.assertEqual(len(res["blocks"]), 2)
        finally:
            if os.path.exists(test_file):
                os.remove(test_file)

    @patch("mantis.mcp.tools.R2Wrapper")
    def test_mantis_rabin_sections(self, mock_wrapper_cls):
        """mantis_rabin_sections returns section metadata."""
        mock_instance = MagicMock()
        mock_wrapper_cls.return_value = mock_instance
        mock_instance.get_sections.return_value = [
            R2Section(name=".text", size=1024, vsize=1024, vaddr=0x1000, paddr=0x400, flags="r-x")
        ]

        test_file = os.path.join(EVIDENCE_DIR, "test_sec.raw")
        with open(test_file, "wb") as f:
            f.write(b"\x90" * 32)

        try:
            res = mantis_rabin_sections(test_file)
            self.assertEqual(len(res), 1)
            self.assertEqual(res[0]["name"], ".text")
            self.assertEqual(res[0]["flags"], "r-x")
        finally:
            if os.path.exists(test_file):
                os.remove(test_file)

    @patch("mantis.mcp.tools.R2Wrapper")
    def test_mantis_rabin_info(self, mock_wrapper_cls):
        """mantis_rabin_info returns binary metadata."""
        mock_instance = MagicMock()
        mock_wrapper_cls.return_value = mock_instance
        mock_instance.get_binary_info.return_value = R2BinaryInfo(
            arch="x86", bits=64, os="linux", bin_type="elf"
        )

        test_file = os.path.join(EVIDENCE_DIR, "test_info.raw")
        with open(test_file, "wb") as f:
            f.write(b"\x90" * 32)

        try:
            res = mantis_rabin_info(test_file)
            self.assertEqual(res["arch"], "x86")
            self.assertEqual(res["bits"], 64)
            self.assertEqual(res["os"], "linux")
        finally:
            if os.path.exists(test_file):
                os.remove(test_file)

    @patch("mantis.mcp.tools.reconstruct_dumped_pe")
    def test_mantis_reconstruct_pe(self, mock_recon):
        """mantis_reconstruct_pe invokes reconstruction engine."""
        mock_recon.return_value = True

        src = os.path.join(EVIDENCE_DIR, "src_dump.raw")
        dst = os.path.join(EVIDENCE_DIR, "dst_repaired.raw")
        with open(src, "wb") as f:
            f.write(b"MZ\x90\x00" * 16)

        try:
            res = mantis_reconstruct_pe(src, dst)
            self.assertEqual(res["status"], "success")
            self.assertTrue(res["reconstructed"])
        finally:
            if os.path.exists(src):
                os.remove(src)
            if os.path.exists(dst):
                os.remove(dst)

    def test_mcp_server_initialize_protocol(self):
        """MCPServer responds correctly to initialize JSON-RPC request."""
        server = MCPServer()
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {},
        }
        resp = server.handle_request(req)
        self.assertIsNotNone(resp)
        self.assertEqual(resp["id"], 1)
        self.assertEqual(resp["result"]["serverInfo"]["name"], "mantis-dfir")
        self.assertIn("tools", resp["result"]["capabilities"])

    def test_mcp_server_tools_list_protocol(self):
        """MCPServer responds to tools/list with all tool definitions."""
        server = MCPServer()
        req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }
        resp = server.handle_request(req)
        self.assertIsNotNone(resp)
        tools = resp["result"]["tools"]
        self.assertGreaterEqual(len(tools), 9)
        names = [t["name"] for t in tools]
        self.assertIn("mantis_r2_disasm", names)

    def test_mcp_server_tools_call_protocol(self):
        """MCPServer handles tools/call and returns text content."""
        server = MCPServer()
        req = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "mantis_search_timeline",
                "arguments": {"keyword": "test_search_entry"},
            },
        }
        resp = server.handle_request(req)
        self.assertIsNotNone(resp)
        self.assertFalse(resp["result"]["isError"])
        content = resp["result"]["content"]
        self.assertEqual(content[0]["type"], "text")

    def test_mcp_server_unknown_method(self):
        """MCPServer returns -32601 on unknown method."""
        server = MCPServer()
        req = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "invalid/method_name",
        }
        resp = server.handle_request(req)
        self.assertIsNotNone(resp)
        self.assertEqual(resp["error"]["code"], -32601)

    def test_mcp_server_run_stdio(self):
        """MCPServer.run_stdio processes lines and writes responses."""
        input_stream = io.StringIO('{"jsonrpc": "2.0", "id": 10, "method": "ping"}\n')
        output_stream = io.StringIO()

        server = MCPServer(stdin=input_stream, stdout=output_stream)
        server.run_stdio()

        raw_output = output_stream.getvalue().strip()
        resp = json.loads(raw_output)
        self.assertEqual(resp["id"], 10)
        self.assertEqual(resp["result"], {})


if __name__ == "__main__":
    unittest.main()
