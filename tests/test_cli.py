"""
Unit tests for Project Mantis CLI (src/mantis/cli.py).
Verifies subcommands, argument parsing, fail-closed handling, and backward-compatible flags.
"""

import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

# Ensure src is on sys.path
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from mantis.cli import build_parser, main


class TestMantisCLI(unittest.TestCase):
    """Test suite for Mantis unified CLI interface."""

    def test_cli_no_args_shows_help(self):
        """Calling mantis with no args should show help and return 0."""
        with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
            ret = main([])
            self.assertEqual(ret, 0)
            self.assertIn("Project Mantis", mock_stdout.getvalue())

    def test_cli_help_flag(self):
        """Calling mantis --help should exit with 0."""
        parser = build_parser()
        with patch("sys.stdout", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as cm:
                parser.parse_args(["--help"])
            self.assertEqual(cm.exception.code, 0)

    @patch("mantis.cli.cmd_triage")
    def test_cli_triage_subcommand(self, mock_cmd):
        """mantis triage forwards flags to triage handler."""
        mock_cmd.return_value = 0
        ret = main(["triage", "--deep"])
        self.assertEqual(ret, 0)
        self.assertTrue(mock_cmd.called)

    @patch("mantis.cli.cmd_triage")
    def test_cli_legacy_flags_routing(self, mock_cmd):
        """mantis --live routes automatically to triage handler."""
        mock_cmd.return_value = 0
        ret = main(["--live", "--interval", "10"])
        self.assertEqual(ret, 0)
        self.assertTrue(mock_cmd.called)

    @patch("mantis.cli.cmd_carve")
    def test_cli_carve_subcommand(self, mock_cmd):
        """mantis carve forwards flags to carve handler."""
        mock_cmd.return_value = 0
        ret = main(["carve", "--memory", "--disk"])
        self.assertEqual(ret, 0)
        self.assertTrue(mock_cmd.called)

    def test_cli_analyze_dump_missing_file_fails_closed(self):
        """mantis analyze-dump fails closed on missing dump file."""
        ret = main(["analyze-dump", "/nonexistent/test_dump_12345.raw"])
        self.assertEqual(ret, 1)

    def test_cli_analyze_dump_json_output(self):
        """mantis analyze-dump with --json outputs valid structured analysis."""
        with tempfile.NamedTemporaryFile(suffix=".raw", delete=False) as f:
            # Write 48b8 (movabs rax, imm) trampoline
            f.write(b"\x48\xb8\x00\x10\x40\x00\x00\x00\x00\x00\xff\xe0" + b"\x90" * 100)
            dump_path = f.name

        try:
            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                ret = main(["analyze-dump", dump_path, "--pid", "2048", "--json"])
                self.assertEqual(ret, 0)
                output = mock_stdout.getvalue()
                json_start = output.find("{")
                json_end = output.rfind("}")
                self.assertNotEqual(json_start, -1)
                data = json.loads(output[json_start : json_end + 1])
                self.assertEqual(data["pid"], 2048)
                self.assertEqual(data["dump_path"], dump_path)
                self.assertIn("classification", data)
                self.assertIn("verdict", data)
        finally:
            if os.path.exists(dump_path):
                os.remove(dump_path)

    @patch("mantis.mcp.server.run_mcp_server")
    def test_cli_mcp_subcommand(self, mock_mcp_server):
        """mantis mcp launches MCP server."""
        ret = main(["mcp"])
        self.assertEqual(ret, 0)
        self.assertTrue(mock_mcp_server.called)


if __name__ == "__main__":
    unittest.main()
