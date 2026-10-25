"""
Mantis Model Context Protocol (MCP) Subsystem.
"""

from .server import MCPServer, run_mcp_server
from .tools import (
    MCP_TOOLS,
    dispatch_tool,
    mantis_carve_strings,
    mantis_get_evidence_context,
    mantis_query_cache,
    mantis_r2_disasm,
    mantis_r2_entropy,
    mantis_rabin_info,
    mantis_rabin_sections,
    mantis_reconstruct_pe,
    mantis_search_timeline,
)

__all__ = [
    "MCP_TOOLS",
    "MCPServer",
    "dispatch_tool",
    "mantis_carve_strings",
    "mantis_get_evidence_context",
    "mantis_query_cache",
    "mantis_r2_disasm",
    "mantis_r2_entropy",
    "mantis_rabin_info",
    "mantis_rabin_sections",
    "mantis_reconstruct_pe",
    "mantis_search_timeline",
    "run_mcp_server",
]
