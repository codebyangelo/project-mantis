"""
Project Mantis: Autonomous DFIR Framework
"""

from .courtroom import CourtroomScriptGenerator
from .exceptions import (
    MantisBoundaryError,
    MantisError,
    MantisInvalidBootSignatureError,
    MantisOutOfBoundsPartitionError,
    MantisR2Error,
    MantisReconstructionError,
    MantisTruncatedBlockError,
)
from .extractor import (
    ClampedStreamReader,
    invalidate_evidence_cache,
    validate_sector_bounds,
)
from .falsifier import AdversarialFalsifier, CounterHypothesis
from .mcp import (
    MCP_TOOLS,
    MCPServer,
    dispatch_tool,
    run_mcp_server,
)

__version__ = "0.5.5"
__author__ = "Angelo Ayton"

__all__ = [
    "MCP_TOOLS",
    "AdversarialFalsifier",
    "ClampedStreamReader",
    "CounterHypothesis",
    "CourtroomScriptGenerator",
    "MCPServer",
    "MantisBoundaryError",
    "MantisError",
    "MantisInvalidBootSignatureError",
    "MantisOutOfBoundsPartitionError",
    "MantisR2Error",
    "MantisReconstructionError",
    "MantisTruncatedBlockError",
    "__author__",
    "__version__",
    "dispatch_tool",
    "invalidate_evidence_cache",
    "run_mcp_server",
    "validate_sector_bounds",
]
