"""
Mantis Typed MCP Tool Surface.
Exposes forensic extraction, radare2 reverse-engineering, and memory triage capabilities
over the Model Context Protocol (MCP) with typed parameter schemas and fail-closed validation.
"""

import json
from dataclasses import asdict
from typing import Any

from ..exceptions import MantisBoundaryError
from ..logger import ExecutionLogger
from ..mcp_server import (
    carve_memory_strings,
    get_evidence_context,
    query_json_cache,
    search_disk_timeline,
    validate_path,
)
from ..r2.reconstructor import reconstruct_dumped_pe
from ..r2.wrapper import R2Wrapper


def mantis_r2_disasm(path: str, offset: int | str = 0, count: int = 10) -> list[dict[str, Any]]:
    """
    Disassembles opcodes at a specified offset inside an extracted binary or memory dump.

    Args:
        path: Absolute or relative path to the target binary/dump.
        offset: Offset or virtual address (int or hex string like '0x1000').
        count: Number of instructions to disassemble (default 10).
    """
    valid_path = validate_path(path)
    if isinstance(offset, str):
        offset_val = int(offset, 16) if offset.startswith("0x") else int(offset)
    else:
        offset_val = int(offset)

    wrapper = R2Wrapper()
    opcodes = wrapper.disassemble(valid_path, offset=offset_val, count=count)
    return [asdict(op) for op in opcodes]


def mantis_r2_entropy(path: str, block_size: int = 1024) -> dict[str, Any]:
    """
    Calculates file and block-level Shannon entropy to detect packing or encryption.

    Args:
        path: Path to target file within sandbox.
        block_size: Size of blocks for entropy calculation (default 1024).
    """
    valid_path = validate_path(path)
    wrapper = R2Wrapper()
    profile = wrapper.calculate_entropy(valid_path, block_size=block_size)
    return asdict(profile)


def mantis_rabin_sections(path: str) -> list[dict[str, Any]]:
    """
    Extracts executable sections and virtual memory mappings using rabin2.

    Args:
        path: Path to target executable or memory dump.
    """
    valid_path = validate_path(path)
    wrapper = R2Wrapper()
    sections = wrapper.get_sections(valid_path)
    return [asdict(s) for s in sections]


def mantis_rabin_info(path: str) -> dict[str, Any]:
    """
    Extracts binary architecture, compiler, endianness, and headers using rabin2.

    Args:
        path: Path to target executable.
    """
    valid_path = validate_path(path)
    wrapper = R2Wrapper()
    info = wrapper.get_binary_info(valid_path)
    return asdict(info)


def mantis_reconstruct_pe(dump_path: str, output_path: str) -> dict[str, Any]:
    """
    Reconstructs dumped PE/ELF virtual sections to raw disk format via rabin2 (Issue #15449).

    Args:
        dump_path: Path to the raw memory dump slice.
        output_path: Path where the repaired binary will be written.
    """
    src_valid = validate_path(dump_path)
    # output must also reside in allowed directories
    dst_valid = validate_path(output_path)
    reconstruct_dumped_pe(src_valid, dst_valid)
    return {
        "status": "success",
        "dump_path": src_valid,
        "output_path": dst_valid,
        "reconstructed": True,
    }


def mantis_get_evidence_context() -> dict[str, Any]:
    """
    Retrieves the global forensic evidence context and discovered artifact metadata.
    """
    raw_ctx = get_evidence_context()
    try:
        return json.loads(raw_ctx)
    except (json.JSONDecodeError, TypeError):
        return {"raw_context": raw_ctx}


def mantis_query_cache(cache_name: str, keyword: str = "") -> dict[str, Any]:
    """
    Queries an aggregated JSON evidence cache (e.g. 'pstree', 'netscan', 'malfind', 'cmdline').

    Args:
        cache_name: Name of the cache (e.g. 'pstree' or 'pstree.json').
        keyword: Optional search filter.
    """
    raw_data = query_json_cache(cache_name, keyword=keyword)
    try:
        return json.loads(raw_data)
    except (json.JSONDecodeError, TypeError):
        return {"raw_data": raw_data}


def mantis_search_timeline(keyword: str) -> dict[str, Any]:
    """
    Searches the carved bodyfile and disk timeline for file access or creation events.

    Args:
        keyword: Keyword or path snippet to match.
    """
    return search_disk_timeline(keyword)


def mantis_carve_strings(regex_pattern: str, memory_image_path: str, pid: str = "NONE") -> dict[str, Any]:
    """
    Executes in-memory regex carving across a target process or full memory image.

    Args:
        regex_pattern: Regular expression to carve.
        memory_image_path: Path to memory dump.
        pid: Optional target PID.
    """
    valid_path = validate_path(memory_image_path)
    res = carve_memory_strings(regex_pattern, valid_path, pid=pid)
    return {"status": "success", "output": res}


# MCP Tool Definitions (JSON-RPC 2.0 / Model Context Protocol Spec)
MCP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "mantis_r2_disasm",
        "description": "Disassembles machine opcodes at an offset in an executable or memory dump using radare2.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to binary or memory dump slice."},
                "offset": {"type": ["integer", "string"], "description": "Starting offset or hex address (e.g. '0x1000')."},
                "count": {"type": "integer", "description": "Number of instructions to disassemble.", "default": 10},
            },
            "required": ["path"],
        },
        "handler": mantis_r2_disasm,
    },
    {
        "name": "mantis_r2_entropy",
        "description": "Calculates Shannon entropy to detect packed, obfuscated, or encrypted payloads.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to target file."},
                "block_size": {"type": "integer", "description": "Block size in bytes.", "default": 1024},
            },
            "required": ["path"],
        },
        "handler": mantis_r2_entropy,
    },
    {
        "name": "mantis_rabin_sections",
        "description": "Extracts binary section headers and permissions using rabin2.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to executable."},
            },
            "required": ["path"],
        },
        "handler": mantis_rabin_sections,
    },
    {
        "name": "mantis_rabin_info",
        "description": "Extracts binary architecture, OS, compiler, and binary class using rabin2.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to executable."},
            },
            "required": ["path"],
        },
        "handler": mantis_rabin_info,
    },
    {
        "name": "mantis_reconstruct_pe",
        "description": "Reconstructs memory-dumped PE/ELF virtual sections to disk format via rabin2.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "dump_path": {"type": "string", "description": "Path to memory dump."},
                "output_path": {"type": "string", "description": "Path for repaired binary."},
            },
            "required": ["dump_path", "output_path"],
        },
        "handler": mantis_reconstruct_pe,
    },
    {
        "name": "mantis_get_evidence_context",
        "description": "Retrieves the global forensic evidence context and metadata.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
        "handler": mantis_get_evidence_context,
    },
    {
        "name": "mantis_query_cache",
        "description": "Queries an aggregated forensic evidence cache (pstree, netscan, malfind, cmdline).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "cache_name": {"type": "string", "description": "Cache name (e.g. 'pstree', 'netscan')."},
                "keyword": {"type": "string", "description": "Search keyword or PID.", "default": ""},
            },
            "required": ["cache_name"],
        },
        "handler": mantis_query_cache,
    },
    {
        "name": "mantis_search_timeline",
        "description": "Searches disk timeline and bodyfile entries for file access or modification events.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "keyword": {"type": "string", "description": "Keyword or filepath snippet."},
            },
            "required": ["keyword"],
        },
        "handler": mantis_search_timeline,
    },
    {
        "name": "mantis_carve_strings",
        "description": "Performs regex carving inside memory image or process memory allocations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "regex_pattern": {"type": "string", "description": "Regex pattern to sweep."},
                "memory_image_path": {"type": "string", "description": "Path to memory dump."},
                "pid": {"type": "string", "description": "Target PID or 'NONE'.", "default": "NONE"},
            },
            "required": ["regex_pattern", "memory_image_path"],
        },
        "handler": mantis_carve_strings,
    },
]


def dispatch_tool(name: str, arguments: dict[str, Any]) -> Any:
    """
    Executes a named MCP tool with validated arguments.
    Raises MantisBoundaryError if the tool is unknown.
    """
    for tool in MCP_TOOLS:
        if tool["name"] == name:
            handler = tool["handler"]
            ExecutionLogger.log("MCP_TOOLS", f"Invoking tool {name} with args: {arguments}")
            return handler(**arguments)

    raise MantisBoundaryError(f"Unknown MCP tool: {name}")
