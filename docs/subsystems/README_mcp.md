# Documentation: `mcp/` Subsystem

## Overview

The `mcp/` subsystem implements a native, dependency-free Model Context Protocol (MCP) server for Project Mantis. Operating over standard input/output (stdio) using the JSON-RPC 2.0 protocol specification, it allows LLM host environments (such as Claude Desktop, Cursor, Continue, or autonomous agent frameworks) to discover, inspect, and invoke Mantis forensic and reverse-engineering capabilities.

---

## Architectural Breakdown

```
src/mantis/mcp/
├── __init__.py     # Re-exports MCPServer, dispatch_tool, and typed tools
├── server.py       # Stdio JSON-RPC 2.0 protocol server engine
└── tools.py        # 9 typed tools with parameter schemas and path sandboxing
```

### Protocol Compliance (MCP Spec 2024-11-05)
The `MCPServer` implements the standard lifecycle methods:
1. `initialize`: Returns server metadata (`mantis-dfir v0.5.5`) and capabilities (`{"tools": {"listChanged": false}}`).
2. `notifications/initialized`: Notification handshake acknowledgement.
3. `tools/list`: Returns JSON schema definitions for all 9 registered tools.
4. `tools/call`: Executes the target tool function, returning structured text content blocks (`{"content": [{"type": "text", "text": "..."}]}`).
5. `ping`: Health check returning an empty JSON object.

---

## Registered MCP Tools

| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| **`mantis_r2_disasm`** | `path` (str), `offset` (int/hex str), `count` (int) | Disassembles opcodes at a specified offset inside an extracted binary or dump using radare2 `pdj`. |
| **`mantis_r2_entropy`** | `path` (str), `block_size` (int) | Computes overall and block-level Shannon entropy via `rahash2` to detect packed or encrypted payloads. |
| **`mantis_rabin_sections`**| `path` (str) | Extracts section names, virtual addresses, sizes, and permission flags (`r-x`, `rw-`) via `rabin2 -j -S`. |
| **`mantis_rabin_info`** | `path` (str) | Extracts binary architecture, compiler, endianness, and binary type via `rabin2 -j -I`. |
| **`mantis_reconstruct_pe`**| `dump_path` (str), `output_path` (str) | Repairs virtual memory section headers in dumped PE/ELF binaries via `rabin2 -O r -O p` (Issue #15449). |
| **`mantis_get_evidence_context`** | None | Retrieves global investigation metadata and discovered evidence images from `context.json`. |
| **`mantis_query_cache`** | `cache_name` (str), `keyword` (str) | Queries aggregated forensic JSON tables (`pstree`, `netscan`, `malfind`, `cmdline`) with keyword filtering. |
| **`mantis_search_timeline`**| `keyword` (str) | Sweeps the carved filesystem bodyfile and disk timeline for file access or modification events. |
| **`mantis_carve_strings`**| `regex_pattern` (str), `memory_image_path` (str), `pid` (str) | Executes surgical in-memory regex sweeps across target process VAD allocations or full images. |

---

## Security Model & Path Sandboxing

All tools accepting file paths strictly enforce the `validate_path()` security boundary from `mcp_server.py`:
* **Path Traversal Prevention**: Ensures resolved canonical paths reside strictly within `EVIDENCE_DIR` or `CACHE_DIR`.
* **Null Byte Rejection**: Detects and rejects poison null bytes (`\x00`).
* **Fail-Closed Execution**: Violations immediately raise `ValueError` and log a security error to `execution.log`.
