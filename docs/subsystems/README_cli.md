# Documentation: `cli.py`

## Overview

The `cli.py` module serves as the centralized command-line interface entrypoint for Project Mantis. It exposes standard subcommands (`triage`, `carve`, `analyze-dump`, `mcp`) while maintaining backwards-compatibility with legacy command invocations. Installed via the console script entrypoint `mantis = "mantis.cli:main"` in `pyproject.toml`, it provides deterministic argument parsing, logging integration, and sub-engine dispatch.

---

## Architectural Breakdown

The CLI architecture wraps underlying forensic sub-engines (orchestrator, extractor, sieve, falsifier, and MCP server) behind an `argparse` dispatch tree:

```
mantis
├── triage         -> cmd_triage()        -> orchestrator.main()
├── carve          -> cmd_carve()         -> extractor.main()
├── analyze-dump   -> cmd_analyze_dump()  -> MalfindClassifier + AdversarialFalsifier
└── mcp            -> cmd_mcp()           -> mcp.server.run_mcp_server()
```

### Dependencies
- **Standard Library**: `argparse`, `json`, `sys`, `typing`
- **Internal Modules**:
  - `falsifier.AdversarialFalsifier`: Evaluates candidate memory dumps against known administrative and JIT profiles.
  - `sieve_deterministic.MalfindClassifier`, `MalfindAllocation`: Classifies raw memory allocations.
  - `logger.ExecutionLogger`: Standardized logging and status emission.

---

## Component Details

### 1. Subcommand Handlers

#### `cmd_triage(args: argparse.Namespace) -> int`
- **Purpose**: Dispatches offline disk/memory triage or live continuous host monitoring to `orchestrator.py`.
- **Arguments**:
  - `--deep`: Forwarded to orchestrator to enable deep forensic carving (EVTX, Registry, Prefetch, LNK).
  - `--live`: Forwarded to orchestrator to trigger live `/proc` and network socket telemetry monitoring.
  - `--interval`: Inspection window interval in seconds (default 30s).
- **Return**: Integer process exit code (0 on success).

#### `cmd_carve(args: argparse.Namespace) -> int`
- **Purpose**: Directs artifact extraction and carving pipelines via `extractor.py`.
- **Arguments**:
  - Flags for selective extraction: `--deep`, `--memory`, `--disk`, `--registry`, `--evtx`, `--prefetch`, `--lnk`, `--pcap`.
- **Return**: Integer process exit code.

#### `cmd_analyze_dump(args: argparse.Namespace) -> int`
- **Purpose**: Performs standalone deterministic analysis on a memory dump or carved binary slice.
- **Workflow**:
  1. Reads up to 4096 bytes from the specified dump file.
  2. Disassembles opcodes using `R2Wrapper` if radare2 is installed, or matches known byte sequences (e.g. `48b8` trampolines).
  3. Synthesizes a `MalfindAllocation` structure and classifies it via `MalfindClassifier`.
  4. Runs the `AdversarialFalsifier` to detect administrative false positives.
  5. Outputs findings to console or emits structured JSON when `--json` is supplied.
- **Exit Codes**: Returns `0` on successful analysis; returns `1` fail-closed if the file cannot be read.

#### `cmd_mcp(args: argparse.Namespace) -> int`
- **Purpose**: Launches the Model Context Protocol stdio server for AI host integration.
- **Arguments**:
  - `--transport`: Transport mechanism (`stdio`).

---

## Backward Compatibility & Invocation Modes

`main(argv)` checks incoming command-line arguments:
* If the first argument begins with legacy flags (`--deep`, `--live`, `--interval`), `main()` prepends `"triage"` automatically, ensuring existing scripts continue working without modification.
* If invoked with no arguments, it prints help and returns exit code 0.
