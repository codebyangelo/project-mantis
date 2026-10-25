# mcp_server.py - Detailed Documentation

## 1. Overview
The `mcp_server.py` module acts as a highly specialized, secure execution engine and forensic analysis controller within the Mantis DFIR (Digital Forensics and Incident Response) agent framework. It provides a robust interface for interacting with forensic artifacts, memory images, disk timelines, and system registries. By combining bounded command execution, targeted parsing of volatile/non-volatile forensic cache files, and surgical memory/hive carving techniques, the server enables complex forensic queries without risking context pollution, path traversal, or runaway processes.

## 2. Dependencies and Environmental Context
The module relies on the following standard and internal libraries:
- **Standard Libraries**: `subprocess`, `os`, `json`, `time`, `sys`, `threading`, `hashlib`, `re`, `typing` (`List`, `Tuple`, `Set`).
- **Internal Modules**: 
  - `config`: Imports `EVIDENCE_DIR`, `CACHE_DIR`, `PLAYBOOK_PATH`.
  - `logger`: Imports `ExecutionLogger` for structured, centralized logging of all critical actions and security events.

## 3. Architecture & Security Mechanisms

### Top-Down Architecture
The script operates primarily on a procedural basis with one major object-oriented component (`SurgicalCarver`). It functions as a middleware layer between the higher-level agent reasoning engine and the raw forensic data/system binaries (like `volatility`, `icat`, `strings`). 

### Bottom-Up Security & Safety
- **Path Traversal Prevention**: Strict real-path validation ensures that all file operations are confined within the `EVIDENCE_DIR` and `CACHE_DIR`. 
- **Timeouts and Process Control**: Subprocess execution is wrapped in a strict timing model (`run_with_timer`) preventing infinite hangs during forensic tool execution.
- **Data Truncation**: Memory carving and cache querying functions are strictly bounded (e.g., maximum returned string lengths, maximum scan sizes, max results caps) to prevent overwhelming the context window of the LLM consuming the data.

---

## 4. Function Breakdown & Extreme Detail

### 4.1 Path Security & Validation
#### `validate_path(path_str: str) -> str`
- **Purpose**: Prevents path traversal vulnerabilities (e.g., `../../../etc/shadow`) by ensuring any provided path resolves entirely within allowed directories.
- **Mechanism**:
  - Checks for string validity and null byte (`\x00`) injection.
  - Uses `os.path.realpath` to resolve symlinks and relative references.
  - Compares the base of the resolved path against `os.path.realpath(EVIDENCE_DIR)` and `os.path.realpath(CACHE_DIR)` using `os.path.commonpath`.
  - Raises a `ValueError` if the boundary is breached and logs the attempt.
- **Output**: Returns the securely validated absolute path.

### 4.2 Subprocess Execution Engine
#### `run_with_timer(cmd: list, task_name: str, timeout_sec: int = 300) -> str`
- **Purpose**: Executes underlying OS and forensic commands safely.
- **Mechanism**:
  - Accepts a command vector (`list`) preventing shell-injection (uses `shell=False`).
  - Implements a strict timeout parameter (default 300s).
  - Captures `stdout` and `stderr`. If a command fails (non-zero return code), logs the error but still returns partial standard output if available.
  - Propagates timeouts and OS exceptions up the chain.
- **Logging**: Highly verbose; logs command start, vector payload, execution time, and outcome.

### 4.3 Context & Data Retrieval
#### `get_evidence_context() -> str`
- **Purpose**: Fetches the global forensic context built by initial extraction tools.
- **Mechanism**: Checks for `context.json` inside the `CACHE_DIR`. If found, reads and returns it. If not, returns a static JSON string indicating the context is missing.

#### `resolve_username_from_pid(pid: str) -> str`
- **Purpose**: Correlates a given Process ID to a specific Windows username.
- **Mechanism**:
  - First attempts to parse `cmdline.json`. It iterates through entries matching the PID and runs a regex (`[uU]sers[\\/]([^\\/]+)`) against the process arguments to extract the username.
  - If `cmdline.json` fails or is missing, falls back to `pstree.json`. It recursively searches the process tree nodes for the matching PID and applies the same regex to the process execution path.
- **Output**: Returns the username string, or an empty string if unresolvable.

#### `query_json_cache(cache_name: str, keyword: str = "") -> str`
- **Purpose**: A universal querying mechanism for cached JSON artifacts. Incorporates intelligent routing and specialized forensic logic.
- **Mechanism**:
  - **Sanitization**: Validates `cache_name` with `^[a-zA-Z0-9_]+$`.
  - **Special Handler - `registry_map`**: If the target is the registry map and a PID is provided as the keyword, it dynamically calls `resolve_username_from_pid(pid)` to narrow down `NTUSER` hives to only the relevant user's hive, alongside `SYSTEM` and `SOFTWARE`. This drastically reduces noise.
  - **Special Handler - `malfind`**: If looking for `PAGE_EXECUTE_READWRITE` in malfind output, it iterates through the cache and specifically extracts PIDs possessing RWX memory segments.
  - **General JSON Search**:
    - If no keyword is provided, returns raw text but blocks payloads over 50,000 bytes.
    - If the cache is a list of dictionaries, searches keys and values for case-insensitive keyword matches.
    - Truncates output gracefully at 8000 characters to prevent context-bleeding, appending `[!] OUTPUT TRUNCATED`.
    - If the file is not valid JSON, it falls back to standard line-by-line text matching (grep style).

### 4.4 Disk & Physical Artifact Carving
#### `extract_and_carve_hive(inode: str, disk_image_path: str) -> str`
- **Purpose**: Direct physical extraction and string-carving of registry hives from a raw disk image bypassing the OS.
- **Mechanism**:
  - Validates the inode format (digits/hyphens) and disk path.
  - Chains `icat -i ewf <image> <inode>` into `strings -el` (little-endian 16-bit strings, typical for Windows registry).
  - **Anomaly Detection Logic**:
    1. **Malware Persistence**: Looks for `.dll` references in `c:\` paths. Excludes standard directories (`system32`, `winsxs`, etc.) to isolate anomalous/injected DLLs.
    2. **Data Leakage**: Scans for specific drive letters (`[d-z]:\\`) or document extensions (`.pdf`, `.xlsx`, etc.), excluding standard Microsoft/Appdata paths. Caps lines to <150 chars to filter out garbage bytes.
  - Enforces a 120-second timeout on the pipe operation.

### 4.5 Advanced Surgical Memory Carving
The script employs a highly sophisticated, disk-less memory carving system to extract IOCs (Indicators of Compromise) directly from raw memory images.

#### `class SurgicalCarver`
- **Purpose**: Targeted string extraction using Volatility `malfind` VADs (Virtual Address Descriptors) and `memmap` metadata without writing intermediate dumps to disk.
- **Methods**:
  - `_run_memmap_meta(pid, timeout)`: Invokes Volatility 3's `windows.memmap` tool, extracting just the memory layout metadata in JSON format (no dumping).
  - `_get_suspicious_vads(pid)`: Identifies anomalous memory regions (RWX / Write-Copy) from the `malfind` cache and extracts their virtual start and end addresses.
  - `_coalesce_ranges(ranges)`: Optimization algorithm that merges overlapping or adjacent memory physical offsets to minimize disk I/O operations.
  - `carve_pid(pid, ioc_regex, max_matches)`: 
    - Maps the suspicious virtual address spaces (VADs) to physical offsets using the `memmap` metadata.
    - Opens the raw memory image.
    - Seeks to the exact physical offsets of the injected/suspicious pages and reads in chunks of 256KB.
    - Applies regex pattern matching for ASCII strings (`[ -~]{8,}`) and then searches for the specific IOC.
    - Limits matches to prevent overwhelming the AI context.
  - `carve_pid_committed_fallback(...)`: Fallback routine if no suspicious VADs are flagged. Scans all committed memory for the PID, bounded by a strict 50MB budget (`total_budget`).

#### `carve_memory_strings(regex_pattern: str, memory_image_path: str, pid: str = "NONE") -> str`
- **Purpose**: Wrapper function exposing the `SurgicalCarver` to the wider MCP interface.
- **Mechanism**:
  - Validates PID string.
  - Provides a built-in macro for network indicators: If `regex_pattern` is "NETWORK" or contains "http", it dynamically injects an advanced regex to catch URLs and IP addresses.
  - Executes the carver and returns the report.

### 4.6 Supporting Forensics Functions
#### `read_dfir_playbook() -> str`
- Reads the incident response playbook directly from `PLAYBOOK_PATH`, returning its contents or a warning if missing.

#### `search_disk_timeline(keyword: str) -> dict`
- **Purpose**: Scans timestamped timeline caches (MFT and Bodyfile).
- **Mechanism**:
  - Iterates over all files in `CACHE_DIR` prefixed with `bodyfile_` or `mft_`.
  - Performs line-by-line streaming reads to avoid memory bloat.
  - Special PID matching: If the keyword is purely digits (PID), it parses the pipe-delimited timeline format to ensure the PID matched in the correct column, reducing false positives.
  - Hard limit of 200 returned lines to prevent context window saturation.

## 5. Execution Logging & Telemetry
Every function inside `mcp_server.py` relies heavily on `ExecutionLogger.log()`. This establishes a continuous, auditable trail of:
- Tool execution parameters.
- File and cache access.
- Security enforcement actions (path blocks, cache sanitization).
- Successful anomaly detection (e.g., specific RWX segments found, malicious DLLs carved).
- Performance metrics (subprocess execution timing).

This telemetry is essential for debugging the autonomous agent behavior and generating post-incident forensic reports.
