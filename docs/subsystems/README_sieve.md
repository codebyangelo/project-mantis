# Comprehensive Analysis of `sieve.py`

## Overview
`sieve.py` is a highly specialized triage and pre-processing module designed for a forensic analysis orchestrator. It acts as a deterministic "sieve", filtering through large volumes of forensic artifacts (memory dumps, disk images, network captures) to identify, score, and prioritize suspicious entities for further review—likely by an LLM-based agent. 

The module is explicitly built with severe performance constraints in mind ("optimized for Celeron"). It entirely avoids heavy API calls during its initial analysis phases, instead relying heavily on pure string operations, pre-compiled regular expressions, and an aggregate scoring system to flag malicious indicators.

## Architecture & Phases
The script is structured into a top-down processing pipeline encompassing three distinct phases:

### Phase 0: Pre-Compiled Patterns and Constants
This section initializes static indicators of compromise (IOCs) and heuristic rules. By pre-compiling regular expressions and utilizing Python `set` objects for constant-time lookups, it achieves maximum execution speed.

*   **LOTL (Living Off The Land) Definitions**:
    *   `LOTL_BINARIES`: A set of native Windows executables frequently abused by attackers to evade detection (e.g., `powershell.exe`, `rundll32.exe`, `certutil.exe`).
    *   `LOTL_SUSPICIOUS_KEYWORDS`: Command-line arguments that transform a benign LOTL execution into a weaponized one (e.g., `-enc`, `bypass`, `downloadstring`, `decode`).
*   **Path & Process Masquerading**:
    *   `ANOMALOUS_PATH_FRAGMENTS`: Directories frequently used as malware staging or drop zones (e.g., `\temp\`, `\users\public\`).
    *   `PROTECTED_SYSTEM_NAMES`: A strict whitelist of core Windows processes (e.g., `svchost.exe`, `lsass.exe`). These are checked against legitimate `SYSTEM_PATHS` to detect process hollowing or masquerading.
*   **Process Lineage Heuristics**:
    *   `OFFICE_PARENTS` and `BROWSER_PARENTS`: Used to detect classic phishing and exploitation chains (e.g., Word or Chrome unexpectedly spawning a shell from `SHELL_CHILDREN`).
*   **Regular Expressions**:
    *   `RE_DOUBLE_EXT`: Detects double extensions commonly used to trick users (e.g., `document.pdf.exe`).
    *   `RE_TRUNCATED_EXE`: Detects truncated `.ex` extensions, often an artifact of memory parsing errors or stealth tactics.
    *   `KNOWN_GOOD_NET`: Whitelists benign network domains (Microsoft, Google, Apple) and private IP ranges to reduce false positives.

### Helper Functions (Zero API Calls)
A suite of purely deterministic string-operation functions for evaluating heuristics:
*   `_is_private_or_reserved(ip_str)`: Filters out RFC 1918 private IPs and loopbacks.
*   `_score_network(netscan_entries)`: Evaluates network connections for suspicious traits. Points are awarded for active external TCP connections, non-standard ports (deviating from 80/443), and open listening sockets exposed to the internet (`0.0.0.0`).
*   `_is_anomalous_path(path, img)`: Detects if a process is running from an unusual directory or using double extensions. Notably includes logic to bypass false positives from Microsoft OneDrive/Temp installers.
*   `_is_masquerading(img, path)`: Identifies if a critical system process name is being used from outside expected system directories (e.g., an `svchost.exe` running from `AppData`).
*   `_has_suspicious_lotl_args(img, args)`: Scrutinizes arguments for known scripting hosts (`wscript`, `mshta`) or tools like `certutil` being used to download/decode payloads.
*   `_is_script_execution(img, args)`: Flags uncompiled script executions (Python, JS, VBS).
*   `_has_anomalous_parent(...)`: Detects anomalous parent-child relationships, such as Microsoft Word spawning PowerShell.
*   `_is_expected_empty_cmdline(img)`: Checks if a process lacking command-line arguments is legitimately expected to be empty (like `smss.exe`), as opposed to being a hollowed process.

---

### Phase 1: Ingest & Index
This phase bridges the gap between raw forensic tool output and the Python script's internal representation.

#### `build_pid_table()`
It loads JSON cache files (generated beforehand by tools like Volatility) located in `CACHE_DIR`:
1.  **PSTREE**: Loads process tree data and flattens it recursively into a global `pid_table`. It extracts process image details and utilizes explicit `PPID` values to map parent-child relationships accurately into a `parent_map`.
2.  **CMDLINE**: Merges command-line arguments into the corresponding PID entries in the table.
3.  **NETSCAN**: Merges network connection details.
4.  **MALFIND**: Merges memory injection findings (e.g., VAD regions exhibiting `PAGE_EXECUTE_READWRITE` permissions).

---

### Phase 2: Deterministic Scoring
Applies a cumulative, rule-based scoring mechanism to memory processes based on the heuristics defined in Phase 0.

#### `score_pid_table(pid_table, parent_map)`
Iterates through all ingested processes and assigns a risk score along with discrete text tags called "signals":
1.  **RWX Injection (+100)**: Detects raw shellcode injection via `malfind`. Assigned `SIG_RWX_INJECTION`.
2.  **LOTL Weaponization (+80 or +10)**: High score for malicious arguments (`SIG_LOTL_SUSPICIOUS_ARGS`); minor score if the binary is merely present.
3.  **Script Execution (+70)**: High score for Python, JS, or VBS execution.
4.  **Masquerading (+60)** or **Anomalous Path (+40)**.
5.  **Network Anomalies**: Adds up to 50 points based on the results of `_score_network`.
6.  **Parent-Child Anomaly (+30)**: Detects macro/exploit execution.
7.  **Empty Command Line (+20)**: Indicator of process hollowing or injection.

The final score is hard-capped at 250 to avoid runaway composite scores. Returns a tuple of `(pid, score, signals)`.

---

### Phase 3: Entity Aggregation & Selection
This is the core orchestration function that unifies multi-source forensic evidence into a prioritized output list.

#### `get_suspect_entities(api_budget: int = 30)`
This function expands the scope beyond volatile memory processes to include disk artifacts and network streams. Its goal is to select the top entities, governed by an `api_budget` parameter, preventing token explosion when passing data to the LLM.

1.  **Memory Processes**: Incorporates the scored processes from Phase 2. Includes specific logic to deduct points and remove false positive masquerading signals for truncated `.ex` files if the arguments explicitly match the executable name.
2.  **Disk Artifacts (Bodyfile)**: Parses NTFS bodyfiles to find anomalous disk artifacts based on path analysis.
    *   *Malware Drop Zones*: Detects executables (`.exe`, `.dll`, `.ps1`) in `Temp` or `AppData` directories.
    *   *Data Leakage Indicators*: Identifies archives, documents, or deleted files in user directories. It explicitly flags `.lnk` files in the `Recent` folder, which is crucial for tracking USB execution or data exfiltration.
    *   Extracts and formats MACB (Modified, Accessed, Changed, Born) timestamps. Furthermore, it dynamically merges LNK string extractions if matching data exists in `lnk_data`.
3.  **Registry Hives**: Ingests pre-parsed registry mapping data for `SYSTEM`, `SOFTWARE`, and `NTUSER` hives to flag potential persistence mechanisms, assigning a base score of 90 to ensure they are manually reviewed.
4.  **Deep Forensics - EVTX (Event Logs)**: Ingests suspicious string hits from Windows Event Logs. Limits hits to 50 to prevent LLM token overflow.
5.  **Deep Forensics - Prefetch**: Ingests hits from Prefetch files (evidence of execution) and assigns a score of 85.
6.  **Deep Forensics - PCAP (Network)**: Ingests parsed PCAP streams containing suspicious strings, scoring them at 90.

**Filtering, Quotas, and Sorting:**
*   **Score Threshold**: All entities are aggregated and sorted by score in descending order. Any entity with a score below 60 is discarded.
*   **Deduplication**: A `seen` set tracks entities (by file path or ID) to ensure identical artifacts aren't processed twice.
*   **Diversity Quotas**: A `type_limits` dictionary enforces diversity in the output, preventing one class of artifact from consuming the entire LLM budget:
    *   Files: max 10
    *   Processes: max 15
    *   Registry, PCAP, Prefetch: max 5 each
*   The function halts and returns the list of `SuspectEntity` dictionaries once `api_budget` is reached.

## Bottom-Up Context
From a bottom-up perspective, `sieve.py` transforms raw bytes and OS-level properties into structured, heavily contextualized evidence blocks. It starts with raw IP addresses, file paths, and unparsed command lines, applying strict regexes and logic to flag isolated anomalies. These atomic anomalies are grouped by entity (like an `inode` or a `PID`). By combining network evidence with parent-child relationship evidence and memory allocation evidence, it synthesizes a single numeric score and textual "signal" (e.g., `SIG_RWX_INJECTION`). Ultimately, the orchestrator relies entirely on `sieve.py`'s prioritization to decide what small fraction of gigabytes of forensic data gets advanced analysis.
