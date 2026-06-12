# Project Mantis: Agentic Framework (agent_v0.1.4)

Project Mantis is an autonomous digital forensics and incident response (DFIR) framework designed to accelerate the triage of volatile memory and disk images. It integrates Volatility 3 outputs with LLM-driven reasoning to identify and investigate malicious artifacts.

## 1. Architecture
Project Mantis follows a "Controller-Actor" agentic pattern:

*   **Orchestrator (`orchestrator.py`):** Acts as the central brain. It manages the LLM session, governs tool execution, and maintains the `thoughts.txt` ledger.
*   **Agent (`agent.py`):** The LLM integration layer (Gemini). It utilizes system instructions to strictly enforce a multi-step forensic triage protocol.
*   **MCP Server (`mcp_server.py`):** The tool interface layer. It acts as an abstraction for system-level operations (file parsing, Volatility execution, string carving).
*   **Extractor (`extractor.py`):** A pre-processing module that builds the environment context by running Volatility plugins and creating local cache files (JSON/text) to optimize downstream performance.
*   **Data Tier:** Evidence is cached as local JSON files and memory dumps, significantly reducing latency by preventing redundant heavy disk I/O.

## 2. Function
The primary function of Project Mantis is **automated behavioral triage**. 
* It discovers evidence (memory/disk), processes it into searchable caches, and executes a deterministic "Null Hypothesis" loop to evaluate suspicious PIDs.
* It offloads the cognitive burden of manual log correlation from the examiner to the LLM, which systematically checks PIDs for persistence (registry), execution (pstree/cmdline), and C2 activity (network/memory strings).

## 3. Current State
* **Automated Triage:** The framework can successfully transition from raw evidence to a finalized MITRE ATT&CK report.
* **Deterministic Logic:** The agent strictly follows the mandated per-PID heuristic loop (`pstree` -> `cmdline` -> `hive carve` -> `netscan` -> `memory carve`).
* **Caching Engine:** Native JSON filtering and regex carving utilize a cache-first approach (using MD5 hashes of queries), which allows the agent to process subsequent PIDs in milliseconds.
* **Fallback Mechanisms:** Includes pure-Python partition table parsing and recursive directory searching if standard forensic utilities (`mmls`, `icat`) are missing or fail.

## 4. Limitations and Missing Features
* **Output Truncation:** While the tool handles large JSON files via pagination/keyword filtering, it is limited to 8,000 characters per output. This could lead to information loss during massive investigation sets.
* **External Dependencies:** Heavily dependent on the presence of the `vol` (Volatility 3) binary and other sleuth-kit tools. If these are unavailable, the agent falls back to string searching, which is less precise than structured forensic analysis.
* **Memory Image Size:** The current architecture assumes a "Memory-to-Cache" extraction flow. For massive memory dumps (e.g., 64GB+), the `vol` memmap command may create significant local I/O stress.
* **Hardcoded Logic:** The "Null Hypothesis" and procedural loop are strictly defined in the `system_instruction`. While this ensures consistency, it reduces the agent's ability to "pivot" off-script if a novel, non-standard attack vector is identified.
* **Security/Verification:** The system relies on an examiner key to seal reports; however, there is no built-in verification mechanism for the integrity of the original evidence files themselves (no automated hashing/chain-of-custody logging at ingestion).