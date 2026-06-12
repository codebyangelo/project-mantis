This document provides an architectural and functional analysis of **Project Mantis, version agent_v0.2.4**, an agentic framework designed for autonomous digital forensics and incident response (DFIR).

---

### 1. Architecture
Project Mantis follows a modular, **Agent-Orchestrator-Triage** pattern:

*   **Orchestrator (`orchestrator.py`):** The central FSM (Finite State Machine). It manages the investigation lifecycle, iterates through suspect entities, invokes the LLM for analysis, and triggers secondary forensics (surgical carving) when requested by the agent.
*   **Agent (`agent.py`):** Encapsulates the Gemini API integration. It uses **Pydantic** for structured output, enforcing strict JSON schemas to ensure the orchestrator receives valid `AgentCommand` objects.
*   **Forensic Triage Engine (`sieve.py`):** A pre-processing layer that performs deterministic, rule-based scoring of system artifacts (processes, network connections, registry hives) to reduce the search space before hitting the LLM.
*   **Forensic Extractor (`extractor.py`):** A data preparation layer. It leverages `volatility3` and `sleuthkit` to extract metadata from memory and disk images, caching the results into JSON for analysis.
*   **MCP Server (`mcp_server.py`):** A "Tool-use" layer that provides the LLM (via the Orchestrator) with the ability to perform read-only forensic operations (e.g., carving strings from memory, reading cache files) to validate its own hypotheses.

---

### 2. Function
The framework is designed to **automate the triage phase of a forensic investigation**. Instead of requiring a human to manually inspect thousands of processes or files, Mantis:
1.  Ingests raw memory/disk images.
2.  Extracts system artifacts.
3.  Assigns risk scores based on heuristic signals (e.g., RWX memory segments, anomalous parents, LOTL binary usage).
4.  Queries an LLM to evaluate the most suspicious entities, optionally triggering "Deep Carving" (surgical memory/disk extraction) to confirm or deny threats.

---

### 3. What it does in its current state
*   **Automated Triage:** Automatically detects and correlates process, network, and registry artifacts.
*   **Surgical Deep-Carving:** When the LLM is unsure, it can request the system to perform targeted byte-level scans of memory (using VAD metadata) or disk inodes to find specific IOCs (URLs, DLL paths, etc.).
*   **Deterministic Filtering:** Efficiently handles small, Celeron-class hardware by using pre-compiled regex and lightweight JSON parsing.
*   **Mitre Mapping:** Automatically correlates findings to the MITRE ATT&CK framework.
*   **Evidence Integrity:** Implements a "Thought Ledger" (`thoughts.txt`) to maintain a chain of reasoning and document integrity (SHA-256 hashing of generated reports).
*   **Security Controls:** Enforces path validation to prevent directory traversal and uses `subprocess` timeouts to prevent resource exhaustion during analysis.

---

### 4. What it doesn't do (Limitations & Missing Features)
*   **Live Memory Acquisition:** The system relies on pre-acquired images (`.mem`, `.raw`) and cannot perform "Live" acquisition on a running production target.
*   **Full Automation:** The orchestrator requires a user to type "investigate" to kick off the FSM loop; it does not currently operate as a continuously running background monitor.
*   **Advanced Rootkit Detection:** While it looks for `PAGE_EXECUTE_READWRITE` and masquerading, it does not perform deep hidden-module detection (e.g., IRP hook detection, DKOM analysis) beyond standard `volatility` plugin output.
*   **Dynamic Playbook Execution:** It reads a `dfir_playbook.json`, but currently, the agent logic is hardcoded into the system instructions rather than dynamically fetching and executing complex multi-step forensic workflows from the playbook file.
*   **Concurrency:** The investigation loop is synchronous. Large disk images may result in blocking delays, even with the internal timeout mechanisms.
*   **Scalability:** The logic for building the "PID table" loads the entire cache into memory. While efficient for moderate images, this might struggle with massive enterprise memory dumps containing tens of thousands of processes.