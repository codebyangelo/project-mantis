# Project Mantis (agent_v0.1.2) Documentation

## 1. Architecture
Project Mantis is a **Modular Agentic Forensic Framework** built on a command-and-control loop between a Google Gemini LLM and a local Python-based execution environment.

*   **The Brain (`agent.py`):** Utilizes a Gemini Flash-Lite model with a strict system instruction set designed to enforce a deterministic state machine behavior. It communicates exclusively via JSON.
*   **The Orchestrator (`orchestrator.py`):** Acts as the central hub (the "Control Plane"). It manages the API boundary, logs thoughts, maintains the integrity of the findings via cryptographic hashing, and routes LLM-requested actions to the local execution tools.
*   **The Execution Plane (`mcp_server.py`):** A collection of wrapper functions that interface with system binaries (`grep`, `jq`, `strings`, `fls`, `icat`, `volatility`). It includes a "Visual Timer" to monitor I/O-heavy subprocesses.
*   **The Environment Builder (`extractor.py`):** Performs initial reconnaissance, evidence discovery, and cache generation (e.g., bodyfiles, registry maps, and Volatility JSON outputs) to ensure the agent has a structured data context to work with.

## 2. Function
Project Mantis is designed to perform **Autonomous Digital Forensics and Incident Response (DFIR)**. Its primary purpose is to ingest memory dumps and disk images, identify malicious artifacts (specifically memory injection and DLL hijacking), and produce a cryptographically verifiable MITRE ATT&CK-aligned report without human intervention during the heuristic analysis phase.

## 3. What it does in its current state
*   **Tri-State Context Mapping:** Automatically detects whether evidence is `HYBRID`, `MEMORY_ONLY`, or `DISK_ONLY` and builds the necessary environment.
*   **Heuristic Loop Execution:** Follows a strict, hard-coded workflow: identifying PIDs with `PAGE_EXECUTE_READWRITE` segments and performing a mandatory 4-step investigation (pstree, cmdline, hive carving, and memory string carving) for each PID.
*   **Cryptographic Reporting:** Upon conclusion of an investigation, it generates a report that is hashed and sealed using an examiner-provided key.
*   **Native Tool Integration:** Uses `jq` and `grep` for surgical data extraction from large forensic JSON caches, preventing memory overflow by enforcing size limits and truncation.

## 4. What it doesn't do (Limitations/Missing Features)
*   **Cross-Platform Support:** The framework is tightly coupled with Windows forensics (`windows.*` Volatility plugins, NTFS pathing, and Windows Registry structure). It is not currently capable of analyzing Linux or macOS images.
*   **Subprocess Cleanup:** While it handles execution via threads, the `run_with_timer` function explicitly avoids killing orphaned subprocesses to prevent state corruption, relying on the orchestrator to manage lifecycle, which could lead to zombie processes during abnormal terminations.
*   **Advanced Memory Reconstruction:** It lacks the ability to perform complex memory forensics (e.g., VAD tree analysis or advanced code-hooking detection) beyond what is exposed by standard Volatility JSON plugins.
*   **Resumability:** If the agent process is terminated mid-investigation, there is no state-saving mechanism to resume the loop from the current PID. It would require a full restart of the heuristic process.
*   **Evidence Validation:** It assumes the provided forensic images are trustworthy; there is no built-in integrity check for the source raw/E01 files before processing.