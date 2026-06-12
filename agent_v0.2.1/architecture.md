This document provides an architectural and functional analysis of **Project Mantis (v0.2.1)**, a tool designed for automated forensic triage and threat detection within memory and disk images.

---

### 1. Architecture
Project Mantis follows a modular **Forensic Pipeline** architecture, separating data acquisition, heuristic filtering, and AI-driven classification.

*   **Extraction Layer (`extractor.py`):** Interfaces with external forensic tools (Volatility 3, `fls`, `icat`) to perform bulk data mining. It generates standardized JSON artifacts for subsequent analysis.
*   **Filtering/Heuristic Layer (`sieve.py`):** Acts as a performance-optimized "Sieve." It builds a comprehensive PID-indexed table and applies deterministic, rule-based scoring (Living-off-the-Land checks, path analysis, and network heuristics) to minimize the workload on the LLM.
*   **Classification Layer (`agent.py`):** A Pydantic-enforced wrapper around Google’s Gemini API. It takes processed heuristic data and provides a structured `AgentCommand` output.
*   **Orchestration Layer (`orchestrator.py` & `mcp_server.py`):** The "brain." It manages the Finite State Machine (FSM), handles secure file access (preventing path traversal), and generates the final MITRE ATT&CK-aligned forensic report.

### 2. Function
The core function of Project Mantis is **Autonomous DFIR Triage**. Its goal is to ingest raw forensic images (memory dumps and disk images) and identify malicious processes or artifacts (e.g., process injection, C2 communication, masquerading) without manual investigation. It performs:
*   **Automated Triage:** Sorting through hundreds of system PIDs to find high-probability threats.
*   **Heuristic Pre-sorting:** Using regex and logic to discard benign processes to conserve API budget.
*   **Contextual Analysis:** Cross-referencing PID activity (network, command line, memory protection) with external intelligence.

### 3. Current State
*   **Deterministic Filtering:** Successfully uses the "Sieve" (`sieve.py`) to reduce large process lists into a manageable list of "suspect PIDs" based on score.
*   **Sandboxed Access:** Implements basic path validation (`validate_path`) to ensure all file operations occur within authorized evidence and cache directories.
*   **Structured LLM Output:** Utilizes Pydantic to ensure the LLM returns strictly formatted, valid JSON, preventing malformed tool output.
*   **Dynamic Carving:** Capable of triggering deep memory analysis (`carve_memory_strings`) on-demand when the LLM determines a need to investigate network indicators.
*   **Integrity Verification:** Hashes generated reports to ensure forensic auditability.

### 4. Limitations and Missing Features
*   **Dependency on SIFT/External Tools:** The tool relies heavily on pre-installed forensic binaries (`vol`, `fls`, `icat`, `strings`). It will fail or crash if these are not in the environment path or configured correctly.
*   **API Pacing/Cost:** While the "Sieve" mitigates this, it remains dependent on the availability and performance of the Google Gemini API.
*   **False Positive Sensitivity:** Relying on basic `strings` output for memory carving can be noisy. The "null hypothesis" fallback in `carve_memory_strings` is an attempt to mitigate this, but it may miss sophisticated, fileless C2 traffic that does not manifest as clear network strings.
*   **Static Scoring Logic:** The heuristic scoring in `sieve.py` is hard-coded. While effective for common patterns, it is not "self-learning" and may struggle with advanced, obfuscated techniques that do not trigger the specific keyword/path lists defined.
*   **No Incident Response:** The framework is currently **read-only**. It identifies and reports threats but lacks the capability to perform remediation (e.g., process termination, file isolation, or memory dumping to external storage).
*   **Error Handling:** The tool catches many exceptions, but the state machine might enter an inconsistent state if a specific plugin (like `vol`) crashes mid-extraction without leaving a valid JSON cache.