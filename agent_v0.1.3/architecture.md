# Project Mantis: Universal Forensic Engine (v0.1.3) Analysis

Project Mantis is an autonomous agentic framework designed for digital forensics and incident response (DFIR). It leverages large language models (LLMs) to orchestrate forensic tool execution, automating the triaging of memory and disk images to identify anomalous behaviors.

---

### 1. Architecture
The system utilizes a **Controller-Worker pattern** consisting of four primary components:

*   **Orchestrator (`orchestrator.py`):** Acts as the central nervous system. It manages the interaction between the LLM and the local environment, maintains a "thought ledger" (logging), and enforces cryptographic integrity for generated reports.
*   **The Forensic Agent (`agent.py`):** A wrapper around Google’s Gemini API. It carries a rigid "System Instruction" that defines the toolset, enforces a deterministic state-machine workflow, and mandates a strict JSON output schema.
*   **MCP Server (`mcp_server.py`):** The tool interface layer. It provides the specific "abilities" the LLM can call (e.g., memory carving, cache querying, hive extraction). It features a threaded execution wrapper with a visual timer for long-running processes.
*   **Extractor (`extractor.py`):** The pre-processing engine. It discovers forensic evidence, calculates disk/partition geometry, generates `bodyfiles`, and performs initial bulk extraction (e.g., Volatility plugins) into cached JSON files.

---

### 2. Function
Project Mantis is designed to perform **autonomous heuristic investigation** of compromised systems. Its primary functions include:
*   **Environment Mapping:** Discovering raw evidence files and establishing a "tri-state" (Hybrid, Memory-only, or Disk-only) execution context.
*   **Automated Triage:** Iterating through memory-based threats (specifically `PAGE_EXECUTE_READWRITE` segments) by correlating process trees, command-line arguments, registry hive anomalies, and network connections.
*   **Reporting:** Synthesizing findings into a MITRE ATT&CK-mapped report, which is then cryptographically signed by an examiner.

---

### 3. Current State
*   **Autonomous Heuristic Loop:** The agent is fully functional in its "PID iteration" loop. It forces the LLM to process every PID identified by `malfind` one-by-one, following a strict A-F investigative pipeline.
*   **Zero-Dependency Parsing:** The framework relies on native Linux utilities (`grep`, `strings`, `fls`, `mmls`) rather than brittle dependencies like `jq`, allowing it to handle deeply nested or malformed forensic data output.
*   **Operational Safety:** The system includes a "Null Hypothesis" directive, forcing the agent to justify its findings and move on to the next process, preventing it from getting stuck on benign (e.g., JIT-compiled) legitimate software.
*   **Integrity Verification:** The system enforces an examiner signature process, hashing the final report and requiring a manual key entry to "seal" the document.

---

### 4. Limitations and Missing Features
*   **Orphaned Process Handling:** The `mcp_server.py` acknowledges that if a user interrupts a task, the subprocess may become orphaned. It lacks a formal SIGKILL/Cleanup mechanism for hanging external forensic tools.
*   **Disk Dependency:** While it handles "Memory-only" mode, its power is significantly limited without a linked Disk Image/Bodyfile, as many of its advanced heuristics rely on registry inode extraction (`extract_and_carve_hive`).
*   **Output Size Constraints:** The system has a hard-coded limit of 8,000 characters for cached queries to prevent the LLM's context window from being flooded by large forensic output, which may cause premature truncation of valid findings.
*   **Manual Intervention:** The system relies on an external "Examiner Key" for report signing, which is not currently managed via a secure vault (e.g., HashiCorp Vault), making the signature process purely symbolic rather than cryptographically robust in a production sense.
*   **Model Reliance:** Because it uses `gemini-3.1-flash-lite`, it is highly dependent on the model's ability to maintain state across long JSON-only conversations; if the model hallucinates the JSON schema, the orchestration loop can break.