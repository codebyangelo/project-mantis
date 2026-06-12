# Project Mantis: Forensic Analysis Framework (agent_v0.1.6)

Project Mantis (referred to in-code as "Project Find Evil") is an agentic framework designed to automate the triage phase of Digital Forensics and Incident Response (DFIR). It leverages local tooling (Volatility 3, The Sleuth Kit) coordinated by a large language model (Gemini) to identify malicious activity in memory and disk images.

---

### 1. Architecture

The framework is built as a **Deterministic State Machine (FSM)** wrapped in an agentic orchestration layer. It is divided into four primary components:

*   **Orchestration Layer (`orchestrator.py`):** Acts as the central controller. It manages the investigation loop, holds the state of the analysis, and performs atomic commits of findings to the IOC store and reporting modules.
*   **Forensic Extractor (`extractor.py`):** A pre-processing suite. It consumes disk/memory images, runs various Volatility plugins, and generates JSON-formatted caches (`pstree`, `cmdline`, `netscan`, `malfind`, `registry_map`).
*   **MCP Server (`mcp_server.py`):** Provides the "Model Context Protocol" interface. It exposes specific, read-only analytical functions to the LLM agent, enforcing path traversal protection and secure execution of system commands.
*   **Agentic Core (`agent.py`):** A Pydantic-enforced Gemini client. It is constrained by a strict system prompt to act as a classifier, returning deterministic JSON objects (`AgentCommand`) based on the provided evidence.

---

### 2. Function
The framework is meant to automate the **"Hypothesis Generation and Validation"** cycle of DFIR. It performs the following logical workflow:
1.  **Ingestion:** Scans raw evidence and generates structural caches.
2.  **Triage:** Queries the `malfind` cache to identify processes with suspicious memory protections (`PAGE_EXECUTE_READWRITE`).
3.  **Heuristic Analysis:** Iterates through suspect PIDs, querying the orchestrator for PSTree, Registry, and Network evidence.
4.  **Verification:** Validates LLM-generated verdicts against actual memory string carves.
5.  **Reporting:** Generates formatted MITRE ATT&CK reports upon confirming malicious activity.

---

### 3. Current State
*   **Deterministic FSM:** The system successfully transitions through states (Evidence -> Triage -> Analysis -> Carving -> Conclusion).
*   **Tool Integration:** Fully functional integration with Volatility 3 (`vol`) and The Sleuth Kit (`fls`, `icat`).
*   **Security:** Implements `validate_path` to prevent path traversal when accessing evidence/cache directories.
*   **Caching Strategy:** Includes a transparent caching layer (`carve_cache`) that stores string-search results to prevent expensive re-computation of memory carves.
*   **Hardened Logging:** All LLM inputs and outputs, as well as tool execution metadata, are logged to `thoughts.txt` and `execution.log` for post-investigation forensic review.

---

### 4. Limitations and Missing Features

*   **Reliance on Static Extraction:** The `extractor.py` must be run manually or triggered initially to build the JSON caches. There is no "on-the-fly" extraction if a process is missed during the initial scan.
*   **Regex-based Filtering:** Memory carving relies on static Regex patterns for network indicators (`NETWORK`). It lacks advanced heuristic analysis for encrypted C2 traffic or protocol-agnostic anomaly detection.
*   **Hardware/Environment Coupling:** The framework relies on specific environment variables (`PFE_EVIDENCE_DIR`) and pre-installed binary dependencies (Volatility, TSK). It is not containerized or portable.
*   **Single-Threaded Bottleneck:** While `mcp_server` uses threading for timer-enforced execution, the FSM loop is strictly linear. Analyzing a large number of PIDs can be time-consuming, as it processes them sequentially.
*   **LLM "Blindness":** The agent only sees the first 1000–2000 characters of evidence provided in the prompt. While effective for simple IOCs, this truncation could miss complex, sprawling malicious scripts or long command-line arguments.
*   **Platform Specificity:** The logic is heavily biased toward Windows forensics (e.g., `registry.hivelist`, `windows.memmap`, `NTUSER.DAT` targeting). It is not currently suitable for Linux or macOS forensic analysis.