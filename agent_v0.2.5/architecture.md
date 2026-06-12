This documentation analyzes **Project Mantis**, version **agent_v0.2.5**, a modular, AI-driven digital forensics and incident response (DFIR) framework designed to automate the triage of memory and disk images.

---

### 1. Architecture
Project Mantis follows a decoupled, component-based architecture organized into specific roles:

*   **Orchestrator (`orchestrator.py`):** The "brain." It manages the Finite State Machine (FSM), governs the logic flow, interfaces with the LLM API, and generates the final MITRE ATT&CK incident reports.
*   **Extractor (`extractor.py`):** The data ingestion layer. It processes disk and memory images using native forensic tools (`volatility3`, `fls`, `mmls`, `icat`), creates structured JSON caches, and performs initial registry mapping.
*   **Sieve (`sieve.py`):** The heuristic scoring engine. It analyzes aggregated data (process trees, command lines, network connections, memory anomalies) and performs a "Suspect Multi-signal Processing Triage" (SMPT) to rank entities by malicious potential.
*   **Agent (`agent.py`):** The AI interface. It leverages Pydantic for structured outputs (JSON schema enforcement), ensuring that LLM decisions are deterministic, type-safe, and mapped to the MITRE ATT&CK framework.
*   **MCP Server (`mcp_server.py`):** The tool-execution bridge. It handles path validation (preventing directory traversal) and provides specialized "surgical" tools like `SurgicalCarver` for memory/hive analysis.

---

### 2. Function
Project Mantis is designed to **autonomously perform triage on forensic evidence**. Its primary objectives are:
*   **Noise Reduction:** Automatically filter thousands of system events down to the most suspicious entities.
*   **Contextual Intelligence:** Use an LLM to evaluate suspicious processes, files, and registry hives against heuristic markers.
*   **Deep Investigation:** Perform "on-demand" surgical carving into suspicious memory segments or registry hives to extract indicators of compromise (IOCs) such as C2 URLs or data exfiltration paths.
*   **Reporting:** Standardize findings into professional-grade MITRE ATT&CK reports with executive summaries.

---

### 3. Current State
*   **Operational Maturity:** The framework effectively bridges static forensic analysis with dynamic LLM reasoning. It is capable of end-to-end processing (Extraction → Heuristic Scoring → LLM Verdict → Deep Carving → Final Report).
*   **Hardenings:** Includes input validation (`validate_path`) to prevent path traversal and uses strict Pydantic schemas to ensure the LLM returns consistent, machine-readable decisions.
*   **Heuristic Logic:** Features a robust set of predefined "SIG_" (Signal) flags, such as `SIG_RWX_INJECTION` and `SIG_DATA_LEAKAGE_INDICATOR`, allowing for automated detection of common attack patterns.
*   **Cache Management:** Implements unique and aggregate JSON caching, allowing the sieve to maintain historical perspective across multiple evidentiary files.

---

### 4. What it doesn't do (Limitations & Missing Features)
*   **No Automated Containment:** The tool is strictly analytical ("Find Evil"). It does not feature functionality to isolate infected hosts, kill malicious processes, or re-image systems.
*   **Dependency on External Tools:** It relies on the pre-existence of `volatility3`, `sleuthkit` (`fls`, `mmls`, `icat`), and `strings` on the host machine. If these are not installed or configured, the Extractor will fail silently or hang.
*   **Limited Correlation Scope:** While it can correlate process/disk/registry data, it does not perform deep temporal timeline reconstruction across disparate log formats (e.g., Windows Event Logs, Sysmon).
*   **API Pacing/Cost:** The framework is entirely dependent on the LLM (Gemini). While it implements a "4-second breather" to avoid API limits, it lacks a robust local fallback for private/air-gapped analysis if the cloud API is unreachable.
*   **Carving Depth:** The `SurgicalCarver` is specialized for VAD-based memory analysis and Registry carving. It does not perform full file-system carving for unallocated space or deep packet inspection (DPI) of PCAP files.
*   **Memory/Disk Image Preparation:** It requires raw image files to be present in the `EVIDENCE_DIR`. It cannot reach out to a network to acquire these images itself.