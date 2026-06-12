# Project Mantis (agent_v0.1.8) - Analysis

This document provides an architectural and functional analysis of **Project Mantis**, an autonomous DFIR (Digital Forensics and Incident Response) agentic framework.

---

## 1. Architecture
Project Mantis follows a **modular, state-machine-driven architecture** designed to bridge raw forensic data with LLM-based decision-making.

*   **Orchestrator (`orchestrator.py`):** Acts as the "Brain" and State Machine. It manages the investigation loop, triggers sub-tools, coordinates LLM interactions, and generates final reports.
*   **MCP Server (`mcp_server.py`):** Acts as the "Tool Interface." It provides secure, abstracted access to filesystem and forensic utilities (`volatility`, `fls`, `icat`, `strings`), ensuring path safety through validation.
*   **Extractor (`extractor.py`):** The "Data Preparation Layer." It parses raw disk/memory images, converts output into structured JSON caches, and performs initial registry mapping.
*   **Agent (`agent.py`):** The "Decision Layer." It interfaces with Google’s Gemini Flash-Lite model, enforcing Pydantic schemas to ensure structured, actionable outputs from the LLM.
*   **Infrastructure:** Uses a `CACHE_DIR` to minimize redundant processing (caching tool outputs) and a `logger.py` module to maintain a transparent, color-coded audit trail of operations.

## 2. Function
Project Mantis is designed to perform **automated memory and disk forensic triage** to identify malicious processes. Its core lifecycle involves:
1.  **Ingestion:** Locating forensic images (Memory/Disk) and establishing an investigation context.
2.  **Triage:** Parsing metadata (processes, connections, registry hives) into searchable JSON caches.
3.  **Heuristic Analysis:** Using an LLM to evaluate individual PIDs based on injected code (RWX memory), command-line arguments, registry anomalies, and network traffic.
4.  **Deep Carving:** Automatically escalating to memory string extraction if the LLM identifies suspicious network indicators that require further evidence.
5.  **Attestation:** Generating a final MITRE ATT&CK-mapped report with an integrity hash.

## 3. Current State
As of `agent_v0.1.8`, the framework is functional for:
*   **Automated Evidence Parsing:** Successfully extracts and caches `pstree`, `cmdline`, `malfind`, and `netscan` data.
*   **Deterministic Evaluation:** Iterates through identified PIDs with RWX (PAGE_EXECUTE_READWRITE) memory segments.
*   **Security Controls:** Implements path validation to prevent traversal attacks.
*   **Caching & Optimization:** Uses MD5 hashing for string carving results and JSON caching to ensure rapid re-evaluations.
*   **LLM Integration:** Successfully enforces a specific Pydantic response schema, ensuring the LLM returns consistent `verdict`, `confidence_score`, and `action` flags.

## 4. Limitations and Missing Features

### Limitations:
*   **Synchronous Execution:** The framework relies on blocking subprocess calls (`subprocess.run`). Large memory images may cause the orchestrator to hang or time out if the timeout settings are too restrictive.
*   **Scale Limits:** The system currently relies on local caching. On massive (terabyte-scale) disk images, the `fls` and `icat` operations may consume significant local disk space and I/O overhead.
*   **LLM Token Context:** The system truncates large outputs (8,000 characters). Very verbose forensic logs may lose critical evidence if it appears at the end of a long file.

### Missing Features:
*   **Concurrency:** Lack of asynchronous processing prevents the agent from investigating multiple PIDs in parallel.
*   **Advanced Rootkit Detection:** While it looks for RWX memory, it does not currently perform advanced kernel-level hooks or hidden process detection beyond `pstree` analysis.
*   **Full Remediation:** The agent is purely observational; it does not currently support automated remediation (e.g., killing the malicious PID or deleting the malicious artifact).
*   **Persistence Analysis:** While it parses registry hives, it lacks automated detection for advanced persistence mechanisms like WMI event subscriptions or BITS job analysis.