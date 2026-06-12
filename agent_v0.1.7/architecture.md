# Project Mantis (agent_v0.1.7) Analysis

This document outlines the architecture, functionality, and current state of **Project Mantis**, an agentic framework designed for automated Digital Forensics and Incident Response (DFIR).

---

## 1. Architecture
Project Mantis follows a modular, state-machine-driven architecture designed to interface between raw forensic data and LLM-based decision-making.

*   **Orchestrator (`orchestrator.py`):** Acts as the central "brain" or Finite State Machine (FSM). It manages the investigation loop, iterates through processes, and handles communication with the LLM agent.
*   **Agent (`agent.py`):** A wrapper for Google’s Gemini API, utilizing Pydantic to enforce strict JSON schemas for agent outputs, ensuring that the forensic verdict is machine-readable and predictable.
*   **MCP Server (`mcp_server.py`):** A security-hardened utility layer. It handles file I/O, subprocess execution (e.g., calling Volatility, `strings`, or `icat`), and provides a cached interface for querying forensic data.
*   **Extractor (`extractor.py`):** A preprocessing component that runs heavy-duty forensic plugins (Volatility) against memory and disk images to generate JSON cache files before the analysis loop begins.
*   **Infrastructure (`config.py`, `logger.py`):** Standardizes path management, logging, and environment variable handling.

---

## 2. Function
The primary purpose of Project Mantis is to **automate the identification of "Evil" (malicious behavior)** in memory and disk forensic images.

*   **Automation:** Instead of a human analyst manually searching through logs, the framework programmatically extracts key artifacts (PSTree, Cmdline, Netscan) and allows the LLM to traverse these relationships.
*   **Evidence Correlation:** It maps process IDs (PIDs) to registry hives and network connections to detect common attack patterns, such as Process Injection (RWX memory) or DLL Sideloading.
*   **Standardization:** It produces a structured MITRE ATT&CK-aligned report, reducing the time required to move from raw data to a formal forensic conclusion.

---

## 3. Current State
*   **Hardened Execution:** The system uses `threading` and timers to prevent runaway forensic processes, and implements path-validation logic to prevent directory traversal attacks.
*   **Deterministic Loop:** The FSM currently prioritizes a logical flow: 
    1. Extract triage data.
    2. Identify RWX anomalies via `malfind`.
    3. Loop through flagged PIDs.
    4. Query evidence caches (PSTree, Cmdline, Registry, Network).
    5. Optionally carve memory strings based on LLM feedback.
*   **Caching Layer:** Heavily relies on a `CACHE_DIR`. If a query has been performed before, the system retrieves it from the JSON cache, significantly speeding up the evaluation of multiple PIDs.
*   **Integration:** Successful integration with `gemini-3.1-flash-lite` using structured Pydantic schemas for consistent classification.

---

## 4. What it Doesn't Do (Limitations)
*   **No Automated Image Acquisition:** The framework assumes that memory and disk images are already present in the designated `EVIDENCE_DIR`. It does not perform live acquisition.
*   **Dependency on External Tools:** It relies on external forensic binaries (e.g., `vol`, `fls`, `icat`) being installed and properly configured in the host environment.
*   **Limited "Thinking" Depth:** While the FSM is deterministic, the reasoning capability is entirely dependent on the LLM’s ability to interpret the truncated text/JSON provided in the prompt.
*   **Non-Recursive Analysis:** The current carving mechanisms are largely flat. If an attack involves highly nested or obfuscated artifacts not captured by the initial `extractor.py` routines, the framework may miss them.
*   **Environment Sensitivity:** The system is heavily hardcoded for Windows-based forensic images (evidenced by the registry paths and specific Windows plugins). It is not currently a cross-platform forensic tool.