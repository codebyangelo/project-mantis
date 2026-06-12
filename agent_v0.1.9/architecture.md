# Project Mantis (agent_v0.1.9) Architecture Overview

This document outlines the architecture and functional capabilities of Project Mantis, a specialized agentic framework designed for autonomous Digital Forensics and Incident Response (DFIR) triage.

---

## 1. Architecture
Project Mantis follows a **Deterministic State Machine (FSM) architecture** controlled by an LLM-based orchestrator. It is structured into four primary layers:

*   **Orchestration Layer (`orchestrator.py`):** Acts as the "Brain." It manages the FSM loop, maintains the thought ledger, communicates with the LLM for tactical decision-making, and generates final reports.
*   **Tool/MCP Layer (`mcp_server.py`):** Provides a secure sandbox interface for interacting with forensic tools (Volatility, TSK/SleuthKit, `strings`). It includes path validation to prevent traversal and handles cache queries.
*   **Intelligence Layer (`agent.py`):** A Pydantic-enforced Gemini agent. It uses structured JSON schema to ensure LLM outputs are programmatically actionable by the orchestrator.
*   **Data/Caching Layer (`extractor.py` & `config.py`):** Handles heavy-lift data processing. It pre-processes disk/memory images into JSON artifacts (PSTree, Netscan, Malfind) to reduce latency during the investigation phase.

---

## 2. Function
The primary purpose of Project Mantis is **Autonomous Threat Triage**. It is designed to:
1.  **Ingest** raw memory/disk forensic images.
2.  **Filter** high-volume system data for anomalies (e.g., `PAGE_EXECUTE_READWRITE` memory segments).
3.  **Validate** suspicious processes via cross-referencing multiple forensic artifacts (PSTree, Registry Hives, Command Lines, Network Connections).
4.  **Score** findings using an LLM to categorize processes as "malicious" or "benign."
5.  **Report** findings mapping to the MITRE ATT&CK framework.

---

## 3. Current State
As of version `0.1.9`, the framework is operational for automated triage:
*   **Deterministic Loop:** The agent iterates through PIDs found in `malfind` results.
*   **Artifact Correlation:** Successfully correlates process information (PID) across `pstree`, `cmdline`, `registry_map`, and `netscan`.
*   **Dynamic Carving:** Capable of triggering on-demand memory carving if network indicators (C2) are suspected.
*   **Security Controls:** Implements `validate_path` to restrict tool execution to `EVIDENCE` and `CACHE` directories.
*   **Resiliency:** Features a "Null Hypothesis" fallback where processes without definitive malicious signatures are cleared or flagged for human review.
*   **Integrity:** Produces SHA-256 integrity hashes for generated incident reports.

---

## 4. Limitations and Missing Features
The following features are currently missing or present limitations within the `v0.1.9` iteration:

*   **Dependency on Pre-Extraction:** The system relies on the `extractor.py` script being run successfully *before* the orchestration loop starts. It cannot trigger new deep forensic extractions on demand if a required cache file is missing (only for hive/string carves).
*   **Limited Memory Analysis:** Memory carving is limited to simple `strings` utility filtering. It lacks deep integration with Volatility 3 plugins for complex memory forensic techniques (e.g., DKOM detection or thread execution analysis).
*   **API/Network Reliance:** The system is heavily dependent on the Gemini API. If the LLM enters a failure loop or is rate-limited, the orchestrator fails back to a "benign" verdict, potentially creating false negatives.
*   **Single-Node Execution:** The architecture is currently designed for local forensic environments. It lacks multi-agent coordination or the ability to ingest distributed telemetry.
*   **Regex Limitations:** The memory carving mechanism relies on predefined regex patterns; it does not currently perform advanced heuristic or YARA-based scanning of memory dumps.
*   **Lack of Remediation:** While the tool identifies malicious threats, it does not have the capability to perform automated remediation (e.g., process termination, file deletion, or network isolation).