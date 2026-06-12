# Project Mantis: Agentic DFIR Framework (v0.1.5)

This document provides a technical analysis of **Project Mantis**, an autonomous agentic framework designed for Digital Forensics and Incident Response (DFIR) triage.

---

## 1. Architecture
Project Mantis is a **Modular State Machine** that interfaces between external forensic binaries and an LLM-based decision engine. Its architecture is divided into four primary layers:

*   **Data Acquisition Layer (`extractor.py`):** Acts as the ingestion engine. It maps forensic images (disk/memory), generates bodyfiles for file system mapping, and extracts registry hive metadata. It includes a "pure Python" fallback parser to maintain functionality when specialized tools like `mmls` are unavailable.
*   **Forensic Tool Layer (`mcp_server.py`):** A wrapper layer that provides safe, controlled interfaces to forensic tools (`volatility`, `strings`, `icat`). It implements path validation to prevent directory traversal and uses `threading` to enforce hard timeouts on potentially blocking operations.
*   **Orchestration Layer (`orchestrator.py`):** Manages the FSM (Finite State Machine) loop. It retrieves contextual evidence, manages communication with the LLM, and directs the sequential analysis of suspicious PIDs.
*   **Cognitive Layer (`agent.py`):** Utilizes Google's Gemini API to perform heuristic-based evaluations of collected forensic data. It enforces strict structural output using Pydantic models to ensure the system acts deterministically.

## 2. Function
The framework is designed to **autonomously triage compromised Windows environments**. Its primary function is to:
1.  **Map Evidence:** Scan memory and disk images to identify "interesting" processes (e.g., those with `PAGE_EXECUTE_READWRITE` memory segments).
2.  **Autonomous Investigation:** Query cached forensic output (pstree, cmdline, registry keys) to build a case against specific PIDs.
3.  **Heuristic Validation:** Consult the LLM to determine if a PID exhibits malicious intent or behavioral anomalies.
4.  **Reporting:** Generate MITRE ATT&CK mapped reports if a threat is confirmed, maintaining a "Thought Ledger" for transparency.

## 3. Current State
*   **Hardened Execution:** The framework successfully implements "Safe Tooling" patterns, ensuring that no `shell=True` subprocesses are used, and all file paths are validated against sandbox directories.
*   **Tri-State Mode:** The system can handle `MEMORY_ONLY`, `DISK_ONLY`, or `HYBRID` investigations by dynamically querying discovered evidence.
*   **Caching Mechanism:** The system aggressively caches results (e.g., `carve_cache`, `registry_map.json`) to minimize expensive computation during iterative analysis.
*   **Deterministic FSM:** The `orchestrator` loop follows a strict linear progression per PID, ensuring the LLM is not overwhelmed by providing too much data at once.

## 4. Limitations and Missing Features

### Limitations
*   **Volatility Dependency:** The framework relies heavily on `volatility` (specifically the `vol` binary). If the environment lacks this, many core triage features (pstree, malfind, etc.) will fail or return empty datasets.
*   **LLM API Sensitivity:** The agent is currently bound to the Gemini API. Network connectivity to Google services is a hard dependency for the cognitive layer to function.
*   **Memory Overhead:** While `carve_memory_strings` streams data to avoid RAM saturation, large memory images (`.raw` / `.mem`) still place heavy I/O pressure on the host system.

### Missing Features
*   **Self-Healing/Recovery:** If a specific tool fails (e.g., `vol` crashes due to image corruption), the current loop often terminates rather than attempting a secondary forensic recovery method.
*   **Multi-Agent Coordination:** The system acts as a single agent. It lacks the ability to spawn "specialist agents" (e.g., a dedicated "Registry Specialist" vs. a "Memory Specialist") for parallel processing.
*   **Full MITRE Coverage:** While the framework generates a MITRE report, the current mapping is static and not dynamically derived from the *entire* range of ATT&CK tactics found in the telemetry; it currently focuses primarily on Evasion and Persistence.
*   **True Sandbox Isolation:** The code validates paths but does not execute tools inside a containerized sandbox (e.g., Docker or gVisor), which is standard for analyzing potentially weaponized disk images.