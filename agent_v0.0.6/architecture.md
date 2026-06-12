# Project Mantis: Agent v0.0.6 Analysis

This document outlines the architecture and current state of **Project Mantis**, a Digital Forensics and Incident Response (DFIR) agentic framework designed to automate the triage of memory images and disk forensics.

---

## 1. Architecture
Project Mantis follows a **decoupled RAG-style (Retrieval-Augmented Generation) architecture** designed for high-latency forensic environments:

*   **Data Tier (Offline):** The `extractor.py` utility processes raw forensic artifacts (memory images) into a structured `evidence_cache/` directory.
*   **Logic Tier (Tooling):** The `mcp_server.py` acts as a Model Context Protocol (MCP) bridge, providing the agent with file-system-level read and extraction capabilities.
*   **Intelligence Tier (Agent):** The `agent.py` uses Google’s Gemini API, constrained by strict system instructions to act as a DFIR analyst. It does not perform live analysis; it operates exclusively on the pre-processed cache.
*   **Orchestration Tier:** `orchestrator.py` manages the interactive session, binding the agent’s logic to the available forensic toolset.

---

## 2. Function
The primary purpose of Project Mantis is to **triangulate volatile memory data with static disk forensics**. It is designed to move from high-level "suspicious process" detection to low-level forensic verification:

1.  **Ingestion:** Cache static Volatility plugin outputs (process trees, command lines, network connections, and memory anomalies).
2.  **Autonomous Triangulation:** Use Large Language Model (LLM) reasoning to correlate network anomalies (e.g., `netscan`) with process behaviors (e.g., `pstree`) and memory injections (e.g., `malfind`).
3.  **Verification:** Pivot from memory insights to disk-level artifacts by carving specific files via Sleuth Kit (`icat`) for cryptographic verification (SHA-256).

---

## 3. Current State
*   **Operational:** The framework can successfully parse pre-extracted JSON memory logs.
*   **Extraction:** It has a working "disk-to-agent" pipeline using `icat` to extract files by inode directly from E01 disk images.
*   **Logic:** The agent is correctly configured with a temperature of `0.0` (deterministic) to ensure high-fidelity adherence to forensic heuristics (e.g., ignoring JIT memory artifacts).
*   **Modularity:** The tool is decoupled; `extractor.py` can be run independently to prepare data before the agent even initiates.

---

## 4. Limitations & Missing Features
As of version 0.0.6, the following items are absent or require attention:

*   **Lack of Automation in Pivoting:** Currently, the agent requires the user to prompt for an Inode number. There is no automated translation layer that converts a suspicious file path found in `cmdline` into its corresponding Inode number on the disk image.
*   **Static Memory Cache:** Because it relies entirely on the JSON cache, the agent cannot perform "deep dives" into specific memory regions that were not included in the initial `extractor.py` run without restarting the entire extraction process.
*   **No Incident Timeline:** The agent currently analyzes "snapshots." It lacks a temporal correlation feature to reconstruct an execution timeline (events relative to each other).
*   **Error Handling:** If the `icat` carve fails (e.g., invalid inode or disk image path errors), the agent receives a text response but lacks a "retry" mechanism to self-correct or look for alternative file locations.
*   **Tooling Scope:** Only a limited set of Volatility plugins (`pstree`, `cmdline`, `netscan`, `malfind`) are currently ingested. Plugins like `filescan` or `shimcache` are missing, which are vital for deeper persistence hunting.