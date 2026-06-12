# Project Mantis (Agent_v0.0.8) Technical Analysis

This document outlines the architecture and current state of **Project Mantis**, a specialized agentic framework designed for automated Digital Forensics and Incident Response (DFIR) against memory images.

---

## 1. Architecture
The system employs a **modular orchestration pattern** separating high-level reasoning from low-level system execution.

*   **Orchestrator (`orchestrator.py`):** Acts as the central hub. It manages the lifecycle of the LLM session, handles API fault tolerance (back-off/retry logic), and bridges the gap between the agent's intent and hardware-level execution.
*   **Agent Core (`agent.py`):** Encapsulates the Google Gemini-based intelligence. It uses structured `system_instructions` to force sequential tool usage and define a multi-phase investigation workflow.
*   **MCP Server (`mcp_server.py`):** A tool-interface layer providing controlled, "governed" access to cached forensic data and utilities.
*   **Evidence Extractor (`extractor.py`):** The heavy-lifting utility that interfaces directly with `volatility` (vol) to process `.raw` memory images into JSON cache files.

---

## 2. Function
Project Mantis is designed to perform **autonomous memory forensics**. Its primary function is to:
1.  **Orchestrate Investigation:** Move from environment discovery to targeted analysis using a defined playbook.
2.  **Govern Resource Consumption:** Enforce strict limits on LLM context windows (via character capping) and API traffic (via cadence governors) to manage the operational footprint.
3.  **Automated Extraction:** Transform high-resource Volatility memory scans into a searchable, cached format, allowing the agent to perform "Surgical RAG" (Retrieval-Augmented Generation) without overwhelming the context window.

---

## 3. Current State
*   **Operational Workflow:** The agent successfully moves through the defined phases:
    *   **Phase 1:** User triggers investigation; agent issues a signal to start the hardware-intensive extraction.
    *   **Phase 2:** The Orchestrator intercepts this signal, spawns a `subprocess` to build the cache, and re-primes the agent with the gathered context.
*   **Safety/Governor Implemented:** The system includes active "RPM (Requests Per Minute) Quotas" via `time.sleep` calls and payload size validation (e.g., denying full `netscan` outputs in favor of keyword-specific searches).
*   **Hardware Choke:** The framework effectively manages long-running processes, using a status-update loop to keep the user informed during memory parsing.

---

## 4. Limitations & Missing Features

*   **Hardcoded Environment Dependencies:** The system relies heavily on specific paths (`/mnt/sift_ext4/...`). It is not currently portable or "plug-and-play" across different forensic workstations.
*   **Limited Cache Intelligence:** The `read_evidence_cache` tool is a simple text parser. It does not perform semantic search or vector-based retrieval; it relies strictly on string-matching (`keyword in line`).
*   **Lack of Error Resilience in Parsing:** If a Volatility plugin returns malformed data or if a cache file becomes corrupted, the system handles the exception but lacks a mechanism to self-heal or re-run specific failed plugins.
*   **Static Playbook:** While there is a `read_dfir_playbook` function, the agent's actual logic is hardcoded in the `system_instruction` within `agent.py`. There is currently no dynamic integration where the playbook actually modifies the agent’s behavior.
*   **Single-Agent Bottleneck:** The framework is built for a single, linear agentic flow. It lacks parallel investigation capabilities, meaning it cannot cross-reference multiple memory samples or incident sources simultaneously.