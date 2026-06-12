# Project Mantis (agent_v0.0.3) Analysis

This document provides an architectural overview of **Project Mantis**, a specialized agentic framework designed for autonomous Digital Forensics and Incident Response (DFIR) triage on memory dumps.

---

## 1. Architecture
Project Mantis follows a **modular, tool-use-centric ReAct (Reason + Act) architecture**. It is composed of three primary layers:

*   **Orchestration Layer (`orchestrator.py`):** Acts as the central hub. It manages the CLI loop, handles file I/O for telemetry and cognitive logging, and acts as the gatekeeper for system resources and rate-limiting.
*   **Agentic Core (`agent.py`):** Utilizes the Google GenAI SDK (Gemini) to maintain a persistent chat session. It is constrained by a `system_instruction` that mandates an iterative investigation loop and enforces strict parameter requirements for tool usage.
*   **Tooling Layer (`mcp_server.py` + `orchestrator.py`):** Provides the agent with external capabilities, including restricted binary execution for environment validation and a file-based retrieval system for forensic telemetry.

---

## 2. Function
The primary objective of Project Mantis is to **automate the initial triage phase of a memory investigation**. 

Instead of a human manually parsing massive memory outputs, the agent is tasked to:
1.  **Formulate Hypotheses:** Document forensic reasoning in a persistent `thoughts.txt` file.
2.  **Navigate Data:** Query pre-cached forensic outputs (malfind, pstree, netscan) using targeted parameters to avoid token exhaustion.
3.  **Autonomous Investigation:** Work through the provided dataset to identify potential threats without requiring constant manual guidance.

---

## 3. Current State
*   **Operational Readiness:** The framework is fully initialized, including Gemini API integration and tool connectivity.
*   **Safety/Defensive Logic:** The system includes "Token Defense" logic that forces the agent to use a `search_term` for large forensic files to prevent context window overflows.
*   **Rate-Limiting:** The system implements intentional execution delays (e.g., 5-12 seconds) to respect API throughput (TPM) limits and avoid overloading the LLM backend.
*   **Transparency:** Every agentic "Thought" is persisted to disk, allowing for auditable post-incident reviews.
*   **Pipeline Integrity:** The `mcp_server` provides a built-in "dry-run" mechanism to ensure the underlying Volatility environment is active before processing data.

---

## 4. Limitations and Missing Features

### Current Limitations:
*   **Static Telemetry:** The tool relies on pre-generated text files (`windows_malfind_manual_verify.txt`, etc.) rather than performing real-time extraction from a raw `.dmp` file.
*   **Hard-Coded Constraints:** The agent is restricted to only three specific plugins, limiting its utility to high-level process and network discovery.
*   **Latency:** Due to API rate-limit defenses (the 12-second sleep timers), the investigation process is intentionally slow.
*   **Environmental Sensitivity:** If the `GEMINI_API_KEY` is missing or the `vol` binary is not in the system path, the agent fails immediately.

### Missing Features:
*   **Dynamic Parsing:** The framework lacks a direct interface to Volatility's raw output; it currently relies on manual ingestion of pre-processed reports.
*   **Advanced Forensic Capabilities:** The agent lacks the capability for registry analysis, code injection extraction, or timeline analysis—key components for a full-scale forensic investigation.
*   **Resiliency to Large Data:** While it blocks bulk ingestion, it lacks the ability to "scroll" or "paginate" through data, forcing it to rely exclusively on precise `grep`-style search terms provided by the agent.