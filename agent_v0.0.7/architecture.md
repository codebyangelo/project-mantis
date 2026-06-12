# Project Mantis (agent_v0.0.7) Analysis

## 1. Architecture
Project Mantis follows a **hub-and-spoke agentic architecture** designed to manage resource-intensive Digital Forensics and Incident Response (DFIR) tasks via a constrained LLM environment.

*   **Orchestrator (`orchestrator.py`):** Acts as the central nervous system. It manages the lifecycle of the LLM session, handles system-level interrupts, performs native hardware-level calls (bypassing the agent if necessary), and enforces robust API error handling.
*   **The Agent (`agent.py`):** A wrapper for the Google GenAI SDK. It uses a strictly defined `system_instruction` to force a "step-by-step" reasoning process, ensuring the agent does not overwhelm the environment by calling too many tools simultaneously.
*   **Tooling Layer (`mcp_server.py`):** An MCP-like (Model Context Protocol) interface that provides the agent access to forensic evidence. It includes a "governor" to rate-limit interaction and enforce data size limits.
*   **Extraction Engine (`extractor.py`):** A sidecar utility that performs heavy lifting using the `Volatility` memory forensics framework.

## 2. Function
The framework is designed to automate the triage of memory dump files (`.raw`). Its primary purpose is to **bridging the gap between automated forensic analysis and LLM-driven intelligence**. 

It accomplishes this by:
*   **Contextualizing Evidence:** Converting large, complex forensic outputs (Volatility plugins) into digestible, cached snippets.
*   **Managing Cognitive Load:** Preventing the LLM from being flooded with data by enforcing character limits and requiring keyword-based filtering.
*   **Resource Throttling:** Managing heavy system IO (memory scanning) through a staged approach: "Tactical" (light) vs "Deep" (full) scans.

## 3. Current State
*   **Operational Readiness:** The system is functional and capable of initiating a "Hardware Choke" (deep extraction) when triggered by the agent.
*   **Safe Execution:** The `orchestrator` includes a retry mechanism for API calls, accounting for common 503/429 errors during high-volume processing.
*   **Workflow Enforcement:** The agent is successfully constrained to a sequential logic flow (Discovery → Playbook → PSTree → Surgical Analysis).
*   **State Persistence:** Evidence is cached locally on disk (`evidence_cache/`), allowing the agent to persist context across different conversational turns.

## 4. What it doesn't do (Limitations & Missing Features)
*   **Lack of Real-time Memory Analysis:** The system relies entirely on pre-computed or on-demand cached files. It does not perform "live" memory forensics; it only operates on the static `.raw` image provided in the configuration.
*   **Authentication/Security:** The script assumes the environment is trusted. There is no verification of the contents of the `evidence_cache` or the `/mnt/sift_ext4/` directory; it blindly processes whatever files are present.
*   **No Auto-Remediation:** While it can "find evil," it lacks a defensive implementation layer (e.g., automated PID killing, process suspension, or network socket closure). It is currently an "observability-only" agent.
*   **Fragile Error Recovery:** If an `extractor.py` subprocess fails catastrophically or writes malformed JSON, the `read_evidence_cache` function will likely fail to recover, as the error handling is generic (`print` and return string).
*   **No Multi-Agent Collaboration:** There is no mechanism for an agent to signal another instance or report results to an external SOC platform beyond the console log.