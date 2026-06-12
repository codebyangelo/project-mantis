# Project Mantis Analysis: Version v0.0.9.1

This document provides a structural and functional analysis of the Project Mantis framework, an agentic cybersecurity tool designed for autonomous forensic investigation.

---

### 1. Architecture
Project Mantis follows a **centralized orchestration pattern** that utilizes a closed-loop feedback mechanism between an LLM cognitive core and a local execution environment.

*   **Cognitive Core (`agent.py`):** Utilizes Google’s Gemini API with strict system instructions to act as a deterministic decision engine. It is configured with `temperature=0.0` to minimize hallucination.
*   **Orchestrator (`orchestrator.py`):** Acts as the "Controller" or "Middle-ware." It manages the API boundary, enforces JSON schema integrity, and maps LLM-generated instructions to actual system tool calls.
*   **Execution Layer (`mcp_server.py` & `extractor.py`):** A set of tool-specific functions that interface with the local filesystem (DFIR artifacts) and Volatility memory analysis plugins.
*   **Communication:** Interactions occur via an asynchronous loop where the agent outputs JSON, the orchestrator executes the corresponding local function, and the result is fed back into the agent to inform the next action.

### 2. Function
The framework is designed to **automate the triage and analysis of memory images** (DFIR). Its primary purpose is to:
1.  **Orchestrate forensic investigations** by following standardized playbooks.
2.  **Navigate massive datasets** (memory dumps) by using a caching system that prevents LLM context-window overflow.
3.  **Perform autonomous iteration:** The agent evaluates its own findings, decides on the next required forensic step (e.g., checking network connections after finding a suspicious process), and executes it without manual operator intervention.

### 3. Current State
*   **Operational Readiness:** The system is functional as a CLI-based agent. It successfully initializes a persistent session with the Gemini API.
*   **Constraint Enforcement:** The tool includes robust "API Governors," including:
    *   **Rate Limiting:** A 5-second cadence for tool execution to protect API quota.
    *   **Context Management:** Sophisticated logic to truncate or reject massive memory analysis outputs (`netscan`/`malfind`) unless the user specifies a keyword.
    *   **Payload Sanitization:** The orchestrator uses Regex to ensure the LLM output is strictly valid JSON.
*   **Hardware Interface:** The framework includes a native sub-process caller (`extractor.py`) that can trigger full, heavy memory parsing (the "Hard-Choke" mode).

### 4. Limitations and Missing Features
*   **Static Memory Pathing:** The `MEM_IMAGE` path is hardcoded in `extractor.py` (`/mnt/sift_ext4/evidence/Rocba-Memory/Rocba-Memory.raw`), making the tool inflexible for analyzing different images without manual code changes.
*   **No Persistence/Memory:** While the agent "thinks" through the investigation, it lacks a long-term memory store across sessions. Once the script exits, the investigative progress is lost unless manually reconstructed.
*   **Dependency on SIFT Workstation:** The tool relies on specific directory structures (e.g., `/mnt/sift_ext4/`) and external tools (Volatility, `vol`) being pre-configured in the environment. It lacks environment detection or self-configuration.
*   **Lack of Advanced Error Recovery:** If the `extractor.py` sub-process fails unexpectedly during a heavy operation, the orchestrator does not have a "smart" retry mechanism; it simply logs the error and potentially hangs or stalls the agent’s reasoning loop.
*   **Security of Execution:** The orchestrator runs as a privileged process calling `subprocess.run` based on instructions received from an external LLM. While the schema is constrained, an LLM jailbreak or successful prompt injection could technically lead to the execution of unintended commands within the host environment.