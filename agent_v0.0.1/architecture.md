# Project Mantis: Agent Framework Analysis (agent_v0.0.1)

This document provides an architectural and functional analysis of **Project Mantis**, a nascent agentic framework designed to assist in Digital Forensics and Incident Response (DFIR) by triaging memory artifacts.

---

### 1. Architecture
Project Mantis utilizes a **ReAct (Reasoning + Acting) loop** architecture, leveraging a centralized orchestrator to bridge an LLM (Gemini) with local forensic tools and data sources.

*   **Orchestrator (`orchestrator.py`):** Acts as the central nervous system. It manages the CLI, enforces security/throttling constraints, handles tool execution requests from the agent, and manages the session lifecycle.
*   **Cognitive Engine (`agent.py`):** Utilizes the Google GenAI SDK (`gemini-1.5-flash-lite`) to process incoming triage requests. It is governed by a strict `system_instruction` that mandates iterative reasoning and enforces tool usage protocols.
*   **MCP Server Simulation (`mcp_server.py`):** A wrapper for interaction with the Volatility 3 framework. It currently acts as a safety bridge to ensure binary availability.
*   **Telemetry Interface:** The system relies on "manual verify" text files as proxies for actual memory analysis output, acting as a structured database for the agent to query.

---

### 2. Function
The framework is designed to automate the initial stages of memory forensics. Its intended function is to:
1.  **Autonomous Investigation:** Accept high-level triage commands (e.g., "Find the malware") and decompose them into actionable technical steps.
2.  **Telemetry Triage:** Query pre-parsed forensic data files (`pstree`, `netscan`, `malfind`) to identify suspicious PIDs, network connections, or memory injections.
3.  **Auditable Reasoning:** Force the agent to document its "thought process" into a persistent file (`thoughts.txt`) for later review by a human analyst.
4.  **Resource Management:** Enforce strict API token limits and rate-limiting to ensure the agent doesn't crash or trigger rate-limit blocks from the LLM provider.

---

### 3. Current State
*   **Operational Readiness:** The agent is fully initialized, connected to the Gemini API, and capable of executing the ReAct loop.
*   **Tooling:** 
    *   **Cognitive Logging:** Functional (`record_cognitive_process` successfully commits to disk).
    *   **Forensic Retrieval:** Functional with search/filtering capabilities.
    *   **Safety Interlocks:** Implemented. The system successfully blocks large-payload ingestion of `pstree` and `netscan` to protect the LLM’s context window.
*   **Throttling:** Proactive rate-limiting (12-second sleeps) is integrated into the `query_forensic_evidence` function to defend against API TPM (Tokens Per Minute) exhaustion.
*   **Resiliency:** Basic retry logic (3 attempts) exists for 503 Service Unavailable errors.

---

### 4. Limitations & Missing Features
The current iteration (v0.0.1) is a prototype with several significant constraints:

*   **Static Data Dependency:** The agent currently relies on pre-created static text files (`*_manual_verify.txt`) rather than performing real-time analysis of live memory dumps.
*   **Limited Plugin Access:** While the `mcp_server.py` exists to bridge to live tools, it is currently locked to `[plugin] -h` (help documentation). It cannot yet execute meaningful analysis commands on raw memory images.
*   **Lack of Deep Analysis:** The agent is explicitly barred from registry parsing, file system metadata, or string extraction, limiting its ability to perform comprehensive "deep" forensics.
*   **Primitive Error Handling:** The "fatal error" handling for missing binaries is basic and terminates the session; there is no automated recovery or "safe mode" for the MCP server.
*   **Single-Turn Persistence:** While thoughts are logged, the agent's memory of the *results* of forensic queries relies entirely on the model's context window; there is no persistent database of "known evil" findings for the agent to reference across long-running sessions.