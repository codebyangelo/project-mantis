# Project Mantis: Agent Core v0.0.9 Analysis

This document outlines the architecture, functionality, and current state of **Project Mantis**, a deterministic, autonomous cybersecurity agentic framework.

---

### 1. Architecture
Project Mantis utilizes a **layered, closed-loop orchestrator architecture** designed to bridge Large Language Model (LLM) reasoning with deterministic system-level execution.

*   **Cognitive Core (`agent.py`):** Uses Google’s Gemini Flash model with strict system instructions to act as a routing engine rather than a chatbot. It is forced into a deterministic JSON-only output mode.
*   **Orchestrator (`orchestrator.py`):** Acts as the "Central Nervous System." It manages the API boundary, sanitizes LLM output (removing markdown), and maintains an **asynchronous autonomy loop** that allows the agent to chain commands without human intervention until a system limit or specific "break" condition is met.
*   **Execution Layer (`mcp_server.py` & `extractor.py`):** 
    *   `mcp_server.py` handles telemetry retrieval and enforces safety constraints (RPM throttling and data payload limits).
    *   `extractor.py` provides the hardware-level integration with the Volatility framework to perform deep-dive memory analysis.

---

### 2. Function
The primary objective of Project Mantis is the **autonomous forensic triage of memory images.** It is designed to:
1.  **Standardize Analysis:** Enforce the use of predefined DFIR (Digital Forensics and Incident Response) playbooks.
2.  **Govern Resource Consumption:** Protect against API rate limits and memory overflow (via "Hardware Choke" and "RPM Governor" mechanisms).
3.  **Automate Decision Making:** Allow the agent to iteratively pivot from broad scans (`pstree`) to targeted investigations (`malfind`/`netscan`) based on discovered artifacts.

---

### 3. Current State
*   **Autonomy Loop:** The framework successfully implements a "self-correction" loop. If the LLM generates an illegal action or broken JSON, the orchestrator detects the failure, injects an error prompt, and forces the agent to re-try without requiring human input.
*   **Safety Guards:** The `read_evidence_cache` tool actively monitors payload size. It prevents the loading of massive dumps (e.g., raw `netscan` output) and forces the agent to use keyword filtering to reduce data overhead.
*   **Orchestration Logic:** The agent is correctly configured to initialize by reading the `dfir_playbook.json` file as its first action.
*   **Hardware Integration:** The system includes a functional "Hardware Choke" that triggers `extractor.py` to run Volatility plugins on demand when a cache is missing.

---

### 4. Limitations and Missing Features
Despite the functional core, v0.0.9 has several gaps:

*   **Wiring/Connectivity:** While the tools are defined and passed to the agent, the current `orchestrator.py` logic effectively comments out or bypasses the actual tool execution (e.g., the `read_evidence_cache` execution is currently a "break" to the manual prompt). The framework is "wired" but not yet "live."
*   **Context Window Management:** Although the system denies large payloads, it does not currently support true context summarization. It relies on keyword filtering, which assumes the agent knows exactly which string to search for to identify a threat.
*   **Hardware/Memory Dependency:** The system is tightly coupled to specific hardcoded paths (`/mnt/sift_ext4/`). It lacks dynamic discovery of memory image locations.
*   **Lack of Persistence:** There is no long-term memory mechanism between agent sessions; if the process terminates, the "investigative state" (outside of the cache) is lost.
*   **Tool Complexity:** The `extract_and_hash_inode` tool is purely a stub and lacks actual implementation logic for filesystem interaction.