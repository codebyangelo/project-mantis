# Project Mantis: Agent Core v0.0.9.2 Analysis

This document outlines the architecture and current capabilities of the **Project Mantis** agentic framework, designed for autonomous DFIR (Digital Forensics and Incident Response) investigations.

---

### 1. Architecture
Project Mantis employs a **Modular Orchestrator-Agent-Tool** architecture:

*   **Orchestrator (`orchestrator.py`):** Acts as the central nervous system. It maintains the event loop, manages the API gateway boundary, enforces safety constraints (JSON schema validation), and executes system-level tool calls.
*   **Cognitive Core (`agent.py`):** Utilizes Google’s Gemini API (`gemini-3.1-flash-lite`) configured with a strict system instruction. It is forced into a deterministic, role-playing logic loop where it acts as a router rather than a general-purpose conversationalist.
*   **Execution Layer (`mcp_server.py`):** Acts as a bridge (MCP-like) between the LLM and the file system. It wraps volatile memory analysis tools with guardrails (rate limiting and payload size restrictions).
*   **Telemetry Layer (`extractor.py`):** A background utility that performs the heavy-lifting of Volatility plugin execution on raw memory images, converting binary output into searchable JSON cache files.

---

### 2. Function
The framework is designed to **automate the investigation of raw memory forensic images**. Its primary function is to:
*   Transition from manual analysis to an agentic, iterative loop where the AI decides which Volatility plugins to query based on previous findings.
*   Reduce "cognitive load" on human analysts by parsing complex memory artifacts and comparing them against pre-defined DFIR playbooks.
*   Enforce "Hardware Choking"—ensuring that the agent does not overwhelm the host system’s resources by aggressively throttling read requests and enforcing strict byte-count limits on data passed back to the LLM.

---

### 3. Current State
*   **Deterministic Control:** The agent successfully adheres to a strict JSON schema. It uses a "reasoning -> action -> plugin" loop that allows it to navigate through a multi-step investigation autonomously.
*   **Rate & Payload Governance:** The framework actively enforces a 5-second API cadence and implements "System Denials" if the LLM requests overly large data sets, forcing the agent to use keyword-based filtering instead.
*   **Integration:** The agent can load a `dfir_playbook.json`, perform cache lookups (via `read_evidence_cache`), simulate forensic inode hashing, and signal the orchestrator to trigger a human review once a finding is confirmed.
*   **Resilience:** The system includes retry logic for API gateway constraints (429/503 errors) and a JSON recovery mechanism for when the model drifts from the required output format.

---

### 4. Limitations and Missing Features
*   **Simulated Artifacts:** Much of the "active" forensic work (e.g., `extract_and_hash_inode`) is currently a placeholder simulation rather than a functional implementation of low-level disk/memory forensic code.
*   **Hard-coded Paths:** The system relies on absolute paths (e.g., `/mnt/sift_ext4/...`), making it non-portable and environment-specific. It will fail on any machine that does not mirror the development environment's directory structure exactly.
*   **Cache Fragility:** The cache build process (`extractor.py`) is decoupled from the agent's run-time; if the `evidence_cache` directory isn't pre-populated by the `extractor.py` script prior to execution, the agent's primary tool will return fatal errors.
*   **Lack of Direct Memory Interaction:** The agent does not run Volatility plugins in real-time; it relies entirely on the pre-built JSON cache. If the agent needs information not captured during the initial `extractor.py` build, it is functionally blind and has no way to dynamically execute new forensic commands.
*   **Security Boundary:** The "System Override" checks are implemented in Python logic (`if/else`) within the orchestrator; if the LLM were to successfully jailbreak the orchestrator's parsing logic, there is limited secondary sandboxing to prevent the agent from attempting arbitrary file access.