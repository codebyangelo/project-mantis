# Project Mantis (agent_v0.0.4) - Architecture & Analysis

This document provides a technical breakdown of the 'Project Mantis' forensic agent framework, which automates the triage of memory dumps and E01 disk images using a combination of heuristic analysis and an LLM-based ReAct agent.

---

### 1. Architecture
Project Mantis follows a modular **Orchestrator-Agent-Tooling** architecture:

*   **Orchestration Layer (`orchestrator.py`):** Acts as the central controller. It manages state persistence, executes low-level forensic tooling (Volatility/SleuthKit), and implements the initial three-phase triage pipeline.
*   **Cognitive Layer (`agent.py`):** A wrapper around the Google Generative AI SDK (`gemini-3.1-flash-lite`). It uses a specific system prompt to guide the AI through a ReAct (Reasoning and Acting) loop, allowing the model to decide which tools to invoke based on forensic findings.
*   **Tooling Layer (`mcp_server.py` & helper functions):** A collection of discrete functions exposed to the LLM (MCP-style). These tools bridge the gap between the LLM's reasoning and the host OS's forensic binaries (Volatility `vol` and The Sleuth Kit `fls`/`icat`).
*   **Persistence Layer:** Uses `findevil_triage_profile.json` as a "Source of Truth" cache, allowing the agent to resume analysis without re-running time-consuming forensic scans.

---

### 2. Function
The framework is designed to **autonomously perform DFIR (Digital Forensics and Incident Response) triage** on potentially compromised Windows systems. Its primary goals are:
1.  **Reduce Manual Noise:** Automated filtering of common "JIT-heavy" false positives (e.g., Chrome/Teams memory pages) and benign app-local deployments (e.g., `api-ms-win` DLLs).
2.  **Autonomous Investigation:** Instead of providing raw data, the agent correlates command-line arguments, process hierarchies, and memory anomalies to build a hypothesis.
3.  **Advanced Verification:** Automatically performs forensic "strikes" such as verifying DLL sideloading by hashing files extracted directly from the E01 image.

---

### 3. Current State
*   **Multi-Phase Automation:** The engine successfully completes three distinct phases: (1) In-memory mapping, (2) Heuristic flag detection (LOLBins/Path checking), and (3) Targeted forensic strikes (`malfind`/`fls`).
*   **Tool Exposure:** The agent is fully integrated with tool-calling capabilities, specifically allowing it to request file extractions, hash computations, and profile queries.
*   **Heuristic Logic:** The agent possesses advanced, context-aware rules (e.g., distinguishing between legitimate garbage-collected VAD regions and actual injections).
*   **Stateful Memory:** The agent utilizes `thoughts.txt` to log its internal reasoning, providing an audit trail for the investigator.

---

### 4. Limitations & Missing Features

*   **API Dependence:** The system relies entirely on external Google GenAI connectivity. If the API is rate-limited or the network is unreachable, the investigation halts.
*   **Static Tooling:** The framework assumes `vol` (Volatility) and `fls/icat` (SleuthKit) are installed in the host's system PATH. It lacks a self-contained environment (e.g., Docker containerization) to ensure binary compatibility.
*   **Limited Forensics Scope:** 
    *   **Registry/MFT:** The current version ignores Registry hives and the Master File Table (MFT), which are crucial for detecting persistence mechanisms (RunKeys, Services).
    *   **Network Artifacts:** The agent lacks analysis for network connections or ARP cache entries, which are vital for C2 (Command & Control) detection.
*   **Single-Image Constraint:** It is hardcoded to specific paths (`/mnt/sift_ext4/...`). A more robust implementation would require a configuration file or CLI arguments to dynamically set evidence paths.
*   **Error Handling:** While there is logic for `subprocess` failures, complex forensic edge cases (e.g., encrypted partitions or corrupted images) may crash the orchestrator loop.