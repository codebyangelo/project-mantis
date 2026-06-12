# Project Mantis: Technical Analysis (Agent v0.0.9.3)

This document outlines the architecture and current state of **Project Mantis**, an agentic cybersecurity framework designed to automate Digital Forensics and Incident Response (DFIR) tasks using memory forensics tools (Volatility) and large language models (LLM).

---

### 1. Architecture
Project Mantis follows a **Mediated Autonomous Loop** architecture:

*   **Cognitive Core (`agent.py`):** Utilizes Google Gemini (`gemini-3.1-flash-lite`) with strict system instructions to act as a deterministic decision engine. It enforces a "Zero-Trust Triangulation" doctrine, requiring multiple data points before escalating findings.
*   **Orchestration Layer (`orchestrator.py`):** Acts as the central controller. It manages the interaction loop between the LLM and the local environment, handles API boundary protection (retry logic), and enforces JSON schema compliance.
*   **Tooling Layer (`mcp_server.py`):** Provides a Model Context Protocol-like interface. It acts as an abstraction layer between the agent and raw forensics data, enforcing telemetry constraints, rate limiting (RPM protection), and payload size limits.
*   **Data Acquisition Layer (`extractor.py`):** Handles the "heavy lifting" by executing native binary commands (Volatility) against memory images, converting output into cacheable JSON state files.

---

### 2. Function
The framework is designed to perform **autonomous memory forensics investigations**. Its primary goals are:
1.  **Reduce Analyst Fatigue:** Automating the triage of common memory forensic plugins (`pstree`, `netscan`, `malfind`).
2.  **Ensure Analytical Rigor:** Preventing premature conclusions by enforcing a multi-vector verification process (e.g., verifying a memory injection alert with network and process tree context).
3.  **Governance:** Using a "Human-in-the-loop" requirement for final malicious classification, preventing the agent from acting on false positives without oversight.

---

### 3. Current State
As of v0.0.9.3, the project is a functional prototype:
*   **Deterministic Routing:** The agent successfully operates in a loop, taking actions and receiving "system feedback" until it either requests a human review or hits a processing error.
*   **Rate Limiting & Safety:** Includes a 5-second cadence governor in the tool server to respect API quotas and a "hard cap" on payload sizes to prevent context window overflow.
*   **State Management:** The system uses a disk-backed `evidence_cache` to ensure that expensive forensic operations are performed only when necessary, with results persisting between steps.
*   **Failure Recovery:** Implements basic self-correction where it prompts the LLM to fix malformed JSON outputs if parsing fails.

---

### 4. Limitations & Missing Features
The following features are currently missing or present significant limitations:

*   **Static Hardcoding:** The `extractor.py` and `mcp_server.py` rely on hardcoded paths (`/mnt/sift_ext4/...`) and static directory structures, making the tool non-portable without manual environment setup.
*   **Simulated Functionality:** The `extract_and_hash_inode` function is currently a placeholder (simulated) and does not perform actual disk-to-memory forensic correlation.
*   **Error Handling (Forensic):** While there is an API boundary for errors, the forensics pipeline is fragile. If the Volatility tool fails to parse a malformed memory image, the agent receives an error string that it may not be equipped to resolve beyond "retry."
*   **Lack of Telemetry Depth:** The current allowed plugin list is quite narrow. It cannot perform advanced memory forensics tasks like VAD analysis, DLL injection auditing, or kernel-level rootkit detection.
*   **Token Efficiency:** The orchestrator transmits the current "system feedback" back into the chat session repeatedly. For long investigations, this may lead to high token consumption even with the payload size caps in place.