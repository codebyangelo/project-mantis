This document provides an architectural and functional analysis of **Project Mantis, version agent_v0.2.0**.

---

## 1. Architecture
Project Mantis follows a modular, agentic pipeline designed to process digital forensic images (memory/disk) through a deterministic-to-probabilistic orchestration layer.

*   **Orchestration Layer (`orchestrator.py`):** Acts as the "Brain," managing the state machine loop. It handles LLM interaction (via Gemini), coordinates between the data cache and the agent, and generates the final MITRE ATT&CK report.
*   **Data Processing Layer (`mcp_server.py` & `extractor.py`):** The "Sensors." It interacts with forensic tools (Volatility, TSK/The Sleuth Kit) to ingest raw disk/memory images, build JSON-formatted caches, and provide safe, read-only access to this telemetry for the agent.
*   **Heuristic Layer (`sieve.py`):** The "Filter." It serves as a pre-LLM processor that calculates a numerical threat score for processes based on static anomalies (e.g., LOTL binaries, masquerading paths, parent-child relationships).
*   **Agentic Layer (`agent.py`):** The "Classifier." Utilizes a structured Pydantic-enforced LLM interface to make final verdicts based on the evidence presented by the Orchestrator.

---

## 2. Function
Project Mantis is designed for **Autonomous Digital Forensics and Incident Response (DFIR) Triage**. Its core purpose is to:
1.  **Ingest** large forensic images (RAM dumps/Disk images).
2.  **Triage** processes to isolate potential threats by reducing the search space from thousands of processes down to a small, manageable "high-suspect" set.
3.  **Evaluate** these suspects using a combination of deterministic heuristics and LLM-based reasoning.
4.  **Report** findings mapping to the MITRE ATT&CK framework, providing justifications and severity levels for human responders.

---

## 3. Current State
*   **Heuristic Pre-filtering:** The system effectively uses `sieve.py` to calculate PID-based threat scores (0-250 range) using multi-factor signals (RWX memory, LOTL args, parent anomalies).
*   **Deterministic FSM:** The `orchestrator` implements a strict loop that prevents the LLM from making uncontrolled calls; it only exposes specific cached data or limited forensic functions.
*   **Evidence Handling:** It successfully links physical disk inodes (registry hives) to process behavior and supports volatile memory carving for network artifacts.
*   **Agentic Constraints:** The use of `Pydantic` schemas for LLM responses forces the model to adhere to a strict classification output, minimizing "hallucination" in the verdict logic.

---

## 4. What it doesn't do (Limitations & Missing Features)
*   **Deep Memory Analysis:** While it can carve strings, it lacks advanced memory analysis capabilities found in mature platforms (e.g., heap analysis, object tracking, or cross-referencing thread structures).
*   **Full Automation:** The tool is not designed to be "self-healing." It stops at "Report Generation," assuming a human will review the "Suspicious" categorized entities.
*   **Real-time Response:** It is a post-mortem tool. It is not currently architected to perform live response (e.g., killing malicious processes or quarantining files on a live system).
*   **Dependency on External Tools:** The functionality is entirely dependent on the pre-existence of `vol` (Volatility) and `fls`/`icat` (The Sleuth Kit) on the host machine. If these tools fail or are missing, the entire extraction phase breaks.
*   **Scalability:** While it uses cache files to save time, the current approach of feeding context to an LLM on a *per-PID* basis may become costly or slow if the suspect list is very large (API rate limits).