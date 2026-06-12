# Project Mantis: Agentic Framework Analysis (v0.1.0_extraction_test)

This document provides an architectural and functional analysis of the current iteration of the "Project Mantis" cybersecurity framework.

---

## 1. Architecture
The project follows a **Modular Agentic Loop** architecture, utilizing a separation of concerns between the cognitive core (LLM), the orchestration layer, and the hardware-bound execution layer.

*   **Cognitive Core (`agent.py`):** Uses a Google GenAI client (`gemini-3.1-flash-lite`) configured with rigid system instructions and a zero-temperature setting to enforce deterministic outputs.
*   **Orchestration Layer (`orchestrator.py`):** Acts as the "Traffic Controller." It parses agent decisions, handles API retries/throttling, enforces JSON schema compliance, and writes to an append-only "Thought Ledger."
*   **Execution Layer (`mcp_server.py` & `extractor.py`):** Serves as the abstraction layer between the LLM and the physical environment. It wraps Volatility3 functionality and enforces strict rate-limiting and output sanitization to prevent LLM context-window exhaustion.
*   **Storage Layer:** Employs a local `evidence_cache/` directory to store physical memory dumps and plugin results, enabling the agent to perform multi-step analysis without re-running heavy volatility tasks.

## 2. Function
Project Mantis is designed to perform **automated, multi-vector DFIR (Digital Forensics and Incident Response) triage** on memory images. Its primary objective is to move from raw memory analysis to a verified, human-reviewed incident report through a process of "triangulation," ensuring that malicious findings are corroborated by multiple data sources (e.g., memory anomalies plus network activity).

## 3. Current State
*   **Asynchronous Processing:** The framework supports background execution of `extractor.py` via `subprocess.Popen` to prevent blocking the agent loop during heavy I/O tasks.
*   **Hardened Guardrails:** The system implements an "API Governor" and "System Denials." It proactively truncates or rejects oversized payloads to protect the LLM context window.
*   **Zero-Trust Workflow:** The agent is hard-coded to ignore "single-vector" alerts, forcing a recursive loop until the agent provides at least two corroborated indicators of compromise.
*   **Auditable Ledger:** Every thought process and system interaction is committed to a `thoughts.txt` log, providing a transparent trail of the agent’s logic.
*   **Human-in-the-Loop:** The system includes a cryptographic verification gate (`request_human_review`), where findings are only finalized upon the entry of a manual examiner key.

## 4. Limitations and Missing Features
*   **Memory/Resource Constraints:** The reliance on reading files into memory for LLM evaluation creates a hard limit on the amount of evidence the agent can process at once (50,000 character limit for keyword searches).
*   **Limited Plugin Suite:** The framework is currently restricted to four hard-coded plugins (`pstree`, `cmdline`, `netscan`, `malfind`). It lacks the ability to dynamically load or query new Volatility plugins based on findings.
*   **Rigid Orchestration:** The `orchestrator.py` requires precise matching of JSON keys. If the LLM drifts from the schema, the error-handling loop is the only recovery mechanism; there is no self-correction mechanism built into the agent itself.
*   **Static Pathing:** The `extractor.py` and `mcp_server.py` rely on hardcoded paths (`/mnt/sift_ext4/...`). This reduces portability and requires specific environment setups to function.
*   **No Parallelism in Analysis:** While extraction is asynchronous, the *analysis* (the agent's cognitive processing) is strictly linear. The agent cannot process multiple plugins in parallel, which may lead to longer investigation times for complex artifacts.