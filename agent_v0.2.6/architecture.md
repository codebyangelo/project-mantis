# Project Mantis (agent_v0.2.6) Analysis

## 1. Architecture
Project Mantis is a **multi-component agentic DFIR (Digital Forensics and Incident Response) framework** designed for automated memory and disk triage. Its architecture follows a modular "Pipeline & Brain" design:

*   **Orchestration Layer (`orchestrator.py`):** Acts as the Finite State Machine (FSM). It manages the investigation lifecycle, tracks "thoughts" (logs), and interfaces between the data processing modules and the LLM agent.
*   **Intelligence Layer (`agent.py`):** A Pydantic-enforced wrapper around the Gemini API. It uses a structured schema to ensure the LLM provides consistent, programmatic outputs (verdicts, MITRE mappings, deep-carve requests).
*   **Data Processing Layers:**
    *   **Extractor (`extractor.py`):** The data ingestion engine. It interacts with native forensic tools (Volatility 3, `fls`, `icat`, `mmls`) to build a JSON-indexed evidence cache.
    *   **Sieve (`sieve.py`):** The heuristic scoring engine. It performs deterministic analysis on cached data (calculating risk scores for processes, network connections, and registry persistence) to identify "suspect entities."
    *   **MCP Server (`mcp_server.py`):** An abstraction layer that provides "tool use" capabilities to the agent, allowing it to perform dynamic memory/disk carving upon request.

## 2. Function
The framework is designed to **autonomously triage forensic images** to identify malicious activity, data exfiltration, and persistence. Its workflow is:
1.  **Ingestion:** Map and extract metadata from memory/disk images into a searchable cache.
2.  **Filtering:** Apply deterministic heuristics (Sieve) to rank entities by suspicion.
3.  **Classification:** Send highly-suspect entities to an LLM (Gemini) to determine a verdict.
4.  **Deep Investigation:** Perform "Surgical Carving" (dynamic extraction of strings or files) if the LLM determines it needs more context to confirm a threat.
5.  **Reporting:** Synthesize findings into a final Markdown report mapped to the MITRE ATT&CK framework.

## 3. Current State
In version `agent_v0.2.6`, the system is fully functional for **batch triage**.
*   **Heuristics:** Successfully implements scoring for LOTL (Living-Off-The-Land) binaries, RWX memory segments, and suspicious network activity.
*   **Surgical Capability:** Can perform context-aware, zero-disk-write memory string carving using VAD metadata.
*   **Deterministic Logic:** Uses a "Budget-Aware" approach to ensure the LLM focuses only on the most suspicious entities (API cost management).
*   **Reporting:** Automatically generates high-fidelity MITRE-aligned reports with SHA-256 integrity hashes.

## 4. What it doesn't do (Limitations)
*   **Full Automation:** The tool requires manual trigger (`investigate`) after initialization; it is not a background daemon.
*   **Forensic Tool Dependency:** The framework relies on an external environment being pre-installed with `vol` (Volatility 3), `fls`, `icat`, and `strings`. If these are missing or mismatched, the extraction phase will fail silently or partially.
*   **Advanced Rootkits/Anti-Forensics:** The `sieve.py` logic is heuristic-based. It may struggle against sophisticated stealth rootkits that manipulate VADs or registry keys in ways that bypass these specific regex-based detection patterns.
*   **Live Incident Response:** It is designed for *post-mortem* forensic images, not live triage of an infected system in real-time.
*   **Stateful Memory:** While it keeps a thought ledger, it does not maintain a long-term "memory" of previous investigations; each run is an isolated session.