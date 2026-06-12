# Project Mantis (agent_v0.2.8_vertex) Analysis

Project Mantis is a modular, agentic Digital Forensics and Incident Response (DFIR) framework designed to automate the triage of memory and disk images. By leveraging heuristic scoring and LLM-driven decision-making, it shifts from manual analysis to an autonomous "investigative loop" model.

---

## 1. Architecture
Project Mantis follows a **Pipeline-Orchestrator-Intelligence** architecture:

*   **Extraction Layer (`extractor.py`):** A headless processing engine that interacts with forensic tools (Volatilty 3, Sleuth Kit) to convert raw images into structured JSON caches.
*   **Heuristic Sieve (`sieve.py`):** A deterministic "pre-processor" that consumes the JSON caches. It calculates risk scores based on static rules (e.g., suspicious file paths, LOLBins, network anomalies) to filter out noise before the LLM engages.
*   **Orchestration Layer (`orchestrator.py` & `mcp_server.py`):** Acts as the central nervous system. It manages the state machine, provides secure file access (MCP-like server), and coordinates the "Carver" tools.
*   **Intelligence Layer (`agent.py`):** The Gemini-based agent that receives specific evidence packets, enforces output schemas using Pydantic, and performs high-level synthesis (attribution and narrative generation).

---

## 2. Function
The framework is designed to **reduce the "time-to-triage"** in incident response. It:
1.  **Ingests** memory/disk images and generates forensic artifacts (process trees, registry hives, network connections).
2.  **Ranks** suspected malicious entities based on a set of pre-defined heuristic signals.
3.  **Investigates** selected entities by providing the LLM with relevant, isolated snippets of evidence.
4.  **Deep-Carves** additional data (if requested by the LLM) to confirm or deny hypotheses.
5.  **Reports** the final status in a standardized format, mapping findings to the MITRE ATT&CK framework and generating an executive synthesis.

---

## 3. Current State
As of `agent_v0.2.8_vertex`, the system is a functional automated forensic tool capable of:
*   **Automatic Triage:** Successfully integrates `volatility3` plugins (`pstree`, `malfind`, `netscan`) and `fls`/`icat` for disk imaging.
*   **Heuristic Filtering:** High-performance pre-filtering of artifacts, ensuring the LLM is only tasked with high-context items (budget-aware).
*   **Autonomous Iteration:** It performs "follow-up" actions; if the LLM identifies a suspicion but requires more data, the orchestrator triggers dynamic memory or disk carving (Surgical Carver) to provide the missing strings.
*   **Integration with Google Cloud:** Uses the Gemini `3.1-flash-lite` model for classification, supporting Pydantic validation to ensure structured, machine-readable decisions.

---

## 4. Limitations & Missing Features
Despite its power, the tool has specific operational constraints:

*   **Memory Footprint:** While it attempts to stream data (e.g., in `carve_and_stream_strings`), the reliance on large JSON files for caching metadata can lead to high memory consumption on systems with many processes or large registry hives.
*   **Dependency on External Tooling:** It relies heavily on local installations of `volatility3`, `fls`, `icat`, and `strings`. If these tools are not in the PATH or are misconfigured, the framework fails silently or errors out.
*   **Limited "Deep" Context:** While it uses `evtx` and `prefetch` streaming, the logic is keyword-based (`pf_keywords`, `evtx_keywords`). It does not yet perform full-spectrum parsing of those files.
*   **Pacing Constraints:** The current iteration uses fixed `time.sleep(4)` for API pacing. This is an inefficient way to handle rate limits and could lead to performance bottlenecks during large investigations.
*   **OSINT/Synthesis Risks:** The Executive Synthesis module uses Google Search to attribute threats. This is subject to the accuracy of search results and potentially "hallucinated" links if the threat actor or TTPs are not publicly documented.
*   **Single-Image Bias:** While it supports multiple images, the logic heavily favors the first image found in the evidence directory for certain operations, potentially creating blind spots in multi-disk/multi-memory scenarios.