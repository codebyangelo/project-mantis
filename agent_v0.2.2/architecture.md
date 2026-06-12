# Project Mantis (agent_v0.2.2) Technical Documentation

## 1. Architecture
Project Mantis is a modular, agentic DFIR (Digital Forensics and Incident Response) triage framework. It follows a **Pipeline-Orchestrator-Agent** pattern designed for offline forensic image analysis:

*   **Extraction Layer (`extractor.py`):** Uses Volatility 3 and `fls`/`mmls` (Sleuth Kit) to process raw memory and disk images. It generates JSON-based caches (`pstree`, `cmdline`, `malfind`, `netscan`, `hivelist`) representing the state of the machine at the time of capture.
*   **Heuristic Sieve (`sieve.py`):** A deterministic, rules-based engine that acts as an "attention mechanism." It parses the JSON caches, calculates risk scores (0–250) based on signals (e.g., `SIG_RWX_INJECTION`), and selects a subset of "high-risk" PIDs for the LLM to inspect.
*   **Agentic Orchestrator (`orchestrator.py` & `agent.py`):** The central FSM (Finite State Machine) that manages the Gemini 3.1 Flash-Lite interaction, enforces Pydantic schema validation for structured outputs, and handles follow-up "Surgical Carving" requests.
*   **Memory Carver (`mcp_server.py`):** Provides low-level access to memory/disk images. The `SurgicalCarver` class performs direct binary reading (avoiding intermediate disk writes) to find specific IOCs in memory-mapped VADs.

## 2. Function
The primary purpose of Project Mantis is to **automate the triage of large-scale forensic images.** It filters out benign "noise" and directs limited LLM inference tokens only toward suspicious entities (PIDs). It mimics a human analyst's workflow:
1.  **Triage:** Automatically extract process metadata.
2.  **Filter:** Assign scores to PIDs based on known malicious patterns (e.g., Living-Off-The-Land (LOTL) binaries, network anomalies, injection).
3.  **Investigate:** Use the LLM to analyze the high-risk shortlist.
4.  **Validate:** Perform "surgical" memory carving on demand if the LLM identifies a hypothesis requiring further proof (e.g., extracting C2 domain strings).

## 3. Current State
*   **Operational:** The framework successfully executes Volatility plugins, generates structured cache files, and builds a "Heuristic PID Table" that ranks processes.
*   **Deterministic Reasoning:** It uses a structured FSM that logs every "thought" and transaction, allowing for auditability.
*   **LLM Integration:** It currently uses Gemini 3.1 Flash-Lite, enforced with strict Pydantic schemas, to provide binary (benign/malicious) verdicts with reasoning.
*   **Surgical Capability:** It includes a memory carver (`SurgicalCarver`) that targets specific suspicious memory regions (VADs) identified by `malfind`, effectively searching for IOCs without dumping the entire memory image to disk.

## 4. What It Doesn't Do (Limitations/Missing Features)
*   **No Automated Full-Disk Scanning:** The carver is "surgical"—it relies on previously identified PIDs. If a malicious binary has no active process or is not caught by `malfind`, it will likely be missed.
*   **Dependency Requirements:** The framework assumes an environment where `vol` (Volatility 3), `fls`, and `mmls` are pre-installed and mapped correctly in the system PATH.
*   **Limited Network Context:** The network anomaly scoring (`_score_network`) is primitive. It relies on standard heuristics and does not perform advanced DNS/IP reputation lookups.
*   **Scaling:** While the cache-based approach is efficient for a single analysis, there is no integrated database (like Elasticsearch/SQL) to correlate findings across multiple host images over time.
*   **Memory Format Handling:** While it supports common formats like `.raw` and `.vmem`, it relies heavily on Volatility's capability to handle the specific image; if a memory profile is mismatched or corrupted, the extraction layer will fail silently or return empty caches.