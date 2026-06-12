This document provides an architectural and functional analysis of **Project Mantis, version agent_v0.2.7**, a specialized agentic framework designed for automated DFIR (Digital Forensics and Incident Response) triage.

---

### 1. Architecture
Project Mantis follows a modular, state-driven architecture designed to bridge raw forensic data (Memory/Disk images) with high-level LLM-based reasoning.

*   **Data Ingestion (`extractor.py`):** Acts as the ingestion layer. It classifies evidence (memory vs. disk), runs Volatility3 plugins (`pstree`, `malfind`, etc.) for memory, and uses `fls` (SleuthKit) to generate bodyfiles for disk artifact parsing.
*   **The Sieve (`sieve.py`):** A deterministic "pre-filter" that reduces the LLM's load. It aggregates disparate JSON caches into a PID/Entity-indexed table and applies heuristic scoring (e.g., RWX memory segments, anomalous parents, LOTL argument patterns).
*   **Agentic Core (`agent.py` & `orchestrator.py`):** The "Brain." It utilizes Google’s Gemini API with Pydantic-enforced schemas to ensure structured output. It implements a Finite State Machine (FSM) loop that moves from heuristic detection to surgical carving (deep analysis) and finally to incident synthesis.
*   **Orchestration (`mcp_server.py`):** The interface layer. It enforces path security and manages the "Surgical Carver," which reads memory images or registry hives on-demand without dumping entire images to disk.

### 2. Function
The framework is designed to **minimize "Human-in-the-Loop" time** during early-stage incident response.
*   **Goal:** Automatically identify malicious processes, suspicious files, and registry persistence artifacts from forensic images.
*   **Workflow:** 
    1. Extract metadata from disk/memory.
    2. Score entities (PIDs, Files, Hives) based on threat heuristics.
    3. Delegate high-scoring entities to an LLM for classification.
    4. Dynamically "carve" (extract strings/indicators) if the LLM requires more context.
    5. Generate a MITRE ATT&CK-mapped executive report.

### 3. Current State
*   **Hardened Logging:** All actions are tracked via `ExecutionLogger` and an internal `thoughts.txt` ledger to provide transparency.
*   **Deterministic Filtering:** Successfully implements "Budget-Aware Selection," where only the most suspicious entities are sent to the LLM (api_budget=30), preventing token exhaustion and keeping costs predictable.
*   **Surgical Carving:** The framework now supports memory string extraction for specific PIDs and registry hive carving for USB/data leakage detection.
*   **Integration:** It supports real-time OSINT via Google Search, allowing the LLM to attribute activity to known threat actors based on discovered C2/TTPs.

### 4. What it doesn't do (Limitations & Missing Features)
*   **Full Memory Dump Analysis:** The tool relies on metadata/VADs (Virtual Address Descriptors) from Volatility3. It does not perform full-scale memory forensics (e.g., scanning for rootkit hooks or kernel-level malware).
*   **No Automated Containment:** It is a diagnostic/triage tool only. It does not possess "Active Response" capabilities (e.g., killing processes, isolating network hosts, or wiping files).
*   **Dependency on External Binaries:** The tool is strictly tied to a Linux environment with `vol` (Volatility3), `icat`, `strings`, `mmls`, and `fls` installed. If the environment is not set up perfectly (e.g., missing SleuthKit), the extraction phase will fail.
*   **Limited Data Types:** While it handles registry keys and memory processes well, it lacks deep parsing for complex filesystem metadata or user-level artifacts like browser history or shellbags beyond simple keyword searching.
*   **Scaling:** The `sieve.py` approach is optimized for single-machine analysis. It lacks the distributed processing capability required for large-scale enterprise forensic clusters.