# Project Mantis: Agentic DFIR Framework (v0.2.9_vertex)

This document provides a technical overview of **Project Mantis**, an automated, agentic Digital Forensics and Incident Response (DFIR) framework designed to accelerate triage and threat hunting.

---

## 1. Architecture
Project Mantis follows a **modular, state-machine driven architecture** designed to minimize manual analysis time on memory and disk images.

*   **Extraction Layer (`extractor.py`):** Uses forensic tools (e.g., `volatility3`, `fls`, `icat`, `strings`) to parse raw images into structured JSON caches. It is highly optimized for resource-constrained environments by using streaming carving.
*   **Intelligence Layer (`agent.py`):** Integrates with Google Vertex AI (Gemini). It enforces structured output using **Pydantic schemas** (`AgentCommand`, `ExecutiveSynthesis`) to ensure the AI remains within deterministic operational boundaries.
*   **Orchestration Layer (`orchestrator.py`):** Acts as the "FSM" (Finite State Machine). It iterates through heuristic-scored entities, queries the LLM for verdicts, handles dynamic "deep carving" requests, and generates formal documentation.
*   **Analysis/Sieve Layer (`sieve.py`):** A high-performance deterministic engine that performs pre-scoring and entity grouping before the data is handed to the LLM (API budget management).

---

## 2. Function
Project Mantis is designed to perform **autonomous incident triage**. It is meant to:
1.  **Ingest** raw memory (`.mem`, `.raw`) and disk (`.dd`, `.img`) forensic images.
2.  **Filter and Score** potentially malicious entities (processes, files, registry keys) using internal heuristics before querying an LLM.
3.  **Validate Hypotheses** by performing "surgical" memory and disk carving only when requested by the AI.
4.  **Synthesize Reports** and map activity to **MITRE ATT&CK** techniques, providing an executive-level summary and incident narrative.

---

## 3. Current State
*   **Fully Functional FSM:** The system successfully manages an "Investigate" loop, iterating through entities based on severity scores.
*   **Surgical Carving:** The framework supports real-time extraction of specific memory strings (using `vol` VAD metadata) and physical disk file streaming (using `icat` and `fls`) without writing entire blobs to disk.
*   **Deterministic Reasoning:** By combining heuristic signals (e.g., `SIG_RWX_INJECTION`) with LLM evaluation, it maintains a balance between automated speed and intelligent context assessment.
*   **Reporting:** It generates automated Markdown reports with SHA-256 integrity hashes and NIST 800-61r2 alignment.

---

## 4. Limitations & Missing Features

*   **External Dependency Reliance:** The framework heavily relies on local binary availability (`vol` for Volatility, `fls`, `icat`, `mmls` from Sleuth Kit). If these binaries are not installed or configured in the system PATH, the extractor will fail.
*   **Heuristic Overlap:** The `sieve.py` engine is highly opinionated. While this prevents "token explosion" in the LLM, it may occasionally miss low-and-slow threats that do not match the predefined list of LOTL (Living off the Land) binaries.
*   **Memory Depth:** The framework treats `malfind` as the primary source of suspicious memory segments. It currently lacks full "Heap/Stack" inspection capabilities and relies on VAD protection flags.
*   **Pacing Constraints:** The current `orchestrator.py` implements a hardcoded `time.sleep(4)` to handle API rate limits. This is effective but inefficient for large-scale evidence triage.
*   **Single-Image Focus:** While it supports multiple images, the context-building logic is designed to aggregate them into a single global cache, which may cause "signal noise" if multiple dissimilar images are provided simultaneously.