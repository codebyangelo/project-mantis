This document provides an architectural and functional analysis of **Project Mantis, v0.3.0_vertex**.

---

### 1. Architecture
Project Mantis is a modular, agentic Digital Forensics and Incident Response (DFIR) framework designed to perform automated triage on disk, memory, and network artifacts. Its architecture is divided into four primary segments:

*   **Extraction Layer (`extractor.py`):** Acts as the data ingestion engine. It interacts with raw forensic images (memory, disk, pcap) using tools like `volatility3` (`vol`) and `sleuthkit` (`fls`, `icat`) to produce structured JSON caches.
*   **Analysis Engine (`sieve.py`):** Serves as a deterministic pre-processor. It ingests the JSON caches and performs heuristic filtering (e.g., checking for LOTL binaries, suspicious network connections, and anomalous paths). This reduces the LLM's workload by flagging only "suspect entities."
*   **Orchestration Layer (`orchestrator.py`):** The "brain" that manages the state machine. It iterates through the identified suspect entities, queries the LLM for verdicts based on a provided playbook, handles dynamic deep carving, and generates the final MITRE ATT&CK report.
*   **Intelligence Layer (`agent.py`):** Integrates with Google’s Vertex AI (Gemini). It enforces strict structural integrity using Pydantic models to ensure that the LLM functions as a "deterministic playbook executor" rather than a creative chatbot.

---

### 2. Function
Project Mantis is meant to automate the **"Detection and Analysis"** phase of incident response. Its primary purpose is to ingest large-scale forensic data, prioritize high-risk artifacts, and provide a clear, evidence-backed verdict (Malicious, Suspicious, or Benign) mapped against MITRE ATT&CK techniques, while minimizing human-in-the-loop requirements.

---

### 3. Current State
*   **Evidence Handling:** Successfully parses process trees, command lines, memory injections (malfind), network connections, registry hives, Prefetch, and EVTX event logs.
*   **Heuristic Pre-Filtering:** Effectively reduces "noise" by scoring artifacts before LLM evaluation, allowing the system to scale beyond simple file inspection.
*   **Deterministic Guardrails:** The integration with Pydantic ensures that the LLM cannot hallucinate formats. It forces the model to follow a "Presumption of Benignity" and strict decision-matrix logic.
*   **Dynamic Carving:** The system is capable of performing "surgical" string carving on memory/disk in response to initial LLM triage, allowing for iterative evidence discovery.
*   **Reporting:** Generates automated, timestamped Markdown reports containing incident narratives, MITRE mappings, and NIST-aligned containment recommendations.

---

### 4. Limitations & Missing Features

*   **Dependency on External Tools:** The framework relies on external command-line utilities (`vol`, `fls`, `icat`, `strings`). It will fail if these are not present in the system `$PATH` or if their output formats change (e.g., Volatility plugin updates).
*   **RAM/Resource Limits:** While it uses chunked streaming to read files, there is an implicit assumption that the environment has enough storage to hold the `CACHE_DIR` contents, which can become significant for large disk images.
*   **Single-Agent Bottleneck:** The current orchestrator is sequential. It evaluates entities one-by-one, which, combined with the 4-second API pacing, results in slow performance for high-volume evidence sets.
*   **Limited Correlation:** While it aggregates data, it lacks a complex temporal graph engine. It performs point-in-time analysis of artifacts rather than correlating events across different sources (e.g., tying a specific network connection to a specific registry change across different time zones or boot cycles).
*   **No Self-Correction (Retry Logic):** While the code handles basic API exhaustion, it lacks a deep self-correcting loop. If the LLM produces a "Suspicious" verdict for a clearly malicious file due to a misparsed JSON value, the system does not automatically re-run the extraction with higher verbosity.
*   **Security (Path Validation):** While `validate_path` exists, the framework is heavily dependent on the environment being a trusted sandbox; if the `EVIDENCE_DIR` is compromised or misconfigured, it could lead to arbitrary file access via the forensic tools.