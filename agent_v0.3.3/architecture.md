This document outlines the architecture and functionality of **Project Mantis (v0.3.2_vertex_cfreds)**, an automated, agentic framework designed for digital forensics and incident response (DFIR).

---

### 1. Architecture
Project Mantis follows a modular, pipeline-oriented architecture designed to operate on memory and disk images. It decouples data collection from analysis, utilizing a local "Cache" as the interface between components.

*   **Extractor (`extractor.py`)**: The data ingestion layer. It performs forensic triage using volatility plugins and filesystem analysis (`fls`, `icat`), writing results as structured JSON files into the `CACHE_DIR`.
*   **Orchestrator (`orchestrator.py`)**: The central control unit. It manages the State Machine, invokes the AI Agent for analysis, and generates final reports.
*   **MCP Server (`mcp_server.py`)**: A Model Context Protocol-like layer that safely interacts with the host environment. It provides APIs to read caches, perform string carving, and execute secure sub-processes.
*   **Sieve (`sieve.py`)**: A "Deterministic Scorer." It ingests raw cache files to calculate risk scores for processes and artifacts, narrowing down the massive volume of data into a prioritized subset of "Suspect Entities."
*   **Intelligence Layer (`agent.py`)**: A Pydantic-enforced wrapper for Google’s Gemini 3.1 Flash-Lite. It acts as the final decision engine, strictly following a "Presumption of Benignity" protocol.

---

### 2. Function
The framework is designed to automate the initial triage phase of a DFIR investigation. 
*   **Goal**: To reduce the burden on human analysts by automatically parsing forensics artifacts (memory/disk) and identifying high-confidence malicious activity.
*   **Mechanism**: It creates a "Suspect Entity" list based on predefined heuristic scoring (e.g., RWX memory segments, anomalous parents, LOTL command lines) and presents these entities to the LLM for a final, structured verdict against a provided JSON playbook.

---

### 3. Current State
*   **Artifact Support**: Supports memory forensics (via Volatility), disk analysis (registry hive extraction, EVTX/Prefetch streaming), and network PCAP analysis.
*   **Intelligence**: Employs an LLM-as-a-Judge architecture where the model is constrained by strict JSON schema enforcement (Pydantic) and a "Presumption of Benignity" system instruction to prevent hallucinations.
*   **Deep Carving**: Includes a "SurgicalCarver" which performs zero-intermediate-disk-write string carving on suspicious memory regions, attempting to extract IOCs directly from memory-mapped files.
*   **Reporting**: Automatically generates a structured markdown report with MITRE ATT&CK mapping and an executive incident synthesis.

---

### 4. Limitations & Missing Features

#### Limitations:
*   **API Dependency**: Relies entirely on external AI (Vertex AI/Gemini). It cannot function offline.
*   **Pacing Constraints**: The system includes a hard-coded 4-second delay per API call to respect rate limits, making exhaustive investigations slow on large datasets.
*   **Context Window**: While the orchestrator truncates input data to mitigate token limits, complex incidents with massive logs may lead to information loss during the "Sieve" selection phase.
*   **OS Dependency**: Heavily oriented towards Windows forensic artifacts (e.g., `NTUSER.DAT`, `windows.pstree`, `windows.malfind`).

#### Missing Features:
*   **Live Memory Acquisition**: The tool expects pre-existing images; it does not have a module for live acquisition of a suspect machine's RAM.
*   **Advanced Timeline Analysis**: While it collects metadata, it lacks a visual timeline aggregator (Super-Timeline) to correlate events chronologically across different evidence sources.
*   **Automated Remediation**: The framework generates "Containment Recommendations" but lacks the ability to execute these changes (e.g., isolating a host at the network layer, killing processes on a live target).
*   **Persistence Mechanisms for Linux/macOS**: Analysis is currently strictly optimized for Windows environments.