This analysis covers version **agent_v0.2.3** of 'Project Mantis', a specialized agentic framework designed for automated Digital Forensics and Incident Response (DFIR).

---

### 1. Architecture
Project Mantis uses a **decoupled, modular architecture** designed to bridge raw disk/memory forensics with LLM-based decision-making.

*   **Forensic Layer (`extractor.py`):** Uses Volatility 3 plugins (`pstree`, `malfind`, `netscan`) and Sleuth Kit (`fls`, `icat`, `mmls`) to ingest memory/disk images and produce structured JSON caches.
*   **Heuristic Engine (`sieve.py`):** Acts as a deterministic "pre-filter." It processes the cached artifacts, assigns risk scores based on predefined patterns (Living-off-the-Land (LotL), masquerading, injection), and selects high-confidence candidates for the LLM.
*   **Orchestration Layer (`orchestrator.py`):** Functions as the Finite State Machine (FSM). It manages the investigation lifecycle, maintains a "thought ledger" (audit trail), and communicates with the LLM via Pydantic-enforced schemas.
*   **Intelligence Layer (`agent.py`):** A Pydantic-defined interface for Gemini 3.1 Flash-Lite. It consumes the artifacts and heuristic signals, returning a standardized `AgentCommand` object (verdict, confidence, severity, MITRE mapping).

### 2. Function
The framework is designed to **autonomously triage memory and disk evidence to identify malicious activity.** 
*   It reduces the human burden by filtering thousands of noise-level processes down to a shortlist of high-risk PIDs.
*   It utilizes "Surgical Carving" to extract IOCs (like C2 domains) only when necessary, minimizing resource consumption.
*   It generates high-fidelity reports mapping findings to the MITRE ATT&CK framework, providing a clear path for human responders.

### 3. Current State
*   **Fully Operational Pipeline:** Capable of performing automated forensic ingestion, scoring, and LLM-based classification.
*   **Deterministic Prioritization:** The system correctly prioritizes PIDs using the "Sieve" (scoring 150+ = critical, 60-149 = suspicious).
*   **Validation-Forward:** The system relies heavily on Pydantic schemas, ensuring the LLM output is programmatically consumable, reducing hallucination-induced crashes.
*   **Dynamic Feedback Loops:** The Orchestrator can trigger a second "surgical" memory pass if the initial evidence is inconclusive, effectively performing a multi-stage investigation on a single PID.

### 4. Limitations and Missing Features
*   **Resource Dependency:** The framework relies on external forensic tools (Volatility 3, The Sleuth Kit) being present in the system PATH. It is not a standalone portable executable.
*   **Contextual Blindness:** The "Surgical Carver" relies on `malfind` metadata. If the malware utilizes sophisticated unbacked memory techniques or avoids VAD hooking, the carver may return a "null hypothesis."
*   **Manual Trigger:** While the FSM is automated, the initial triage and evidence ingestion (`extractor.py`) must be verified/triggered via the CLI.
*   **Static Playbook:** While `read_dfir_playbook()` exists, the logic for *interpreting* the playbook is currently rudimentary; it acts as an informative file rather than an executable instruction set.
*   **Network-Only Fallback:** The carver's fallback mechanism for strings is limited to a 50MB budget, which may be insufficient for massive memory images or heavily obfuscated payloads.