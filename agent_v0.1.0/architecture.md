# Project Mantis: Agentic Cybersecurity Framework (v0.1.0)

Project Mantis is an autonomous, agentic framework designed to automate the initial phases of Digital Forensics and Incident Response (DFIR) using memory forensics (Volatility 3). It utilizes a "Cognitive Router" architecture to minimize LLM-driven hallucinations by forcing a rigid, state-driven interaction loop.

---

### 1. Architecture
The system follows a **Modular Asynchronous Controller** pattern:
*   **Cognitive Core (`agent.py`):** Utilizes a low-temperature (0.0) Gemini model instructed to act as a deterministic state machine. It consumes system state and outputs structured JSON commands.
*   **Orchestrator (`orchestrator.py`):** Acts as the central nervous system. It manages the tool-calling loop, performs API retry logic (jitter/backoff), maintains a `thoughts.txt` audit ledger, and enforces the "Human-in-the-Loop" (HITL) final verification.
*   **Hardware Choke/Extractor (`extractor.py`):** A dedicated, resource-intensive module that runs Volatility 3 plugins on a target memory image (`.raw`). It is separated from the agent to prevent CPU-intensive memory forensics from impacting the LLM’s responsiveness.
*   **Evidence Layer (`mcp_server.py`):** Provides an interface between the Agent and the cached artifacts. It includes a "Governor" to limit data throughput (token management) and prevent the Agent from processing massive raw logs at once.

### 2. Function
The framework is designed for **Zero-Trust Memory Triangulation**. Its primary purpose is to:
1.  **Ingest** memory evidence asynchronously.
2.  **Corroborate** potential threats by forcing the Agent to cross-reference multiple forensic vectors (e.g., matching a suspicious `malfind` output with `netscan` activity).
3.  **Audit** every step of the investigation through an append-only ledger for post-incident review.
4.  **Verify** results through a cryptographic handshake where a human examiner provides a key to sign the final incident report, ensuring Chain of Custody.

### 3. Current State
*   **Operational:** The system successfully automates the build of an evidence cache from a memory image.
*   **Cognitive Router:** The agent correctly parses JSON directives and switches between forensic tools.
*   **Data Control:** Implements "System Denials" for large data payloads, forcing the agent to use keyword-based filtering instead of blindly reading raw memory scans.
*   **Security:** Enforces strict adherence to a specific subset of Volatility plugins (`pstree`, `cmdline`, `netscan`, `malfind`).
*   **Persistence:** All findings are logged, and the final report generation includes SHA-256 signatures for evidentiary integrity.

### 4. Limitations & Missing Features
*   **Hardware Dependency:** The script assumes specific file paths (`/mnt/sift_ext4/...`) and local binary dependencies (e.g., `sha256sum`, `vol`), making it non-portable in its current form.
*   **Memory Overhead:** While "Hardware Chokes" are implemented, processing multiple large memory dumps simultaneously could still crash lower-end environments if the `extractor.py` is called repeatedly.
*   **Schema Fragility:** While the agent is instructed to return strict JSON, LLMs occasionally inject markdown headers despite instructions. The `clean_json_payload` function is a "bandage" solution; a more robust schema validation (like Pydantic) would improve reliability.
*   **Limited Forensics:** The framework is restricted to only four Volatility plugins. It lacks advanced capabilities like `yarascan` for signature matching, `volshell` for interactive memory manipulation, or support for multiple image files.
*   **No "Pivot" Logic:** While the agent can "re-align," it currently lacks a mechanism to automatically download or ingest new evidence based on findings (it is locked to a single static `MEM_IMAGE`).