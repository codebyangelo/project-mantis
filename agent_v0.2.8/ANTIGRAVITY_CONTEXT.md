# Project Mantis - Antigravity Agent Context

This file serves as persistent context for any future Antigravity AI sessions. Read this file to immediately understand the state of the project, the architecture of the Universal Forensic Engine, and the recent changes made.

## 1. Project Overview
**Project Mantis** is an autonomous DFIR triage agent. It takes raw digital evidence (dead disks like `.e01` and volatile memory like `.raw` or `.vol3`) and uses a combination of deterministic Python heuristics (Sieve) and Large Language Models (Orchestrator) to detect data leakage and fileless malware, culminating in a CISO-ready Markdown report mapped to MITRE ATT&CK.

## 2. Version History & Architecture

### v0.2.5 (The Base)
- Established the base architecture: `extractor.py` (builds the cache using SleuthKit/Volatility), `sieve.py` (heuristic filters), and `orchestrator.py` (LLM evaluator).
- Included `mcp_server.py` for surgical string carving.
- Encountered JSON serialization crashes during synthesis.

### v0.2.6 (The Timeline Upgrade)
- Fixed the JSON serialization crash in `agent.py`.
- **MACB Timestamp Integration**: Updated `sieve.py` to natively parse MACB timestamps from the `fls` bodyfile and inject them into the LLM context.
- **Incident Synthesis**: The agent acts as a Lead Forensic Investigator, using the timestamps to perfectly reconstruct chronological timelines of attacks (e.g., the CFReDS data exfiltration case over a 3-day span).

### v0.2.7_vertex (The Universal Engine)
- **Vertex AI Migration**: Migrated the `google.genai` SDK to natively use Vertex AI (`vertexai=True`), authenticating via `VERTEX_API_KEY`, `VERTEX_PROJECT_ID`, and `VERTEX_LOCATION` in the user's `~/.bashrc` and `~/.zshrc`.
- **Generic Sieve**: Removed hardcoded CFReDS keywords (e.g., "resign", "secret") from `sieve.py`. The sieve now generically flags deleted user documents and staging archives (`.zip`, `.rar`, etc.) to catch all forms of data exfiltration.
- **OSINT Attribution**: Integrated native Google Search grounding (`tools=[{"google_search": {}}]`). 
  - *Crucial Fix*: Web Search was originally enabled during the Evaluation Phase, which caused the LLM to hallucinate that fileless malware injections were "JIT false positives" after reading IT forums. 
  - The Web Search tool was moved strictly to the **Synthesis Phase**, forcing the agent to trust raw forensic evidence during evaluation and only use the internet to attribute the attack's C2 IPs to APT groups.

### v0.2.8_vertex (Deep Forensics & Project Mantis)
- **Project Renamed**: Officially renamed from Project Find Evil to Project Mantis.
- **Deep Forensics Mode**: Introduced a `--deep` flag to `extractor.py` and `orchestrator.py` that enables streaming extraction and parsing of Windows Event Logs (EVTX) and Prefetch artifacts. To bypass hardware limitations (1.3GB RAM), these parsers stream their data directly to JSON caches instead of holding the records in memory.
- **NIST SP 800-61r2 Alignment**: The generated report now explicitly transitions from "Detection & Analysis" to providing actionable "Containment, Eradication, and Recovery" recommendations based on NIST incident response standards.

## 3. Evidence Processing & Datasets Tested
1. **CFReDS Data Leakage (Disk)**: Successfully caught an insider threat staging data via Google Drive and scrubbing evidence with Eraser/CCleaner.
2. **ROCBA Malware (19GB Memory)**: Successfully transitioned to fileless malware analysis, catching RWX shellcode injected into `SearchApp.exe`, `LockApp.exe`, `smartscreen.ex`, and `MsMpEng.exe` (Windows Defender), complete with C2 network exfiltration IPs.

## 4. Current Status
The agent is fully functional and stable in the `agent_v0.2.8_vertex` directory.
To run the orchestrator:
```bash
cd /mnt/sift_ext4/sift_home/projects/findevil_agent/agent_v0.2.8_vertex
source ~/.bashrc  # Ensure Vertex API keys are loaded
python3 orchestrator.py [--deep]
```
