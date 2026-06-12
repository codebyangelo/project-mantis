# Project Mantis - Antigravity Agent Context

This file serves as persistent context for any future Antigravity AI sessions. Read this file to immediately understand the state of the project, the architecture of the Universal Forensic Engine, and the recent changes made.

## 1. Project Overview
**Project Mantis** is an autonomous DFIR triage agent. It takes raw digital evidence (dead disks like `.e01` and volatile memory like `.raw` or `.vol3`) and uses a combination of deterministic Python heuristics (Sieve) and Large Language Models (Orchestrator) to detect data leakage and fileless malware, culminating in a CISO-ready Markdown report mapped to MITRE ATT&CK.

## 2. Version History & Architecture

### v0.2.5 to v0.2.9_vertex (The Base Engine)
- Established the base architecture (`extractor.py`, `sieve.py`, `orchestrator.py`).
- Implemented MACB Timestamp Parsing, Vertex AI Migration, Deep Forensics (EVTX/Prefetch/PCAP streaming to bypass RAM limits), and NIST SP 800-61r2 Report Formatting.

### v0.3.0 (Zero Blackbox & Deterministic Playbooks)
- **Architectural Shift**: Converted the LLM from a "Blackbox Security Analyst" to a "Playbook Executor" to enforce determinism and audibility.
- Created `dfir_playbook.json` containing explicit evaluation logic (Regex/Signals) and strict False Positive disproval checks.
- Introduced the **Presumption of Benignity**: The LLM must affirmatively disprove benign explanations before classifying an entity as MALICIOUS. If inconclusive, it defaults to SUSPICIOUS.
- **MCP Server Upgrade**: Implemented `mcp_server.py` as an external Tool provider. The LLM can request a "dynamic deep carve" mid-evaluation. The MCP runs shell pipelines (`icat | strings -el`) on physical disk inodes and returns the evidence.

### v0.3.1 (Dynamic Recommendations)
- Removed hardcoded recommendations from `orchestrator.py`.
- Updated the Pydantic Schema (`ExecutiveSynthesis`) to force the LLM to generate dynamic, incident-specific containment and eradication steps.

### v0.3.2 (Deduplication & Budget Quotas)
- **The Deduplication Bug Fixed**: `sieve.py` was previously sending duplicate MFT attributes (`$FILE_NAME` vs `$STANDARD_INFORMATION`) for the exact same `.lnk` files, halving the API budget.
- **Budget Starvation Fixed**: A flood of `.lnk` files (score 100) was previously pushing out critical Registry Hives (score 90). Implemented strict Entity Category Quotas (Max 15 Processes, 10 Files, 5 Hives) in `sieve.py` to guarantee a diverse artifact queue.

## 3. Disproving the Output (The Hallucination Flaw)
In the final validation runs of `v0.3.2`:
1. **ROCBA Malware (Success)**: The Deduplication and Budget fixes worked flawlessly. The agent correctly pushed the `NTUSER.DAT` hive through the queue, triggered a deep strings carve, and mathematically proved process injection and exfiltration to multiple USB drives based entirely on the raw forensic data.
2. **CFREDS Data Leakage (Hallucination Detected)**: The agent correctly isolated the suspicious `secret_project` LNK files. The `SYSTEM` hive was carved and returned NO evidence of USB exfiltration. Yet, during the Executive Synthesis, the LLM blatantly ignored the "Zero Blackbox" / "No Training Data" system prompts. It hallucinated an entire narrative involving "emails to external conspirators", "intercepts at the security checkpoint", and "USB/CD burning" by drawing upon its pre-existing training knowledge of the famous CFREDS dataset, effectively fabricating the synthesis report.

## 4. Current Status
The agent logic is sound and mathematically auditable in `agent_v0.3.2_vertex`. However, we must address the Gemini model's refusal to adhere to the strict "No Training Data" boundary during the narrative synthesis phase when confronted with widely known CTF images.
