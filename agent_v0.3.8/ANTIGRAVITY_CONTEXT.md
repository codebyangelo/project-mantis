# Project Mantis - Antigravity Agent Context

This file serves as persistent context for any future Antigravity AI sessions. Read this file to immediately understand the state of the project, the architecture of the Universal Forensic Engine, and the recent changes made.

## 1. Project Overview
**Project Mantis** is an autonomous DFIR triage agent. It takes raw digital evidence (dead disks like `.e01` and volatile memory like `.raw` or `.vol3`) and uses a combination of deterministic Python heuristics (Sieve) and Large Language Models (Orchestrator) to detect data leakage and fileless malware, culminating in a CISO-ready Markdown report mapped to MITRE ATT&CK.

## 2. Version History & Architecture

### v0.2.5 to v0.3.2 (The Base Engine)
- Established the base architecture (`extractor.py`, `sieve.py`, `orchestrator.py`).
- Implemented MACB Timestamp Parsing, Vertex AI Migration, Deep Forensics (EVTX/Prefetch/PCAP streaming), and NIST SP 800-61r2 Report Formatting.
- Converted the LLM to a "Playbook Executor" (Zero Blackbox) enforcing determinism via `dfir_playbook.json`.
- Implemented `mcp_server.py` allowing LLMs to run mid-evaluation shell pipelines (`icat | strings -el`).
- Fixed Deduplication and Budget Starvation bugs (Entity Category Quotas).

### v0.3.3 to v0.3.6 (The Adversarial Anti-Jailbreak Architecture)
- Encountered massive hallucination flaws where the models ignored "Zero Blackbox" constraints and hallucinated case facts.
- **Prosecutor vs. Defense Attorney**: Split the Orchestrator into an adversarial architecture. The Prosecutor attempts to convict entities, while the Defense Attorney rigidly attempts to disprove them using playbook logic.
- **ClaimGuard & Citation Traps**: Added deterministic regex bans (`inference_bans`) against words like "staging" or "intent" to prevent semantic hallucinations. Also added a `re.findall` loop requiring the Defense Attorney to strictly quote the raw JSON telemetry to back up any claims. 

### Collective Reasoning Testing
- Integrated a `collective_reasoning.py` script that utilizes Groq (`llama-3.3-70b-versatile`), Cerebras (`gpt-oss-120b`), and NVIDIA NIM via the standard OpenAI Python SDK to dynamically debate and attempt to disprove Mantis baseline reports.

### v0.3.7 (Current Baseline - Contextual Determinism)
- **Closed the ClaimGuard Loophole**: Collective reasoning identified that forcing a `BENIGN` verdict when `ClaimGuard` trapped a banned word created a covert whitelist backdoor (where an attacker could name their malware "staging_payload"). The code was updated to force an `INCONCLUSIVE/SUSPICIOUS` verdict instead.
- **Context-Aware Playbooks**: Over-simplified heuristics were tightened. For example, `USB_LNK_001` now explicitly instructs the LLM that external USB drives (e.g. `E:\`, `F:\`) are unauthorized and cannot be disproved without matching corporate network share logic.
- **Strict Determinism**: Enforced `temperature=0.0` across the Prosecutor and Defense Attorney generation configs to ensure full forensic reproducibility.
- **Successful Validation**: `v0.3.7` was run against the CFReDS Data Leakage scenario and correctly matched the NIST master answer key: it successfully isolated the stolen payload LNKs based on the updated playbook logic, caught the resignation letter as suspicious (via ClaimGuard), and successfully cleared the legitimate network share LNKs.

## 3. Current Status
`v0.3.7` is a massive success. The agent accurately parses raw disk artifacts, refuses semantic jailbreaks, and outputs highly deterministic, mathematically auditable DFIR reports without hallucinating known case answers.
