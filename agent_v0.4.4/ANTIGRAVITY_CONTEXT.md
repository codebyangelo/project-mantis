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
- **The Deduplication Bug Fixed**: `sieve.py` was previously sending duplicate MFT attributes (`$FILE_NAME` vs `$STANDARD_INFORMATION`) for the exact same `.lnk` files, halving the API budget.

# v0.4.0 Progress (Automated Cross-Dimensional Pivot)
- **Post-Conviction Pivot Pipeline**: Mantis now seamlessly pivots from a memory conviction (e.g., a process with a malicious `jmp rax` hook) directly to querying the disk timeline cache (`bodyfile`/`mft`) for that specific PID.
- **MCP search_disk_timeline Integration**: Created a dedicated MCP server function allowing the Orchestrator to programmatically `grep` the cache files without relying on unpredictable LLM syntax.
- **Execution Chain Synthesis**: Added a new Pydantic schema (`ExecutionChainSynthesis`) to force the LLM to synthesize the memory conviction and the disk timeline into a cohesive narrative outlining the `dropper_file` and `execution_timeline`.
- **Forensic Terminology**: Refined the Defense Attorney logic to use the strict forensically-sound term `FAILED_TO_DISPROVE` when an artifact cannot be proven benign.
- **Subagent Discovery Automated**: Replaced the manual subagent investigation process (which correctly identified PyInstaller droppers in `/Users/fredr/AppData/Local/Temp/_MEI118162/`) with an automated pivot directly built into the primary deterministic pipeline.

## 3. Current Status
`v0.4.0` represents a transition to fully automated cross-artifact investigation. The agent now creates a continuous forensic thread between volatile memory and persistent disk artifacts, further reducing the need for human intervention in complex pivot scenarios.

### v0.4.1 to v0.4.3 (Hallucination Mitigation & False Positive Balancing)
- **ClaimGuard Removed**: The regex-based `ClaimGuard` in `orchestrator.py` was forcibly downgrading valid `MALICIOUS` verdicts to `SUSPICIOUS` simply because the LLM used common reasoning words (like "indicates"). Removing it successfully allowed true positive threats (e.g., `PID 8312`) to reach the Threat Isolation pipeline.
- **The CFG vs. Trampoline Hallucination**: With ClaimGuard removed, a new hallucination bug was exposed in `v0.4.2_rocba`. The Defense Attorney evaluated `smartscreen.ex` (a truncated baseline process) against the `PROC_INJ_001` rule. Upon seeing standard Control Flow Guard (CFG) padding (`movabs rax`), the LLM hallucinated the presence of an indirect jump trampoline (e.g., `jmp rax`) and incorrectly failed to disprove the artifact, resulting in a false positive isolation.
- **The JIT Padding Reaction**: In `v0.4.3`, an attempt was made to fix this by explicitly instructing the playbook: *"You MUST NOT fail to disprove unless you explicitly see 'jmp'..."*. This backfired. The LLM became hyper-sensitive to the literal word `jmp`. When evaluating a different, legitimate process (`PID 19436 SearchApp.exe`), the LLM encountered benign JIT flow padding (`jmp 0x...` followed by `add byte ptr`). It saw the `jmp` instruction, panicked based on the new explicit playbook directive, and incorrectly isolated the benign process as a malicious trampoline.
- **Current State (Unresolved)**: The `v0.4.3` environment accurately detects the true positives in `cfreds` (Data Exfiltration via `.LNK` files). However, the `rocba` environment is currently suffering from a severe "whack-a-mole" false-positive loop related to `PROC_INJ_001`. 
- **Next Steps**: The `dfir_playbook.json` rule `FP_001_JIT_VERIFICATION` must be perfectly balanced so the LLM can reliably distinguish between:
  1. Benign CFG padding (`movabs rax` without a jump)
  2. Benign JIT flow (`jmp 0x...` followed by `add byte ptr` and `int3`)
  3. Malicious Trampolines (`movabs rax; jmp rax`)
  This must be achieved without making the LLM overly sensitive to literal `jmp` words or prone to hallucinating them when they are not present.
