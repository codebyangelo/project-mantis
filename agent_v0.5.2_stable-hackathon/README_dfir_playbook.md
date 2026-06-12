# DFIR Playbook Documentation

## Overview
This document provides an in-depth analysis of the `dfir_playbook.json` file (Version 1.0.1). It is a highly structured Digital Forensics and Incident Response (DFIR) playbook mapped to the NIST SP 800-61r2 incident response lifecycle. The playbook is uniquely designed to serve as an evaluation matrix for security automation and Large Language Models (LLMs), featuring explicit rules of engagement and structural constraints that actively prevent LLM hallucinations.

## NIST SP 800-61r2 Mapping
The playbook natively maps to the **NIST SP 800-61r2** incident handling guide, specifically focusing on the **Detection & Analysis** phase. Every rule within the playbook outlines the precise NIST step: **Analyze Indicators**. This structure ensures that automated systems or LLMs processing incident alerts act consistently within standard procedural frameworks, accurately classifying findings as valid indicators of compromise (IOCs) before proceeding to containment or eradication.

## Evaluation Matrices
Each detection rule in the playbook functions as an evaluation matrix. The schema consists of:
- **Identification:** `rule_id`, `name`, `threat_category`
- **Context:** `target_artifact` (e.g., process, file, registry_hive)
- **Evaluation Logic:** A set of logical constraints (`conditions` and `conjunction`) requiring specific telemetry fields to match predefined operators (e.g., `regex_match`, `contains`) against target values. 
- **MITRE ATT&CK Mapping:** Comprehensive mappings detailing Tactics, Techniques, and Procedures (TTPs) for threat intelligence enrichment.
- **Severity Context:** Defined incident impact (`severity_if_confirmed`).

## Rules of Engagement & Mitigating LLM Hallucinations
The playbook is specifically engineered to control LLM behavior, enforce strict analytical rigor, and prevent generative hallucinations. It achieves this through the `false_positive_disproval` matrix for each rule:

### 1. Hard Constraints on Subjective Analysis
- **Deterministic Offloading (`AUDIT_ONLY` role):** Rule `PROC_INJ_001` (`FP_001_JIT_VERIFICATION`) explicitly forbids the LLM from attempting to classify assembly patterns. It delegates this task to a deterministic script (`sieve_deterministic.py`). The LLM is structurally constrained to an `AUDIT_ONLY` role, preventing it from hallucinating non-existent shellcode or memory anomalies.
- **Strict Conditional Logic:** Each false positive check uses rigid `disproval_logic` (e.g., `IF X AND Y THEN DISPROVE`). This pseudo-code enforces decision trees that the LLM must follow rather than generating arbitrary rationalizations.

### 2. Guardrails Against Contextual Assumptions
- **Mandatory `INCONCLUSIVE` States:** Rules like `DATA_EXFIL_001`, `DATA_EXFIL_002`, and `EXECUTION_001` explicitly warn the LLM that if the provided telemetry lacks sufficient context (such as destination paths or intent), the evaluation *must* result in an `INCONCLUSIVE` state. This directly mitigates the LLM's tendency to assume or invent missing contextual data.
- **Bypassing Social Engineering in Metadata:** In rule `USB_LNK_001` (`FP_011_AUTHORIZED_MEDIA`), the playbook explicitly warns the LLM that an external drive labeled "Authorized USB" is still unauthorized removable media. This restricts the LLM from being fooled by manipulated volume names or semantic traps.

### 3. Forced Action Sequences
- **Prescribed Tool Execution:** To evaluate certain rules, the playbook forces the LLM to request specific actions rather than inferring outcomes. 
  - `PROC_INJ_001` (`FP_002_DYNAMIC_TIMELINE_CORRELATION`): Instructs the LLM to dynamically use `request_disk_search`.
  - `PERSISTENCE_001` and `USB_EXFIL_001`: Forces the LLM to set `request_deep_carve=true` to extract strings. Furthermore, it instructs the LLM to ignore unrelated artifacts (like `.docx` files) returned by the generic carve tool, constraining its attention to only the relevant persistence markers.

## Detailed Rule Breakdown

### 1. Process Injection
- **PROC_INJ_001: RWX Memory Allocation in System Process**
  - **Threat:** Defense Evasion (T1055)
  - **False Positive Checks:**
    - JIT/Trampoline verification (Strictly deterministic, LLM is Audit Only).
    - Microsoft Defender (`MsMpEng.exe`) internal emulation environment.
    - Dynamic timeline correlation for fileless payloads (forces disk search).

### 2. Defense Evasion
- **PROC_MASQ_001: Process Name Masquerading**
  - **Threat:** Defense Evasion (T1036)
  - **False Positive Checks:** Account for legitimate 15-character Windows kernel EPROCESS truncations (e.g., `smartscreen.ex`).

### 3. Data Exfiltration
- **DATA_EXFIL_001 / DATA_EXFIL_002: Staging Archives & LNK Leakage**
  - **Threat:** Exfiltration (T1048)
  - **False Positive Checks:** Identifies corporate backups or benign personal downloads. Forces INCONCLUSIVE if target context is missing.
- **USB_EXFIL_001 / USB_LNK_001: Removable Media Activity**
  - **Threat:** Exfiltration (T1052.001)
  - **False Positive Checks:** Differentiates corporate network shares from unauthorized physical media, explicitly ignoring misleading volume labels. Forces deep string carving.

### 4. Collection & Execution
- **COLLECTION_001: Automated Collection Script in Temp**
  - **Threat:** Collection (T1119)
  - **False Positive Checks:** Legitimate system installers/updaters.
- **EXECUTION_001: Dropped Executable Payload**
  - **Threat:** Execution (T1204)
  - **False Positive Checks:** Verified self-extracting installers. 

### 5. Anti-Forensics & Persistence
- **ANTI_FORENSICS_001: Data Destruction and Evidence Concealment**
  - **Threat:** Impact (T1485)
  - **False Positive Checks:** Authorized IT decommissioning workflows.
- **PERSISTENCE_001: Malicious Registry Hive Persistence**
  - **Threat:** Persistence (T1547.001)
  - **False Positive Checks:** Forces deep carving. Focuses the LLM strictly on startup/autorun keys and signed baseline DLLs (e.g., OneDrive), filtering out irrelevant background noise.
