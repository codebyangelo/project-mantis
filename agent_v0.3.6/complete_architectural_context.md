# Complete Architectural Context

This document serves as the final architectural summary for **Project Mantis**, tracing its evolution from a nascent ReAct-based prototype (v0.0.1) to a robust, deterministic forensic framework (v0.3.2).

---

## 1. Architectural Evolution
Project Mantis began as a simple CLI-based wrapper around Gemini using a basic ReAct loop to process static text files. Through iterative development, it transitioned into a **state-machine-driven architecture** characterized by four distinct layers:

*   **Extraction Layer:** Modular integration with `Volatility 3` and `The Sleuth Kit` to produce searchable JSON evidence caches.
*   **Heuristic Sieve:** A deterministic "attention mechanism" that filters thousands of artifacts down to a prioritized "Suspect Entity" list, ensuring LLM context windows are utilized efficiently.
*   **Orchestration Layer:** A Finite State Machine (FSM) that maintains the investigative lifecycle, manages API rate limits, and enforces a "Presumption of Benignity."
*   **Intelligence Layer:** A Pydantic-enforced LLM wrapper that prevents hallucination by constraining model output to strict JSON schemas (`AgentCommand`), effectively utilizing the LLM as a logical processor rather than a generative one.

---

## 2. Major Shifts and Capabilities
The project underwent three critical architectural shifts:
1.  **Transition to Deterministic Filtering:** Moving from "ask the LLM everything" to "score with heuristics, verify with LLM."
2.  **Surgical Carving:** The move from bulk data analysis to dynamic, on-demand byte-level memory/disk carving, which significantly reduced the forensic "noise" injected into the context window.
3.  **Schema Enforcement:** The adoption of Pydantic models in v0.3.x finalized the transition from a conversational agent to a programmatic forensic engine.

---

## 3. Function and Logic
Project Mantis serves as an autonomous triage engine. It transforms raw, unstructured memory and disk dumps into a structured incident report. By mapping forensic artifacts to MITRE ATT&CK techniques, the framework enables a standardized, auditable, and rapid response to potential compromises without requiring constant manual expert intervention.

---

## 4. The Zero Black Box Issue: Hallucinated Narratives
In the v0.3.2 context, Project Mantis encountered a critical failure mode designated as the **"Zero Black Box Issue."** 

During the triage of a memory sample, the LLM was provided with a subset of raw evidence logs, including process metadata and network connection strings. However, due to the LLM's pre-existing training data concerning the popular **CFREDS (Computer Forensics Reference Data Sets)** CTF challenges, the agent bypassed the provided raw evidence. Instead of analyzing the specific, provided memory strings—which indicated a standard, non-malicious system state—the model hallucinated a high-fidelity narrative of a complex SQL injection attack and exfiltration event. 

The LLM "reasoned" that the presence of common system artifacts (e.g., `svchost.exe`, `powershell.exe`) coupled with its training data regarding CFREDS scenarios necessitated a malicious verdict. The model effectively ignored the fact that the provided registry and process trees were benign, prioritizing its "latent knowledge" of the CTF challenge's solution over the raw, local forensic telemetry. This highlights the fundamental hazard of LLM-based forensics: when the model is trained on public forensic challenges, it may prioritize "solving the challenge" based on training bias rather than "triaging the evidence" based on actual data.

## 5. Hardware Constraints (CRITICAL)
Project Mantis must operate within the extreme physical constraints of its host machine:
*   **CPU**: Intel(R) Celeron(R) N4020 @ 1.10GHz (2 Cores)
*   **RAM**: ~3.6 GB Total (~1.9 GB available)
*   **Disk**: 135 GB Total, with only 4.1 GB available (97% full)
*   **GPU**: None

These constraints dictate that we cannot run local LLMs or load massive datasets into memory at once. All logic must be computationally cheap locally, relying heavily on cloud APIs and dynamic, surgical data carving.

---
Remember to use gemini-3.1-flash-lite, include a 4 second sleep delay, and use exponential rollback error handling.