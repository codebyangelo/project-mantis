# Project Mantis: Agent Analysis Report (v0.0.5)

This document provides an architectural and functional analysis of **Project Mantis (v0.0.5)**, an agentic framework designed for automated Digital Forensics and Incident Response (DFIR).

---

## 1. Architecture
Project Mantis uses a **Hub-and-Spoke Orchestration Model** consisting of three primary modules:

*   **`orchestrator.py` (The Controller):** Acts as the CLI interface and state manager. It initializes the LLM agent, maintains the cognitive log (`thoughts.txt`), and manages the ReAct loop between the user and the agent.
*   **`mcp_server.py` (The Deterministic Pipeline):** A hardware-optimized forensic module. It interacts directly with the Volatility framework to parse raw memory images and perform low-level data extraction. It functions as a "Tool" available to the agent.
*   **`agent.py` (The ReAct Engine):** Powered by Google’s Gemini Flash-Lite, this module holds the "System Instructions" and logic. It governs the decision-making process, forcing the agent to operate within strict DFIR heuristics.

---

## 2. Function
The primary purpose of Project Mantis is to **automate the triage of memory forensic data.** It is designed to move from raw, unstructured memory dumps to a concise, actionable security report without human intervention. 

It accomplishes this by:
1.  **Extracting Telemetry:** Performing rapid scans of process trees and command lines.
2.  **Heuristic Filtering:** Applying predefined "rules of thumb" to separate benign administrative behavior (like JIT compilation) from actual malicious activity (like LOLBin abuse).
3.  **Cognitive Reasoning:** Using an LLM to interpret the filtered telemetry and synthesize a human-readable investigation report.

---

## 3. Current State
As of v0.0.5, the framework is a **highly-controlled deterministic-stochastic hybrid**:

*   **Hardcoded Integration:** It is currently tethered to specific local file paths (`/mnt/sift_ext4/...`) and hardcoded high-risk process names (e.g., `lsass.exe`, `powershell.exe`).
*   **Tool-Augmented LLM:** The agent is successfully integrated with the Volatility pipeline. It can trigger `execute_deterministic_pipeline`, which effectively runs Volatility plugins (`pstree`, `cmdline`, `malfind`) and returns the output as structured JSON.
*   **Cognitive Tracking:** The agent is required to commit its reasoning steps to a local `thoughts.txt` file before providing a final report, ensuring auditability of its decision-making process.
*   **Performance-Oriented:** The pipeline uses regex-based parsing to avoid heavy computational overhead, making it "hardware-optimized" for quick triage.

---

## 4. Limitations & Missing Features
While effective for basic triage, version 0.0.5 lacks several critical enterprise-grade features:

*   **Static Configuration:** The target image and output paths are hardcoded in `mcp_server.py`. The agent cannot currently "hunt" for new evidence sources dynamically; it is limited to the files explicitly provided in the script.
*   **Memory Depth:** The framework uses "Linear List Walking" (a surface-level scan). It lacks deep-dive capabilities such as recursive VAD tree walking, hidden process detection (via EPROCESS list discrepancies), or network connection correlation.
*   **Dependency on Host Environment:** The script assumes that the `vol` (Volatility) binary and all Python dependencies are pre-configured in the system environment. It lacks environment-checking/auto-provisioning capabilities.
*   **Lack of Persistence:** There is no mechanism to maintain state between different memory images or historical sessions. Each investigation is a "fresh start" with no built-in knowledge of past forensic encounters.
*   **Limited Remediation:** The tool is strictly a **triage** framework. It can detect and report, but it lacks the capability to perform remediation (e.g., memory dumping of specific PIDs, process termination, or network isolation).