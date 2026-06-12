# Project Mantis: Orchestrator (`orchestrator.py`)

## 1. Overview and Top-Down Architecture

The `orchestrator.py` module serves as the central brain and Finite State Machine (FSM) for Project Mantis (v0.5.2), an Autonomous Digital Forensics and Incident Response (DFIR) engine. The script orchestrates the entire incident analysis lifecycle: taking raw telemetry from a parsed cache, redacting sensitive information, assessing entities using deterministic rules or LLM evaluations, performing dynamic queries (disk/memory pivoting), managing multi-agent adversarial debates, and concluding with a cryptographically hashed markdown report.

The orchestrator integrates multiple sub-systems:
- **Baseline Engine**: Compares artifacts against known environmental baselines (`baseline_kb.json`).
- **Deterministic Sieves**: Fast-path classifiers that avoid LLM overhead by directly analyzing specific telemetry patterns (like `malfind` allocations).
- **Multi-Agent Evaluation**: Utilizes `MantisAgent` to spawn Prosecutor, Defense Attorney, and Verifier LLMs to vigorously debate the benign or malicious nature of an entity.
- **Dynamic Pivot Mechanisms**: Follow-up mechanisms like DSL-based fact retrieval, deep memory/registry carving, and disk timeline pivots to synthesize the full execution chain of malware.
- **Reporting & Safety**: Hard grounding mechanisms against hallucinations, auto-sanitization of incident containment recommendations to avoid blocking legitimate subnetways, and exhaustive reporting.

---

## 2. Core Operational Flow (FSM Loop)

The entire logic centers around `run_fsm_loop()`, which follows this top-down execution logic:

1. **Initialization**: It initializes by reading the playbook and environment baseline.
2. **Sieve Extraction**: Identifies suspicious entities using `get_suspect_entities(api_budget=30)`.
3. **Telemetry Obfuscation**: Uses predefined regex mapping (`KNOWN_FINGERPRINTS`) to redact PII and CTF flags.
4. **Baseline Tagging**: The `BaselineEngine` analyzes the evidence and injects relevant baseline tags.
5. **Deterministic Bypass**: If applicable (e.g., `malfind` data), a deterministic classifier (`MalfindClassifier`) assigns a verdict. If matched, it bypasses initial LLM assessment.
6. **Prosecutor Evaluation**: If not deterministically convicted, the main LLM Evaluator acts as the "Prosecutor," returning a strongly-typed Pydantic result (`MantisEvaluation`). This result is validated against a Hard Grounding Layer (checking if the LLM's quotes precisely match the actual evidence).
7. **Dynamic Follow-Ups**: The LLM can dynamically trigger MCP cache queries, disk searches, DSL evidence retrievals, or deep memory/hive carvings. Evidence is appended and the LLM re-evaluates.
8. **Adversarial Debate System**:
    - **Prosecutor Conviction**: If the Prosecutor convicts an entity (`MALICIOUS`).
    - **Defense Attorney**: A new LLM session challenges the ruling, tasked with finding a baseline/playbook exception. The orchestrator employs a **Citation Trap** to ensure the Defense Attorney doesn't hallucinate.
    - **Verifier / Judge**: If the Defense Attorney proposes an override, a third Verifier LLM acts as the ultimate arbiter, adjudicating the debate and issuing the final verdict.
9. **Post-Conviction Pipeline**: If confirmed `MALICIOUS`, the orchestrator queries the disk timeline for the suspect PID, fetching artifacts for an `ExecutionChainSynthesis` to identify droppers and narratives.
10. **Report Generation**: Aggregates results into a comprehensive MITRE ATT&CK mapped report, enriched with NIST containment steps.

---

## 3. Bottom-Up Function Analysis

### 3.1. Telemetry Handling and Logging
* **`KNOWN_FINGERPRINTS`**: A global dictionary containing regex patterns to replace sensitive data with predefined placeholders (e.g., `cfreds` -> `DATASET_ALPHA`).
* **`obfuscate_telemetry(evidence: dict) -> tuple[dict, dict]`**: Converts evidence to a JSON string, maps known fingerprints using regex, and returns the obfuscated dictionary and the mapping dictionary (for later restoration).
* **`restore_telemetry(text: str, mapping: dict) -> str`**: Substitutes obfuscated placeholders in text back to their original values based on the mapping generated during obfuscation.
* **`write_thought_ledger(phase: str, component: str, details: str)`**: Appends raw execution logs and detailed JSON data into a hardened `thoughts.txt` log (`THOUGHTS_PATH`), ensuring auditable trails of API inbound/outbound exchanges.

### 3.2. LLM and External API Interactions
* **`safe_api_call(chat_session, prompt: str, max_retries: int = 3, schema_model=MantisEvaluation) -> BaseModel`**: 
    - Paces the LLM API requests with a 4-second sleep to respect RPM limits.
    - Captures the exact input prompt to the thought ledger.
    - Executes the query, enforces structured Pydantic schema validation (`schema_model.model_validate_json`), logs token consumption, and catches/retries transient API failures via exponential backoff.
* **`update_ioc_store(new_finding: str)`**: Performs a safe, atomic write operation to the historical IOC JSON store. Uses a `.tmp` file and `os.rename` to prevent corruption during concurrent modifications.

### 3.3. Context Resolvers
* **`get_disk_image() -> str`** and **`get_memory_image() -> str`**: Read the `context.json` from the cache directory to dynamically resolve the absolute file paths for raw memory dumps or disk images.

### 3.4. Reporting Engine
* **`generate_mitre_report(results: list, agent_system=None)`**: The final output forge.
    - Iterates over all evaluated entities to segregate `MALICIOUS`, `SUSPICIOUS`, and `BENIGN` targets.
    - Extracts `MitreMapping` from results to generate a list of mapped ATT&CK techniques based on the MITRE dictionary.
    - If `MALICIOUS` targets exist, queries the agent system's `synthesize_investigation()` method to generate a high-level executive narrative.
    - **NIST Alignment & Safe Containment Filtering**: Appends Incident Lifecycle phases. The function implements an IP filtering system (`check_rec`). It parses IP addresses from the LLM's containment recommendations and checks them against corporate subnets/Microsoft CDNs from `baseline_kb.json`. Any recommendation instructing the user to block a baseline IP is heavily tagged as `[REJECTED BY AUTOMATION]`.
    - Automatically calculates token cost totals.
    - Saves the report and signs it with a trailing SHA-256 cryptographic hash of its own contents.

### 3.5. The Core FSM Function (`run_fsm_loop`)
A deep dive into `run_fsm_loop(chat_session, agent_system=None)` logic boundaries:

1. **Initializations**: Instances `BaselineEngine` and parses environmental knowledge. Fetches suspects via Sieve.
2. **Iteration over Entities**: Uses a `for ent in entities:` loop. Obfuscates telemetry and injects baseline tags dynamically.
3. **Deterministic Fast-Path Bypass**: Uses `sieve_deterministic.MalfindClassifier` on specific process memory structures. Automatically assigns verdicts like `MALICIOUS` matching standard memory rules, forging an `AuditTrail` indicating `Deterministic Regex` compliance.
4. **Primary LLM Evaluation (Prosecutor)**:
    - Constructs prompts including environmental context and playbook rules.
    - Parses output via `safe_api_call`.
    - **Hard Grounding Layer**: Checks if the LLM's `exact_telemetry_quote` explicitly exists inside the raw JSON evidence string. Uses aggressive whitespace normalization and unescaping for strict validity. Failure instantly drops the confidence verdict to `SUSPICIOUS`.
5. **Tool Orchestration / Feedback Loops**:
    - `request_mcp_query_cache_name`, `request_disk_search`, `request_evidence_dsl`: Interprets these fields in the `MantisEvaluation` object, maps them to Python sub-processes or native search functionalities (e.g., `search_disk_timeline`), and feeds the parsed output back into the LLM as a dynamically extended prompt loop.
    - `request_deep_carve`: Resolves the specific entity to either physical disk image offset or memory offset and triggers deep analysis (e.g., `carve_memory_strings` or `extract_and_carve_hive`).
6. **Multi-Agent Evaluation & Hallucination Safeties**:
    - Initiates **Defense Attorney** if the initial LLM determines `MALICIOUS`.
    - **Defense Citation Trap**: Verifies the defense attorney's specific citations strictly exist in the baseline or obfuscated evidence strings. Failing the trap prevents the defense from acting on hallucinated strings.
    - If overrules legitimately, invokes the **Verifier** instance to analyze the argument strictly across `PROSECUTOR vs DEFENSE`. 
    - Bypasses this entire multi-agent hierarchy if the conviction was achieved natively via deterministic logic.
7. **Post-Conviction Pivots**:
    - If final status is `MALICIOUS`, extracts PID, searches the disk timeline, and utilizes the `recon_session` to reconstruct execution pipelines, dropper paths, and full timelines using the `ExecutionChainSynthesis` schema.
    - Persists these chains into the atomic IOC store.

### 3.6. Initialization (`verify_and_trigger_cache`, `main`)
* **`verify_and_trigger_cache()`**: Fast-fails if `context.json` does not exist, demanding the user run the extractor pipeline first.
* **`main()`**: Uses `argparse` to handle `--deep` flags, instantiates global Singletons like the `MantisAgent`, and traps `KeyboardInterrupt` for clean operational shutdowns.

---

## 4. Key Design Patterns and Robustness Mechanisms

- **Defense-In-Depth Grounding**: The orchestrator inherently untrusts LLM output. The `exact_telemetry_quote` logic and the "Citation Trap" ensure LLMs cannot confidently condemn or exonerate artifacts using hallucinated telemetry.
- **Fail-Open Safe Recommendations**: The `check_rec(rec)` mechanism within `generate_mitre_report` mitigates the massive risk of LLMs automatically suggesting firewall blocks on essential infrastructure (like domain controllers or Microsoft CDNs), preventing self-inflicted denial of service.
- **Dynamic Feedback Execution**: It doesn't use standard Tool Calling structures but rather deeply parses JSON schemas (Pydantic objects) for explicit tool demands, performs the operations natively, and pushes a dynamic "Follow-Up" prompt to the LLM agent.
- **Execution Reconstruction Pipeline**: Integrates memory artifacts (Process Injection) directly with disk artifacts (NTFS Timelines) by parsing isolated PIDs and tracing backwards in time dynamically.
- **Deterministic Pre-emption**: Saves API budget by applying traditional forensic algorithms where clear indicators exist before routing grey-area entities to LLM evaluation.
