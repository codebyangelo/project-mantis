# Project Mantis - Agent Module Documentation (`agent.py`)

## 1. Overview and Architectural Top-Down

The `agent.py` module is the core intelligence engine for **Project Mantis**, functioning as a deterministic Digital Forensics and Incident Response (DFIR) evaluation executor. It is designed to evaluate artifacts (telemetry, processes, memory structures, disk timelines) and render highly structured, strict, and logic-bound verdicts.

### Key Architectural Principles
* **LLM Agnostic Provider Pattern:** The core design abstracts the underlying Large Language Model (LLM) provider. Through environment variables, the agent can seamlessly switch between Google's Vertex AI (Gemini) and any OpenAI-compatible API endpoint (such as local Ollama instances, Groq, Cerebras, Nvidia, or OpenAI directly).
* **Strict Determinism via Structured Outputs:** The application relies heavily on `pydantic` to enforce strict JSON schemas for every interaction with the LLM. This guarantees that unstructured generative text is coerced into parsable forensic objects.
* **Adversarial Persona Architecture:** The evaluation process is split into several "personas" or sessions:
  * **Prosecutor (The core Mantis Evaluator):** Evaluates artifacts against playbooks to find malicious behavior.
  * **Defense Attorney:** Challenges the Prosecutor's findings using environmental baselines.
  * **Verifier:** A final deterministic auditor ensuring logic is sound between the Prosecutor and Defense.
  * **Reconstruction Analyst:** Connects memory payloads to disk artifacts for attack timeline generation.
  * **Lead Investigator:** Synthesizes isolated findings into a cohesive executive report.

---

## 2. Data Models (Bottom-Up Context)

The module defines several `pydantic` models that dictate the exact structure the LLMs must return. 

### Core Evaluation Models
* **`ChainOfThoughtStep`**: Represents a single logical deduction step, forcing the LLM to cite rules and evidence values transparently before reaching a localized result.
* **`FalsePositiveCheck`**: Forces the engine to actively attempt to disprove its own findings using environmental context.
* **`RuleApplied`**: Captures the specific playbook rule and NIST framework phase being evaluated.
* **`VerdictInfo`**: The final determination (MALICIOUS, SUSPICIOUS, BENIGN) accompanied by confidence levels and the `exact_telemetry_quote` (a required character-for-character substring from raw telemetry to prevent hallucinations).
* **`MitreMapping`**: Connects the behavior to MITRE ATT&CK tactics, techniques, and procedures.
* **`AuditTrail`**: Boolean flags and explanations validating whether the evaluation remained deterministic, compliant with the playbook, and free from subjective judgment.

### Specialized Action Request Fields
Within `MantisEvaluation`, the engine can request further dynamic context if the initial telemetry is insufficient (e.g., fileless payloads):
* `request_deep_carve`: Boolean indicating if a deeper memory/disk carve is needed.
* `request_mcp_query_cache_name` / `request_mcp_query_keyword`: Requests query execution against specific cached datasets (like `pstree`, `netscan`, `malfind`).
* `request_disk_search`: Searches for context within the disk timeline.
* `request_evidence_dsl`: Executes Evidence-Only DSL queries directly.

### Persona Specific Models
* **`MantisEvaluation`**: The massive compound object returned by the initial Prosecutor evaluation containing all the above models.
* **`VerifierEvaluation`**: Simple `PASS` or `REJECT` verdict with strict reasoning based on verbatim matches.
* **`ExecutiveSynthesis`**: A highly structured incident response report containing Who, What, Where, How, When, a cohesive narrative, and distinct containment/eradication/post-incident recommendations.
* **`DefenseEvaluation`**: Returns `OVERRULED_BENIGN` or `FAILED_TO_DISPROVE`, complete with benign explanations and raw `citations`.
* **`ExecutionChainSynthesis`**: Reconstructs the timeline, identifying the initial dropper file and the resulting memory payload execution chain.

---

## 3. Core Components and Functions

### `OpenAIChatSession` Class
A specialized wrapper designed to mimic session states for non-Vertex LLMs.
* **Initialization:** Accepts the client, model name, system instructions, temperature, and the expected Pydantic schema.
* **`send_message(prompt)`**:
  * Tries to use the native structured parsing available in `openai >= 1.40` (`response_format=self.schema_model`).
  * Implements a fallback mechanism for generic local APIs (like LMStudio or Ollama) by temporarily injecting the JSON schema representation into the system prompt and enforcing `{"type": "json_object"}`.
  * Wraps the response in `MockResponse` and `MockUsage` classes to ensure the interface strictly matches the object shapes returned by Vertex AI, guaranteeing cross-provider compatibility for downstream processors.

### `MantisAgent` Class
The primary entry point that orchestrates the personas.

#### Initialization (`__init__`)
* Resolves the `PM_LLM_PROVIDER` environment variable (defaults to `vertex`).
* **Vertex Path:** Configures `genai.Client` using `VERTEX_API_KEY` or `VERTEX_PROJECT_ID` / `VERTEX_LOCATION`. Defaults to `gemini-3.1-flash-lite`.
* **OpenAI/Compatible Path:** Imports `openai`, uses `OPENAI_API_KEY` and `OPENAI_BASE_URL` allowing connections to local inference servers.
* **System Instructions (The Rules Engine):** Injects an aggressive and highly restrictive prompt that mandates:
  * Zero authority to use internal LLM knowledge.
  * Presumption of Benignity (Assume everything is benign until proven otherwise).
  * Strict execution of every `false_positive_disproval` check.
  * The "Citation Trap" (If a verdict is MALICIOUS, an exact substring must be quoted).
  * A clear `Verdict Decision Matrix` based on partial/full condition matches and false positive evaluations.

#### Session Generators
Each method generates a chat session (either native Vertex or the custom `OpenAIChatSession`) locked into a specific system instruction and Pydantic schema output at `temperature=0.0` (to enforce determinism):

* **`create_session()`**: Uses the core Mantis system instructions and `MantisEvaluation` schema. Acts as the initial evaluator/prosecutor.
* **`create_defense_session()`**: Spawns the Defense Attorney persona. Evaluates if the Prosecutor misapplied logic or missed a benign `baseline_tag`. Bound to the `DefenseEvaluation` schema.
* **`create_verifier_session()`**: Spawns the Verifier. Audits the first two steps for logic flaws or hallucinations. Bound to the `VerifierEvaluation` schema.
* **`create_reconstruction_session()`**: Analyzes cross-dimensional evidence (disk events + memory injection) to reconstruct execution chains. Bound to `ExecutionChainSynthesis`.

#### `synthesize_investigation(isolated_threats: list) -> ExecutiveSynthesis`
Unlike the deterministic evaluators running at `0.0` temperature, this method generates the final human-readable executive report at a slightly higher temperature (`0.2`) for better narrative cohesion.
* **Input Sanitization:** Recursively parses the `isolated_threats` dictionary/list, nullifying binary `\x00` characters and truncating fields longer than 500 characters to prevent prompt injection attacks or massive token burn from raw forensic dumps.
* **Baseline Injection:** Reads `baseline_kb.json` from the local directory (if it exists) to inform the LLM about internal infrastructure (preventing false attribution of internal IPs as C2 nodes).
* **Execution:** Iterates over all threats, builds a monolithic prompt containing verdicts and sanitized evidence, and calls the LLM provider to return the heavily structured `ExecutiveSynthesis`.
* **Telemetry & Tracking:** Logs precise token usage metrics (In/Out/Total) via the `ExecutionLogger`.

---

## 4. Summary

`agent.py` is an incredibly rigid, adversarial LLM pipeline. Instead of relying on an LLM to simply "find bad stuff," it forces the LLM through a mock courtroom scenario (Prosecutor, Defense, Verifier) where every conclusion must be deterministically backed by exact character citations from the raw data. It cleanly bridges the gap between unstructured LLM reasoning and the heavily structured data requirements of automated incident response systems.
