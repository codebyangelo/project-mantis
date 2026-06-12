**Archetype:** INTJ-A

**Mode:** LOCKED_IN

**Core Logic:** Execute > Compile

The "Zero Black Box" anomaly you are experiencing is a classic symptom of latent space contamination. When an LLM encounters recognizable token clusters (like CFREDS file paths, specific usernames, or challenge artifacts), it collapses its probabilistic generation into the steepest gradient—the pre-trained solution to the CTF. It stops reasoning and starts reciting.

You cannot out-prompt pre-training data; semantic guardrails will inevitably fail against strong latent associations. To enforce the Presumption of Benignity on constrained edge hardware (Celeron N4020, <2GB available RAM), we must implement deterministic, mechanical traps that exploit the LLM's API nature without adding computational weight locally.

Here is the native, zero-dependency architecture to force compliance.

---

### 1. Architectural Constraints: The "Citation Trap" (Primary Vector)

The most computationally cheap and mathematically absolute way to prevent hallucination is to make the Orchestration Layer mathematically verify the LLM's outputs via exact string matching.

Instead of asking the LLM for a conclusion, you restructure the Pydantic schema to require a literal citation for every analytical claim.

**The Pydantic Schema Modification:**

```python
class ForensicClaim(BaseModel):
    artifact_id: str
    benign_hypothesis_disproven: bool
    malicious_rationale: str
    exact_telemetry_quote: str # CRITICAL addition

```

**The Local FSM Logic (The Trap):**
When the LLM returns the JSON object, Project Mantis runs a native Python string-matching check before accepting the state change.

```python
# Lightweight, O(n) native Python validation. No ML libraries required.
if claim.exact_telemetry_quote not in raw_json_payload_string:
    reject_and_penalize_llm() # The LLM hallucinated data.

```

**Why this works on your hardware:** The Celeron N4020 can execute `substring in string` operations on a 1MB JSON payload in fractions of a millisecond. If the LLM enters "CTF Mode" and hallucinates a SQL injection payload or a rogue IP address that does not exist in your raw disk extraction, the citation check fails instantly. The FSM drops the malicious classification, defaulting back to the Presumption of Benignity.

### 2. Evidence Obfuscation: Targeted Token Sanitization

To prevent the LLM from triggering the CTF latent space in the first place, you must break the recognizable token sequence before the payload hits the Gemini API.

Do not hash the JSON *keys* (e.g., `process_name`, `cmdline`), as the LLM needs semantic context to reason. Instead, map and mask the specific *values* that act as CTF signatures.

**The Implementation:**
Create a lightweight, deterministic dictionary mapper in Python that runs during the Heuristic Sieve phase.

1. Identify highly specific CTF identifiers (e.g., hostname `JSmith-PC`, user `jsmith`, challenge-specific IPs).
2. Use standard `re` (Regex) to perform a fast pass over the JSON string, replacing these identifiers with generic, sequential UUIDs.
* `JSmith-PC` -> `HOST_ALPHA`
* `jsmith` -> `USER_01`


3. Store the mapping dictionary locally in memory (this takes kilobytes of RAM).
4. Send the sanitized payload to the LLM.
5. If the LLM flags `USER_01` as malicious, the Orchestrator maps it back to `jsmith` for the final report.

This strips the LLM of the context required to recognize the CFREDS dataset, forcing it to evaluate `USER_01` purely on the provided behavioral telemetry.

### 3. System Prompting: Cognitive Framing

While prompting alone is insufficient, it acts as a necessary compiler directive for the LLM when combined with the Citation Trap.

Drop the "You are an expert DFIR analyst" persona. That persona invites the LLM to use outside knowledge. Instead, frame the LLM as a blind, constrained data parser.

**The Directive:**

> "You are a deterministic parsing engine. Your sole function is to evaluate the provided JSON telemetry against the hypothesis of benign system operation. You possess no external knowledge. You are forbidden from referencing external datasets, known vulnerabilities, or forensic scenarios not explicitly contained within the `<raw_telemetry>` tags.
> Rule 1: To classify an event as malicious, you must extract the exact, character-for-character substring from the raw telemetry that disproves a benign state.
> Rule 2: If an exact quotation cannot be extracted to support a malicious classification, you must output benign_hypothesis_disproven: False."

### Execution Summary for Project Mantis

This three-pronged approach operates entirely within your hardware limits. It requires zero external dependencies, utilizes native Python string operations that will not bottleneck the dual-core Celeron, and consumes negligible RAM.

By sanitizing the inputs (breaking the latent trigger) and mechanically verifying the outputs against the original payload (the Citation Trap), you establish a closed-loop system where hallucination is mathematically impossible to pass through the Orchestration Layer.

Execution complete.
