**Bold summary:** **Use a cheap, deterministic “evidence-anchoring” pipeline: (1) sanitize known CTF identifiers with reversible salted hashes, (2) force the LLM to emit strict Pydantic JSON that cites artifact IDs and byte-offset checksums, and (3) have the Orchestration Layer mechanically verify every LLM claim with fast local predicates (regexes, exact-match, n‑gram overlap, numeric thresholds).** This combination prevents CTF-triggered recall while remaining CPU/RAM friendly.   [arXiv.org](https://arxiv.org/html/2512.02527v1)  [Github](https://github.com/technion-cs-nlp/hallucination-mitigation)

---

### Quick comparison of the three domains
| **Approach** | **Local CPU cost** | **Determinism** | **Ease to implement** | **Primary risk** |
|---|---:|---:|---:|---|
| **Prompting & framing** | **Low** | Medium | **Easy** | LLM still recalls dataset |
| **Orchestration + schemas** | **Low** | **High** | Medium | Requires careful predicate design |
| **Evidence obfuscation (hashing)** | **Very low** | High (if reversible) | **Easy** | Mapping complexity for analysts |

---

### 1) System Prompting & Cognitive Framing (cheap, but insufficient alone)
- **Technique:** Use a short, strict system prompt that *requires* the model to (a) only reference artifact IDs present in the JSON, (b) output a fixed Pydantic JSON schema, and (c) include for each claim a **list of artifact IDs + exact quoted substrings** that justify the claim.  
- **Why:** Framing reduces free-form storytelling and forces structured outputs the Orchestration Layer can parse. Literature shows structured interventions reduce hallucinations but do not eliminate model recall alone.   [arXiv.org](https://arxiv.org/html/2512.02527v1)
- **Limit:** Models may still invent plausible substrings; must be paired with mechanical checks.

---

### 2) Architectural Constraints (mechanical enforcement)
- **Pydantic schema (required fields):** `claim_type`, `confidence`, `artifact_ids[]`, `quoted_evidence[]`, `byte_offset_checksums[]`, `logical_predicates[]`. **LLM must fill these exactly.**
- **Mechanical verifier (Orchestration Layer):**
  - **Exact-match check:** For each `quoted_evidence`, verify the substring exists in the JSON cache at the claimed byte offsets; compute a local checksum (e.g., SHA-256) and compare to the `byte_offset_checksums`. Reject if mismatch.
  - **Predicate engine:** Implement a small deterministic rule engine (regexes, numeric thresholds, presence/absence tests) that evaluates `logical_predicates` (e.g., `contains_sql_error_log == true`). If predicates fail, mark claim as **UNSUPPORTED**.
  - **Provenance score:** Compute **n‑gram overlap** between claimed narrative and raw evidence; require minimum overlap (e.g., 30%) to accept nontrivial claims.
- **Failure mode:** If any mechanical check fails, the Orchestration Layer forces the LLM to either (a) retract the claim or (b) produce a conservative benign conclusion. This is deterministic and cheap (string ops + hashing).

---

### 3) Evidence Obfuscation (prevent dataset recognition)
- **Reversible salted hashing:** Before sending artifacts to the LLM, **replace high-risk tokens** (usernames, file paths, challenge names) with deterministic salted hashes (e.g., `CTF_USER_1 -> H1a2b3`). Keep a per-run mapping file encrypted locally for analyst review. This prevents the model from matching latent memory while preserving structural signals.  
- **Lightweight sanitization rules:** Only obfuscate tokens on a short whitelist (names, challenge-specific paths) to preserve forensic semantics (timestamps, sizes, hashes). This is CPU‑cheap (string replace + HMAC).  
- **Tradeoff:** Analysts must be able to reverse mapping; keep mapping small and encrypted.

---

### Recommended final pipeline (deterministic, cheap)
1. **Sanitize** JSON: apply reversible salted hashing to known high-risk tokens.  
2. **Sieve**: pass top suspect artifacts with artifact IDs and byte offsets.  
3. **Prompt**: strict system prompt requiring Pydantic JSON with `artifact_ids`, `quoted_evidence`, `byte_offset_checksums`, and `logical_predicates`.  
4. **LLM call** (cloud): LLM returns structured JSON.  
5. **Verify** locally: exact-match substring checks, checksum compare, predicate evaluation, n‑gram overlap. If any check fails, mark claim UNSUPPORTED and request re-evaluation or default to benign.  
6. **Audit log**: store mapping and all checks for reproducibility.

---

### Pros / Cons & Risks
- **Pros:** Deterministic, reversible, CPU‑cheap (string ops + hashing), prevents dataset recall, auditable.  
- **Cons:** Requires careful predicate design; may increase false negatives if predicates too strict.  
- **Mitigation:** Start with permissive thresholds, iterate with real cases, log rejections for analyst review.   [Github](https://github.com/technion-cs-nlp/hallucination-mitigation)  [Nature](https://www.nature.com/articles/s41598-025-31075-1)

