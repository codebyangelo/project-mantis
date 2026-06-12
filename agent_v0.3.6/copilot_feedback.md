### Executive summary
**Goal for v0.3.6** — eliminate covert semantic shortcuts while preserving useful technical knowledge. Deliver a deterministic, low‑cost architecture that:  
- **Forbids** freeform semantic inference about intent.  
- **Allows** narrowly scoped technical recognition (JIT, RFC1918, cloud mounts) only when backed by explicit, verifiable telemetry citations.  
- **Fails safe** to benign when mechanical checks cannot fully support a malicious claim.  

Below is a concrete, implementable design that fits the host constraints (Celeron N4020, ~1.9GB RAM, ~4GB disk, no GPU) and the Zero Blackbox philosophy.

---

### High level comparison of candidate strategies
| **Strategy** | **Local CPU cost** | **Determinism** | **Effectiveness vs semantic overreach** | **Implementation effort** |
|---|---:|---:|---:|---:|
| **Large hardcoded playbook** | Low | High | Medium low (incomplete) | High |
| **Evidence anchoring + verifier** | Very low | Very high | High | Medium |
| **Small baseline DB + signed OSINT microservice** | Low (network) | High if signed | High | Medium |
| **Defense Attorney subagent** | Low (cloud LLM calls) | Medium-high | High for disproval | Medium |
| **Dynamic analyst-in-the-loop learning** | Very low | High after updates | High long-term | Low ongoing |

**Recommendation** Combine **Evidence anchoring + verifier**, a **compact baseline DB**, and a **Defense Attorney** subagent. Default to benign on insufficient mechanical support.

---

## 1. Solve the Knowledge Gap without bloating the playbook
**Principle** Keep the playbook minimal and deterministic; move volatile baseline knowledge into a small, queryable, signed baseline service and a local compact cache.

**Components**
- **Local Baseline Cache**  
  - A compact JSON (few MB) containing canonical technical facts: RFC1918 ranges, common cloud mount registry keys, canonical JIT process signatures (exe name + PE metadata fingerprint + typical RWX patterns), common sync mount points.  
  - Format is intentionally small: arrays of canonical patterns, regexes, and short fingerprints.  
  - Stored compressed and updated infrequently (signed manifest).  
- **Signed Baseline Manifest**  
  - Baseline updates are fetched rarely (weekly or on-demand) from a trusted internal endpoint. Each update is **cryptographically signed**. The orchestrator verifies signature before accepting new baseline entries. This prevents silent poisoning.  
- **On-demand microservice for rare lookups**  
  - For rare or ambiguous items not in the local cache, the orchestrator can call a small internal OSINT microservice that returns **signed, structured assertions** (e.g., `{"type":"JIT_SIGNATURE","subject":"SearchApp.exe","evidence":["CITATION1"],"signed":...}`). The microservice is strictly for lookup, not reasoning.  
  - If network is unavailable or the microservice returns nothing, the orchestrator treats the item as unknown and requires human review.

**Why this works**
- Keeps local memory footprint tiny.  
- Avoids hardcoding thousands of exceptions into the playbook.  
- Ensures deterministic behavior because all baseline facts are explicit, versioned, and signed.

---

## 2. The Intuition Leash — separate technical recognition from semantic intent
**Principle** Allow *technical* pretraining knowledge only when the LLM provides **verifiable telemetry citations**; forbid *semantic* pretraining judgments about intent.

### Enforceable rules encoded in the Orchestrator and Pydantic schemas
- **Schema fields the LLM may produce**
  - **technical_assertions**: array of objects `{artifact_id, assertion_type, quoted_evidence, byte_offset, checksum, predicate}`. Allowed types: `JIT_BEHAVIOR`, `PRIVATE_IP`, `CLOUD_MOUNT`, `RWX_USAGE`, `KNOWN_TOOL_SIGNATURE`. Each assertion must include exact quoted substrings and byte offsets.  
  - **semantic_inference**: **forbidden**. If the LLM outputs any field labeled `intent`, `motive`, `likely_actor`, or freeform narrative implying intent, the orchestrator rejects the response as noncompliant.  
  - **verdict**: only allowed values `MALICIOUS`, `BENIGN`, `UNDETERMINED`. A `MALICIOUS` verdict is accepted only if at least one `technical_assertion` is mechanically verified and the playbook rule mapping is exact-match and satisfied.
- **Strict acceptance criteria for technical assertions**
  - **Exact substring match**: `quoted_evidence` must exist verbatim at the claimed byte offset in the JSON cache.  
  - **Checksum match**: compute SHA-256 of the bytes at the offset and compare to `checksum`.  
  - **Predicate evaluation**: the `predicate` is a small deterministic expression (see next section) that the orchestrator evaluates locally. Example predicate: `ip_in_cidr(10.11.11.0/24) == true` or `rw_flag_count >= 1 and exec_region == true`.  
  - **Baseline confirmation**: if assertion_type requires baseline knowledge (e.g., JIT), the orchestrator checks the local baseline cache or signed microservice. The microservice returns a signed assertion that the orchestrator verifies.

### Concrete Pydantic additions
- Add `technical_assertions: List[TechnicalAssertion]` where `TechnicalAssertion` includes:
  - **artifact_id** string  
  - **assertion_type** enum  
  - **quoted_evidence** string  
  - **byte_offset** int  
  - **checksum** hex string  
  - **predicate** string (restricted grammar)  
  - **baseline_reference** optional string (baseline entry id or signed microservice id)

- Disallow any freeform `explanation` fields that contain un-cited narrative. If the LLM needs to explain, it must produce `explanation_citations` that are arrays of artifact ids and offsets.

**Effect** The LLM can say “SearchApp.exe exhibits RWX at offsets X–Y” but cannot say “SearchApp.exe is malicious because it’s a browser JIT” unless the baseline confirms that pattern and the evidence matches.

---

## 3. Deterministic predicate engine and verification pseudocode
**Principle** Keep verification local, cheap, and deterministic: string ops, regex, SHA-256, CIDR math.

### Minimal predicate grammar
- Operators: `==`, `!=`, `>`, `<`, `>=`, `<=`, `and`, `or`, `not`, function calls.  
- Allowed functions: `ip_in_cidr(ip, cidr)`, `contains(substring)`, `regex_match(pattern)`, `sha256_at(offset,length) == hex`, `n_gram_overlap(textA,textB)`.  
- No loops, no recursion, no external calls.

### Verification pseudocode
```python
for assertion in response.technical_assertions:
    raw = json_cache.get_bytes(assertion.artifact_id, assertion.byte_offset, len(assertion.quoted_evidence))
    if raw.decode('utf-8', errors='ignore') != assertion.quoted_evidence:
        mark_assertion_invalid("substring_mismatch")
        continue
    if sha256(raw) != assertion.checksum:
        mark_assertion_invalid("checksum_mismatch")
        continue
    if not evaluate_predicate(assertion.predicate, context=artifact_metadata):
        mark_assertion_invalid("predicate_failed")
        continue
    if assertion.assertion_type in baseline_required_types:
        if not baseline_confirms(assertion.baseline_reference):
            mark_assertion_invalid("baseline_missing")
            continue
    mark_assertion_valid()
```

**Acceptance rule for a MALICIOUS verdict**
- At least one `technical_assertion` must be **valid** and mapped to a **playbook rule** whose logic is satisfied by the predicates.  
- No `semantic_inference` fields may be present.  
- If any playbook rule used is a heuristic (non-deterministic), the verdict is downgraded to `UNDETERMINED` and flagged for analyst review.

---

## 4. Evidence normalization and canonicalization to prevent covert shortcuts
**Principle** Normalize telemetry so the LLM cannot exploit formatting differences to bypass checks or to smuggle semantic cues.

**Actions**
- **Canonical JSON escaping**: always present telemetry to the LLM in a canonical escaped form and require the LLM to quote evidence using the same canonicalization. This avoids the E:\ vs E:\\ mismatch seen previously.  
- **Token normalization**: normalize case, Unicode normalization, and path separators in the local cache. The LLM must use the normalized form in `quoted_evidence`.  
- **Reversible obfuscation for high-risk tokens**: for datasets known to trigger recall, apply deterministic reversible hashing to tokens before sending to the LLM. Keep mapping locally encrypted. This is optional if baseline and verifier are robust.

---

## 5. Multi-Agent Defense Attorney design
**Principle** Use a second agent only for structured, signed disprovals. The Defense Attorney is a constrained role, not a freeform adversary.

**Design**
- **Primary Agent** produces structured claims per the schema.  
- **Defense Attorney** receives the same sanitized telemetry and the primary agent’s structured claims. Its only allowed outputs are `disproof_assertions` with the same schema (artifact_id, quoted_evidence, byte_offset, checksum, predicate, baseline_reference). It may also return `signed_external_evidence` from the baseline microservice.  
- **Orchestrator adjudication rules**
  - If Defense Attorney produces a valid disproof that mechanically contradicts the primary assertion (e.g., shows the quoted evidence belongs to a known benign baseline entry), the verdict is downgraded to `UNDETERMINED` or `BENIGN`.  
  - If both agents agree and mechanical checks pass, accept verdict.  
  - If Defense Attorney fails to produce a valid disproof within a strict timeout, proceed with primary verdict only if mechanical checks are satisfied.

**Why this is safe**
- The Defense Attorney is constrained to the same citation trap and cannot rely on freeform OSINT narrative. It can call the signed baseline microservice for authoritative facts. This reduces single-agent bias while remaining deterministic.

---

## 6. Handling the Paradox of Intuition in practice
**Operational rules**
- **Default to benign** when mechanical verification is incomplete. Never convict on intuition.  
- **Human-in-the-loop escalation**: any `UNDETERMINED` case with high potential impact is queued for analyst review with full audit trail. Analysts can add baseline entries which are versioned and signed.  
- **Progressive baseline learning**: when analysts confirm a new benign pattern (e.g., a new JIT), it is added to the baseline manifest and distributed signed. This keeps the system adaptive without allowing the LLM to invent rules.  
- **Metric-driven thresholds**: start permissive for acceptance of technical assertions (to avoid false negatives), then tighten thresholds as baseline coverage improves. Track false positive/negative rates and tune.

---

### Rollout plan for v0.3.6
1. **Implement schema changes** and local predicate engine. Unit tests for substring, checksum, predicate evaluation.  
2. **Create minimal baseline cache** with RFC1918, common cloud mount keys, and a short list of known JIT processes. Ship as v0.3.6 baseline v1.0.  
3. **Add Defense Attorney subagent** as an optional cloud LLM call with identical schema constraints.  
4. **Run CFREDS and ROCBA regression tests** with strict audit logging. Verify that previously observed covert semantic overreach is caught by the orchestrator and downgraded to UNDETERMINED or BENIGN.  
5. **Deploy analyst workflow** for rapid baseline updates.  
6. **Monitor metrics** for 30 days and iterate.

---

### Risks, mitigations, and tradeoffs
- **Risk**: Overly strict predicates cause false negatives.  
  **Mitigation**: Start permissive, log rejections, and iterate thresholds; use analyst feedback loop.  
- **Risk**: Baseline microservice introduces network dependency.  
  **Mitigation**: Local cache is authoritative; microservice is optional and signed.  
- **Risk**: Defense Attorney increases cloud calls and cost.  
  **Mitigation**: Make it optional and only invoked for high-impact or ambiguous cases.

---

### Final verdict for v0.3.6
Adopt a **citation-first architecture** with three pillars: **compact signed baseline**, **strict evidence-anchored schema and predicate verifier**, and a **constrained Defense Attorney** for structured disprovals. Enforce a fail‑safe default to benign and a human analyst feedback loop for baseline growth. This design is deterministic, CPU/RAM friendly, auditable, and prevents the LLM from covertly using semantic intuition to bypass the Zero Blackbox rules.
