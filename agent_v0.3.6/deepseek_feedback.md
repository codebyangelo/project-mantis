## Deliberation for Mantis v0.3.6: Forging the Deterministic‑Intuition Divide

The audit of v0.3.5 reveals that the Citation Trap fixed *factual* hallucination, but the system is still poisoned by **semantic intuition** and **rule‑application bypass**. The LLM is exploiting its pre‑training to convict innocuous artifacts (resignation letters, private IPs, JIT‑legitimate RWX) and misusing playbook rules to force a guilty verdict. We must separate *technical baseline knowledge* from *semantic prejudice*, and we must take rule selection out of the LLM’s hands entirely.

Below is a concrete architectural proposal for v0.3.6 that respects the N4020 hardware limits, uses only the existing Vertex AI endpoint, and turns the paradox into a resolved, staged adversarial process.

---

## 1. Deterministic Rule Assignment – Removing the “Rule Hallucination” Vector

**Problem:** The LLM mapped a registry‑exfiltration finding to `PERSISTENCE_001` (autorun keys) simply to obtain a guilty label, completely ignoring the rule’s logic. This is fatal for a Zero‑Blackbox engine.

**Solution: Sever the LLM from rule selection.**
- The **Heuristic Sieve** (deterministic Python) will now be responsible for **assigning candidate playbook rules** based on the artifact’s technical fingerprint.  
  - Example: a registry key with path `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` triggers autorun rules; a process with `MEMORY_PROTECTION = RWX` triggers code injection rules; a suspicious file write triggers exfiltration rules, etc.  
  - This uses simple keyword/path matching on the JSON evidence cache—cheap, predictable, never wrong.
- The **LLM (Prosecutor)** is then invoked with a strict prompt: *“You are given an artifact and exactly ONE playbook rule. Your only job is to verify if the evidence **satisfies all conditions** of that rule. You must cite the exact telemetry strings that fulfil each condition. If any condition is not met, you must return INCONCLUSIVE. You are forbidden from applying any other rule.”*
- The Orchestration FSM loads the rule’s definition from `dfir_playbook.json` and injects it into the prompt verbatim, leaving zero room for creative rule substitution.

**Impact:** The LLM can no longer “shop” for a convenient rule. Every conviction is mechanically tied to the correct rule. This instantly kills the PERSISTENCE_001 hallucination.

---

## 2. The Knowledge Gap – A Curated, Living IT Baseline KB

**Problem:** The model lacks basic IT baseline awareness (RFC 1918, Google Drive mount points, JIT compiler processes) and thus generates embarrassing false positives.

**Constraint:** We cannot hardcode every exception into the playbook; the list would be unmaintainable.

**Solution: A lightweight `baseline_kb.json` that is injected into a dedicated Defense Attorney subagent.**
- The knowledge base contains:
  - **Network:** All RFC 1918 subnets, common cloud private IPs (e.g., metadata endpoints), typical localhost aliases.
  - **Mount Points & Paths:** Known cloud sync roots (`G:\My Drive`, `C:\Users\...\OneDrive`, `~/Dropbox`, etc.) and their registry counterparts.
  - **JIT‑Legitimate Executables:** A curated list of binaries that legitimately use `PAGE_EXECUTE_READWRITE` due to JavaScript/WebView JIT (e.g., `SearchApp.exe`, `msedge.exe`, `chrome.exe`, `Teams.exe`, Electron‑based apps).
  - **System Benign Artifacts:** Windows built‑in tasks, standard browser cache folders, common benign mutexes.
- This KB is a tiny JSON file (a few KB). It is maintained externally (by the community/analysts) and loaded into the agent’s memory at startup.
- It is **never** used to convict. It is only used to propose benign explanations.

This gives the system the “IT common sense” it lacked, without over‑fitting the playbook or inviting the LLM to hallucinate.

---

## 3. The Intuition Leash – The Defense Attorney Subagent

**Problem:** How do we let the LLM recognise a Google Drive mount (a technical fact) but forbid it from inferring that a “Resignation_Letter.docx” is malicious exfiltration based solely on the file name?

**Core Insight:** The human‑readable name of a file is **not a technical indicator**; it is semantic intent. Allowing the LLM to process raw names inevitably activates its language understanding, leading to the exact semantic overreach observed.

**Solution: A two‑tier evidence presentation and an adversarial Defense Attorney.**

### Tier 1 – Obfuscation for the Prosecutor
- Before the **Prosecutor** (primary LLM call) ever sees the evidence, all **user‑created file names, custom folder names, and arbitrary string labels** are tokenized using the salted SHA‑256 method from our earlier design.  
  *Example:* `Resignation_Letter.docx` → `FILE_A3F2C1.docx`. The file extension is preserved (technical relevance), but the semantic payload is stripped.
- **Known baseline names are left intact** using the baseline KB. The sanitizer checks every string against the KB’s list of known benign paths and mount points; if a path prefix matches a known cloud sync folder (e.g., `G:\My Drive\`), it is **kept verbatim**. All other arbitrary names are obfuscated.
- The Prosecutor therefore cannot form a “resignation = insider threat” narrative. It can only analyse technical indicators: file size, timestamps, location (anonymised, unless it’s a known benign mount), and the actual byte signatures present in the telemetry.

### Tier 2 – The Defense Attorney (Full Picture)
- If the Prosecutor returns a **MALICIOUS** verdict, the FSM triggers a **Defense Attorney subagent** (a second LLM call, same cheap Flash‑Lite model).
- This subagent receives **the original, un‑obfuscated evidence** (or at least the de‑tokenized version) **plus** the `baseline_kb.json` fully expanded in the prompt.
- Its system directive:  
  *“You are a defense analyst. Your sole task is to disprove the accusation using technical baseline knowledge and general IT knowledge. You must find plausible benign explanations. You may use your training to recognise patterns (e.g., ‘Chromium JIT requires RWX memory’), but you are absolutely forbidden from using the semantic meaning of user‑created file names or human‑readable strings as evidence of intent. If a file name only suggests a feeling (like resignation), that is NEVER a reason to uphold the conviction. You must either exonerate on technical grounds, or uphold the conviction only if no benign technical explanation exists.”*
- The Defense Attorney’s output is a strict schema: `verdict` (OVERRULED_BENIGN or UPHELD_MALICIOUS) with mandatory `citations` (from the evidence) and `benign_explanation` if overruled.

This creates a clean **Separation of Concerns**:
- The **Prosecutor** works on sanitised, intent‑free evidence and is forced to apply only the assigned rule.
- The **Defense Attorney** has full context (including unobfuscated names) but is legally bound to ignore semantic intent and to use its knowledge only for **exoneration**.
- The final verdict is taken from the Defense Attorney. The system never convicts on a Prosecutor’s word alone.

---

## 4. Adversarial Multi‑Agent Workflow for v0.3.6

The complete triage pipeline for a Suspect Entity becomes:

1. **Deterministic Rule Assignment** – Sieve assigns exact rule(s) based on artifact type.
2. **Evidence Sanitisation** – Tokenize all non‑baseline file/path/name strings. Produce a clean JSON block.
3. **Prosecutor Call** – LLM receives sanitised evidence + assigned rule + “Zero Blackbox” prompt. Returns `VERDICT` (MALICIOUS, INCONCLUSIVE, BENIGN) with citation‑anchored reasoning.
4. **Guard Check** – Orchestrator validates citations and rule compliance. If MALICIOUS, proceed.
5. **Defense Attorney Call** – Receives original evidence (de‑tokenized, complete with names) + baseline KB + Prosecutor’s accusation. Prompt heavily restricts against semantic‑intent conviction. Returns OVERRULED or UPHELD.
6. **Final Verdict** – Orchestrator adopts the Defense Attorney’s decision. For OVERRULED, the entity is cleared (benign); for UPHELD, the entity is flagged as true malicious.
7. **Report Generation** – De‑tokenized human‑readable report uses the preserved mapping.

**Resource analysis:** Every step is a lightweight API call or a local O(1) string operation. No new local models, no memory bloat. The `baseline_kb.json` and tokenization dict are trivial (<1MB). The entire sequence adds ~2 seconds of LLM latency per entity, well within triage tolerance.

---

## 5. Answering the Direct Questions

1. **The Knowledge Gap** – Solved by a separate, updatable `baseline_kb.json` injected only into the defense context, not into the playbook. It is maintained as curated IT common sense, shielded from misuse because it can only exonerate.

2. **The Intuition Leash** – Achieved by **sanitising semantic names for the Prosecutor** (breaking language‑driven prejudice) while **allowing the Defense Attorney to see original strings under a strict rule that forbids semantic inference**. The technical baseline (e.g., “Google Drive mount”) is recognised via the preserved, un‑obfuscated known‑good paths from the KB. The model’s technical knowledge is used only to defend, never to attack.

3. **Multi‑Agent Defense** – Absolutely yes. The Defense Attorney subagent is the cornerstone of v0.3.6. It transforms the system from a single‑point‑of‑failure LLM into a self‑correcting adversarial court. It uses exactly the model’s latent OSINT/IT knowledge that we previously feared, but it chains that knowledge to a strict, pro‑benign mandate and a technical‑only citation requirement. This is not just a workaround; it is the architectural expression of the Presumption of Benignity itself.

---

## Conclusion

v0.3.6 must evolve from a single‑judge system to a **Deterministic Prosecutor + Adversarial Defense Attorney** framework. Rule selection is removed from the LLM, semantic taint is stripped from the prosecutor’s input, and the defense subagent is empowered to apply broad IT knowledge—but only to acquit. This design keeps the engine lightweight, respects the hardware, and permanently closes the intuition paradox. The “Resignation Letter” will never be convicted again, and private IPs will be instantly recognised as benign.
