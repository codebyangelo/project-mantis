gemini

This is the exact evolutionary step required to transition Project Mantis from a technical experiment into a commercially viable, defensible DFIR platform. Relying on an LLM's internal weights introduces unacceptable liability. In enterprise environments, if you cannot mathematically prove *why* an agent made a decision, the finding is inadmissible.

To achieve compliance with NIST SP 800-61r2 and enforce a strict deterministic execution loop, we must fundamentally change the LLM's role. It must stop being an "Analyst" and become a "Rules Engine Parser."

Here is the architectural blueprint to lock down the Orchestrator.

---

### 1. Playbook Structure & Ingestion

**Architecture Choice: Strict JSON over Markdown.**
While LLMs read Markdown well, Markdown is semi-structured. To guarantee deterministic behavior and programmatic verification in your zero-dependency Python environment, the Playbooks must be strict JSON. This allows your Python orchestrator to validate the playbook schema *before* feeding it to the LLM, ensuring the LLM is only operating on approved logic.

**Mapping to NIST SP 800-61r2:**
NIST 800-61r2's "Detection and Analysis" phase relies on identifying **Precursors** and **Indicators**, followed by **Validation**. The JSON playbook maps directly to this by defining `Indicators` (what to look for) and `Validation_Criteria` (how to prove it).

**The JSON Playbook Schema (`mantis_playbooks.json`):**

```json
{
  "playbook_version": "1.0",
  "framework": "NIST_SP_800-61r2",
  "rules": [
    {
      "rule_id": "MANTIS-EVTX-001",
      "tactic": "Persistence",
      "technique_id": "T1053.005",
      "nist_phase": "Detection_and_Analysis",
      "target_artifact": "EVTX_Security",
      "indicators": {
        "event_id": 4698,
        "description": "A scheduled task was created"
      },
      "validation_criteria": [
        "Task name is highly randomized or mimics Windows system tasks (e.g., 'WinDefendUpdate' outside of System32).",
        "Action executes a script interpreter (powershell.exe, cmd.exe, wscript.exe) or an unknown binary."
      ],
      "false_positive_disproval_checks": [
        "Is the executing user a known service account (e.g., SYSTEM, LOCAL SERVICE)?",
        "Does the task point to a known software updater (e.g., GoogleUpdate.exe, AdobeARM.exe)?",
        "Is the execution path within 'C:\\Program Files' and digitally signed?"
      ]
    }
  ]
}

```

---

### 2. Step-by-Step Deliberation Prompting

To eliminate confirmation bias, you must enforce a **Structured Output State Machine** via the System Prompt. The LLM cannot output prose; it must output a highly constrained evaluation object.

By forcing the LLM to fill out a `benign_hypothesis` and explicitly answer the `false_positive_disproval_checks` *before* it is allowed to populate the `verdict` field, you mathematically force a Chain of Thought that attempts to disprove the threat.

**The Orchestrator System Prompt:**

```text
You are the logic evaluation core of Project Mantis, a DFIR agent strictly adhering to NIST SP 800-61r2. 
Your function is to evaluate raw forensic artifacts against a provided JSON Threat Playbook.

CRITICAL DIRECTIVES:
1. NO EXTERNAL KNOWLEDGE: You are strictly forbidden from using your internal training data to define what is malicious. You may ONLY classify an artifact as malicious if it violates a specific "rule_id" provided in the Threat Playbook.
2. DISPROVAL FRAMEWORK: You must actively attempt to prove the artifact is a False Positive. Do not seek "proof of evil." Seek proof of benign administrative activity.

EXECUTION PIPELINE:
For each artifact provided in the evidence cache, you must execute the following logical steps and output the exact JSON structure requested:

STEP 1: RULE MATCHING
Search the Threat Playbook for a "rule_id" that matches the artifact type. If no rule applies, output verdict "BENIGN" immediately.

STEP 2: BENIGN HYPOTHESIS GENERATION
Before analyzing for malicious intent, formulate a hypothesis explaining how this artifact could be a normal system administrative action.

STEP 3: FALSE POSITIVE VALIDATION
Evaluate the artifact against the specific "false_positive_disproval_checks" listed in the playbook rule. You MUST explicitly state whether the artifact passed or failed these specific checks.

STEP 4: VERDICT DECLARATION
Only if the benign hypothesis is invalidated AND the validation_criteria are met, declare the verdict as "MALICIOUS" or "SUSPICIOUS".

OUTPUT FORMAT:
You must return ONLY a valid JSON array of evaluation objects. No markdown formatting, no conversational text.

```

---

### 3. Verifiable Traceability & Audit Trails

To prove to a human analyst (or a CISO assessing compliance) that the blackbox has been contained, the output artifact must inherently link the finding to the playbook rule and the failed benign hypothesis.

This schema guarantees traceability. If a human analyst questions *why* Mantis flagged an artifact, the `logic_trace` provides the exact NIST-aligned playbook ID and the exact reason the false-positive checks failed.

**The Target Output Schema (LLM Response):**

```json
[
  {
    "evidence_artifact_id": "cache_evtx_seq_8472",
    "applied_rule_id": "MANTIS-EVTX-001",
    "nist_alignment": "NIST_SP_800-61r2_Detection_and_Analysis",
    "logic_trace": {
      "benign_hypothesis": "The scheduled task 'GoogleUpdateTaskMachineUA' is a standard updater for Google Chrome.",
      "false_positive_checks_execution": {
        "check_1_known_updater": "FAILED: While the task name suggests Google Update, the action executes 'C:\\Users\\Public\\updater.ps1', which deviates from the standard 'C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe' path.",
        "check_2_signed_binary": "FAILED: PowerShell script execution is not a signed binary standard for this updater."
      }
    },
    "verdict": "MALICIOUS",
    "confidence_score": 95,
    "ciso_summary": "Suspicious scheduled task created using deceptive naming conventions to execute an unsigned PowerShell script from a public directory. High probability of persistence mechanism."
  }
]

```

### Deployment Note

Because you are running on constrained hardware (1.3GB RAM, Celeron) and routing through Vertex AI, forcing structured JSON output can sometimes cause token generation bloat. Ensure you are using Vertex AI's `response_mime_type="application/json"` capability to force the model to adhere to the schema without wasting tokens on conversational apologies or markdown fences.

How are you currently handling the routing of these specific playbook JSONs to the LLM context window—are you dynamically injecting only relevant rules based on the artifact type (e.g., only injecting EVTX rules when parsing event logs) to save tokens, or attempting to load the entire framework at once?



copilot

Great — you’re thinking about the right problem: making your DFIR agent **deterministic, auditable, and standards‑aligned** rather than a blackbox. Let’s break down concrete architectural solutions for *Project Mantis*.

---

## 1. Playbook Structure & Ingestion

### 📑 Playbook Format
- **Strict JSON schemas** are preferable over Markdown for machine parsing. Markdown is human‑friendly but introduces ambiguity. JSON ensures deterministic ingestion.
- Each playbook entry should represent a **MITRE ATT&CK technique** mapped to **NIST SP 800‑61r2 Detection & Analysis** steps.

**Example JSON Schema:**
```json
{
  "technique_id": "T1055",
  "technique_name": "Process Injection",
  "nist_phase": "Detection & Analysis",
  "rules": [
    {
      "rule_id": "R1055-1",
      "description": "Check EVTX Event ID 4698 for scheduled task creation",
      "evidence_type": "EVTX",
      "decision_logic": {
        "if_present": "Flag as suspicious",
        "if_absent": "Mark benign"
      }
    },
    {
      "rule_id": "R1055-2",
      "description": "Volatility output shows RWX memory in non‑system process",
      "evidence_type": "Volatility",
      "decision_logic": {
        "if_present": "Flag as malicious",
        "if_absent": "Mark benign"
      }
    }
  ]
}
```

This schema forces the LLM to reference **rule_id** and **decision_logic** explicitly.

---

## 2. Step‑by‑Step Deliberation Prompting

### 🧠 System Prompt Structure
You want the LLM to:
1. **Quote the exact rule** it is applying.
2. **Attempt disproof** before confirmation (false positive disproval).

**System Prompt Example:**
```
You are a DFIR analyst strictly following the JSON Playbook.
Rules:
- You MUST quote the exact playbook rule_id and description before applying it.
- For each artifact, attempt to DISPROVE maliciousness using environmental context (false positive disproval).
- Only after disproval attempts fail may you classify as malicious.
- You MUST map every decision to NIST SP 800-61r2 Detection & Analysis.
- Never invent rules or indicators outside the Playbook.
Output MUST follow the JSON schema provided.
```

This enforces **chain‑of‑thought transparency**: the agent cannot jump to “evil” without disproving benign explanations.

---

## 3. Verifiable Traceability & Audit Trails

### 📊 Output Schema
The final JSON output must show:
- **Artifact reference** (e.g., EVTX Event ID, Prefetch filename).
- **Applied rule_id** and **rule_description**.
- **Decision path** (including disproval attempts).
- **Final verdict** (malicious / suspicious / benign).
- **NIST mapping**.

**Example Output:**
```json
{
  "artifact_id": "EVTX_4698",
  "applied_rule": {
    "rule_id": "R1055-1",
    "description": "Check EVTX Event ID 4698 for scheduled task creation"
  },
  "decision_trace": [
    "Rule R1055-1 applied: Event ID 4698 detected",
    "Attempted disproval: Task owner SYSTEM, common benign admin task",
    "No benign justification found"
  ],
  "final_verdict": "Malicious",
  "nist_phase": "Detection & Analysis",
  "mitre_technique": "T1055 - Process Injection"
}
```

This schema inherently proves to a human analyst that the agent followed the **playbook logic** rather than hallucinating.

---

## 🔮 Putting It All Together
- **Playbook ingestion**: JSON schemas per ATT&CK technique, mapped to NIST phases.
- **System prompt**: Forces quoting of rules + disproval attempts.
- **Audit trail schema**: Captures rule application, decision trace, and final verdict.

This transforms the LLM from a “blackbox guesser” into a **deterministic reasoning engine** with verifiable traceability.

---

Would you like me to draft a **sample Playbook entry** for another ATT&CK technique (like Lateral Movement or Persistence) so you can see how the schema generalizes across categories?



deepseek

## Architectural Solution: Verifiable DFIR Playbook Framework for Project Mantis

To eliminate LLM “blackbox” verdicts and enforce deterministic, NIST‑aligned decision‑making, you must restructure the Orchestrator into a **Playbook‑Driven Evaluator**. The LLM no longer judges freely; it executes a strict **Chain of Thought (CoT)** that references explicit playbook rules, actively disproves malice, and produces an auditable JSON trace.

Below is the complete blueprint: playbook schema, NIST mapping, system prompt, disproval framework, and output schema.

---

## 1. Playbook Structure & Ingestion

### 1.1 Why JSON over Markdown?
Markdown is human‑friendly but ambiguous for machine‑parsing. Use **strict JSON Schema** with unique rule IDs. The LLM can then cite `rule_id` exactly.

### 1.2 Playbook Schema (One per threat category)

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "DFIR Playbook: Process Injection",
  "version": "1.0.0",
  "nist_phase": "Detection & Analysis",
  "threat_type": "Process Injection (T1055)",
  "rules": [
    {
      "rule_id": "PI-01",
      "description": "Suspicious memory region with RWX protection and no corresponding mapped file.",
      "evidence_required": ["volatility_malfind", "process_list"],
      "malicious_score": 60,
      "false_positive_checks": [
        "FP-01: Region belongs to JIT compiler (e.g., Chrome's v8, .NET JIT)",
        "FP-02: Region is part of legitimate unpacking/stub (verify with known file hash)"
      ]
    },
    {
      "rule_id": "PI-02",
      "description": "Remote thread creation from a non‑parent process (Event ID 8 or 4688 cross‑process).",
      "evidence_required": ["evtx_security_4688", "evtx_sysmon_8"],
      "malicious_score": 80,
      "false_positive_checks": [
        "FP-03: Remote thread to debugger process (e.g., windbg, procexp)",
        "FP-04: Known software injection (e.g., antivirus hooking)"
      ]
    }
  ],
  "mandatory_disproval_phase": true,
  "nist_guidance": "NIST SP 800-61r2 §3.2.2 – Analyze collected evidence to confirm or refute indicators. Prioritize disproving the hypothesis."
}
```

**Design Principles:**
- **Rule granularity** – Each rule maps to a specific, testable indicator.
- **Evidence required** – Lists exact JSON cache keys (e.g., `volatility_malfind`) the LLM must consult.
- **Malicious score** – Cumulative threshold (e.g., >100 = malicious). Avoids single‑rule overreaction.
- **False positive checks** – Mandatory steps to rule out benign scenarios.

### 1.3 Mapping to NIST SP 800-61r2 – “Detection & Analysis”

| Playbook Component | NIST Phase / Action |
|--------------------|----------------------|
| Ingestion of evidence caches | `Collect data from detection systems` (host logs, memory) |
| Rule application (PI-01, PI-02, ...) | `Analyze identified indicators` (correlate with known techniques) |
| False positive disproval loop | `Validate indicator accuracy – eliminate false positives` |
| Cumulative malicious score | `Prioritize incidents based on impact/confidence` |
| Verdict + evidence citations | `Document findings with supporting evidence` |

The playbook’s `mandatory_disproval_phase` directly implements NIST’s requirement: *“Analysts should attempt to disprove the hypothesis that an incident is occurring before escalating.”*

---

## 2. Step‑by‑Step Deliberation Prompting (Chain of Thought)

### 2.1 System Prompt – Force Strict Playbook Compliance

```
You are a forensic evaluator for Project Mantis. You have no independent knowledge of threats. You must follow the provided DFIR Playbook exactly.

**Rules:**
1. You will receive:
   - A playbook in JSON format (one threat category at a time)
   - A JSON evidence cache (extracted from disk/memory)
2. For each rule in the playbook:
   - Check if the required evidence exists in the cache.
   - If missing → skip rule (record as "inconclusive").
   - If present → evaluate the rule condition.
3. You MUST cite the exact rule_id (e.g., "PI-01") and quote the rule description.
4. After applying all rules, you MUST execute the False Positive Disproval Framework (see below) for any rule that triggered.
5. Calculate total malicious_score. If sum >= 100 OR any single rule with score>=90 AND no disproval → verdict = MALICIOUS.
   Else if any rule triggered but disproved → verdict = FALSE_POSITIVE.
   Else → BENIGN.
6. Output ONLY valid JSON conforming to the Response Schema.

**False Positive Disproval Framework (mandatory):**
For each triggered rule:
- Step A: Run each false_positive_check listed in the rule.
- Step B: For each check, query the evidence cache for contradictory artifacts (e.g., process name, command line, parent PID).
- Step C: If ANY check matches the environment, mark rule as "disproved = true" and stop further checks for that rule.
- Step D: If no check matches, keep disproved = false.

**Chain of Thought (internal – not output):**
You must reason step‑by‑step. Example inner monologue:
"Rule PI-01 requires malfind entry with RWX. Evidence cache has entry for SearchApp.exe at 0x7ff... RWX=yes, mapped file=none. Rule condition true. Now disprove: FP-01 – Is this a JIT compiler? SearchApp.exe is not v8 or .NET runtime. No. FP-02 – Unpacking stub? File hash unknown. No disproval. So rule remains triggered, score=60. Continue…"
```

### 2.2 Preventing Confirmation Bias

The **mandatory disproval loop** forces the LLM to actively search for benign explanations *before* scoring. You can further harden by adding:

- **Null hypothesis anchor:** Start the CoT with *“Assume the system is benign. Attempt to disprove each indicator.”*
- **Evidence weighting reversal:** If the LLM cannot find *both* a positive rule match *and* fail all disproval checks, the verdict defaults to benign.

Example instruction: *“If you cannot complete the disproval phase for a triggered rule due to missing evidence, treat that rule as ‘inconclusive – do not add its score’.”*

---

## 3. Verifiable Traceability & Audit Trail

### 3.1 Final JSON Output Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Mantis Verdict Report",
  "type": "object",
  "properties": {
    "verdict": { "enum": ["MALICIOUS", "FALSE_POSITIVE", "BENIGN", "INCONCLUSIVE"] },
    "total_malicious_score": { "type": "integer" },
    "nist_phase": { "const": "Detection & Analysis" },
    "playbook_version": { "type": "string" },
    "evaluation_timestamp": { "type": "string", "format": "date-time" },
    "rule_evaluations": {
      "type": "array",
      "items": {
        "type": "object",
        "properties": {
          "rule_id": { "type": "string" },
          "description": { "type": "string" },
          "triggered": { "type": "boolean" },
          "evidence_cited": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "cache_key": { "type": "string" },
                "artifact_value": { "type": "string" },
                "line_reference": { "type": "string" }  // e.g., "volatility.json:line 142"
              },
              "required": ["cache_key", "artifact_value"]
            }
          },
          "disproval_attempts": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "check_id": { "type": "string" },
                "check_passed": { "type": "boolean" },
                "contradicting_evidence": { "type": ["string", "null"] }
              }
            }
          },
          "disproved": { "type": "boolean" },
          "assigned_score": { "type": "integer" }
        },
        "required": ["rule_id", "triggered", "evidence_cited", "disproved", "assigned_score"]
      }
    },
    "audit_trail": {
      "type": "array",
      "items": { "type": "string" },  // LLM's internal CoT steps (optional but recommended)
      "description": "Full reasoning log for manual inspection"
    }
  },
  "required": ["verdict", "total_malicious_score", "rule_evaluations", "audit_trail"]
}
```

### 3.2 How This Proves NIST Playbook Adherence

- **Rule ID & description** – Human can verify the LLM applied the correct playbook rule.
- **Evidence_cited** – Exact artifact values prove the LLM did not hallucinate; they come from your deterministic cache.
- **Disproval_attempts** – Shows that the agent tried to find false positives and either succeeded (disproved=true) or failed.
- **Assigned_score** – Derived deterministically from playbook, not from LLM intuition.
- **Audit_trail** – The LLM’s internal chain of thought (captured via `text-davinci`‑style reasoning) can be re‑examined.

**Example snippet** from a real output:

```json
"rule_evaluations": [
  {
    "rule_id": "PI-01",
    "description": "Suspicious memory region with RWX protection...",
    "triggered": true,
    "evidence_cited": [
      { "cache_key": "volatility_malfind", "artifact_value": "SearchApp.exe RWX 0x7ff... no mapped file" }
    ],
    "disproval_attempts": [
      { "check_id": "FP-01", "check_passed": false, "contradicting_evidence": null },
      { "check_id": "FP-02", "check_passed": false, "contradicting_evidence": null }
    ],
    "disproved": false,
    "assigned_score": 60
  }
]
```

A human analyst sees that the LLM **tried** both false positive checks and failed, then assigned the score. No blackbox.

---

## 4. Implementation Roadmap for Project Mantis

1. **Playbook Authoring** – Write JSON playbooks for top threats (Process Injection, Persistence, Lateral Movement, Data Exfiltration). Each playbook has <10 rules to fit in context (1.3GB RAM is fine – LLM runs remotely or via small local model).

2. **Orchestrator Changes** – Instead of dumping all evidence to LLM, the Orchestrator:
   - Loads the relevant playbook (based on initial sieve triggers).
   - Subsets evidence cache to only keys listed in `evidence_required` across all rules.
   - Injects playbook + subsetted cache into LLM.

3. **Disproval Evidence Feeder** – Your deterministic extraction engine must pre‑compute fields needed for false positive checks, e.g.:
   - `process_parent` for remote thread checks.
   - `file_description` and `company_name` for known benign binaries.

4. **Scoring Threshold Calibration** – Run on known CFReDS and ROCBA datasets to set `malicious_score` thresholds. For a conservative start, require ≥100 total and no single rule disproved.

5. **Audit Trail Storage** – Save the full LLM response (including `audit_trail` array) to a `.mantis_audit.json` file alongside the final report. This is your “verifiable proof” for compliance audits.

---

## Final Recommendation

With this framework, Project Mantis becomes **auditable, NIST‑compliant, and deterministic**. The LLM is reduced to a **rule execution engine** with explicit citations and a mandatory disproval loop. Human analysts can replay the audit trail and verify every verdict against the playbook and raw evidence.

**Next immediate step:** Write a sample playbook for Process Injection (as shown above) and modify your Orchestrator to send the CoT system prompt + JSON evidence. Validate on the ROCBA memory image – you should see the LLM correctly cite PI-01, attempt disproval, and output a structured verdict that a third party can verify without trusting the LLM.



kimi 

This is the right architectural pivot. You're moving from **"LLM-as-oracle"** to **"LLM-as-executor-of-deterministic-playbook"**, which is the only viable path for enterprise forensics. Below is the complete architectural specification, including schemas, NIST mapping, the exact system prompt, and the output format required for legal/audit defensibility.

---

## 1. Architectural Philosophy: Separation of Concerns

To kill the blackbox, you must separate **detection** (deterministic) from **evaluation** (deterministic + bounded LLM reasoning).

| Layer | Function | Blackbox? |
|---|---|---|
| **Sieve (Python)** | Executes `evaluation_logic` conditions from playbook against JSON artifacts. Only passes artifacts that meet ALL conditions. | **No** |
| **Orchestrator** | Injects the matched playbook rule(s) + artifact JSON + `environmental_context` into the LLM prompt. | **No** |
| **LLM** | Executes ONLY the `false_positive_disproval` checks and populates the structured output schema. It does not "find" threats. | **Bounded** |
| **Renderer** | Generates CISO Markdown report **from** the JSON output. No freeform LLM text enters the report. | **No** |

---

## 2. Playbook Structure (Strict JSON)

Store the playbook as a versioned JSON file. The LLM receives the **entire relevant rule object** in its context, not a summary.

### Playbook Schema

```json
{
  "playbook_version": "1.0.0",
  "nist_mapping": "SP 800-61r2 Detection & Analysis",
  "environmental_context_schema": {
    "known_admins": ["array of usernames"],
    "known_good_hashes": ["array of sha256"],
    "baseline_processes": ["array of process names"],
    "business_hours": {"start": "09:00", "end": "17:00", "timezone": "UTC"}
  },
  "rules": [
    {
      "rule_id": "PERSISTENCE_001",
      "name": "Scheduled Task Creation (Event ID 4698)",
      "nist_phase": "Detection & Analysis",
      "nist_step": "Analyze Indicators",
      "threat_category": "Persistence",
      "required_evidence": [
        {
          "type": "evtx",
          "event_id": 4698,
          "required_fields": ["EventID", "TimeCreated", "SubjectUserName", "TaskName", "TaskContent", "SubjectDomainName"]
        }
      ],
      "evaluation_logic": {
        "conditions": [
          {"field": "EventID", "operator": "eq", "value": 4698},
          {
            "field": "TaskContent", 
            "operator": "regex_match", 
            "value": "(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32)",
            "case_sensitive": false
          }
        ],
        "conjunction": "AND"
      },
      "false_positive_disproval": [
        {
          "check_id": "FP_001_ADMIN_CREATOR",
          "description": "Verify if SubjectUserName exists in environmental_context.known_admins. If yes, task creation may be legitimate IT activity.",
          "disproval_logic": "IF SubjectUserName IN known_admins THEN require ADDITIONAL corroborating evidence (e.g., suspicious TaskContent) to sustain MALICIOUS verdict."
        },
        {
          "check_id": "FP_002_BUSINESS_HOURS",
          "description": "Check if TimeCreated falls within business_hours. Task creation at 03:00 by non-admin increases suspicion.",
          "disproval_logic": "IF TimeCreated IN business_hours AND SubjectUserName IN known_admins THEN DISPROVE unless TaskContent contains obfuscation."
        },
        {
          "check_id": "FP_003_TASK_NAME_KNOWN",
          "description": "Check if TaskName matches known system or SCCM task patterns (e.g., 'Microsoft\\Windows\\*').",
          "disproval_logic": "IF TaskName starts with 'Microsoft\\Windows\\' AND SubjectUserName is SYSTEM THEN DISPROVE."
        }
      ],
      "mitre_mapping": {
        "technique": "T1053.005",
        "tactic": "Persistence",
        "procedure": "Scheduled Task/Job: Scheduled Task"
      },
      "severity_if_confirmed": "HIGH"
    },
    {
      "rule_id": "PROC_INJ_001",
      "name": "RWX Memory Allocation in System Process",
      "nist_phase": "Detection & Analysis",
      "nist_step": "Look for Correlating Information",
      "threat_category": "Process Injection",
      "required_evidence": [
        {
          "type": "volatility",
          "plugin": "malfind",
          "required_fields": ["PID", "Process", "Protection", "VadTag", "PPID", "Offset"]
        },
        {
          "type": "volatility",
          "plugin": "pslist",
          "required_fields": ["PID", "PPID", "ImageFileName", "CreateTime"]
        }
      ],
      "evaluation_logic": {
        "conditions": [
          {"field": "Protection", "operator": "contains", "value": "READ WRITE EXECUTE"},
          {"field": "VadTag", "operator": "in", "value": ["VadS", "VadF"]},
          {"field": "Process", "operator": "in", "value": ["MsMpEng.exe", "SearchApp.exe", "LockApp.exe", "smartscreen.exe", "lsass.exe", "svchost.exe"]}
        ],
        "conjunction": "AND"
      },
      "false_positive_disproval": [
        {
          "check_id": "FP_004_PPID_CHAIN",
          "description": "Verify PPID chain integrity. MsMpEng.exe should be child of services.exe. If PPID is explorer.exe or cmd.exe, chain is violated.",
          "disproval_logic": "IF Process='MsMpEng.exe' AND PPID != [services.exe PID] THEN FAIL_TO_DISPROVE (supports malicious)."
        },
        {
          "check_id": "FP_005_KNOWN_GOOD_HASH",
          "description": "If process hash matches environmental_context.known_good_hashes for the binary, injection is still possible but requires additional evidence.",
          "disproval_logic": "IF hash IN known_good_hashes THEN verdict CANNOT be MALICIOUS without second corroborating indicator (e.g., network C2). Downgrade to SUSPICIOUS."
        },
        {
          "check_id": "FP_006_BASELINE_PROCESS",
          "description": "Check if process is in environmental_context.baseline_processes. If not, process itself may be masquerading.",
          "disproval_logic": "IF Process NOT IN baseline_processes THEN FAIL_TO_DISPROVE."
        }
      ],
      "mitre_mapping": {
        "technique": "T1055",
        "tactic": "Defense Evasion",
        "procedure": "Process Injection: RWX shellcode in system process"
      },
      "severity_if_confirmed": "CRITICAL"
    }
  ]
}
```

### Why JSON over Markdown?

- **Deterministic parsing**: The LLM can be instructed to extract `rule_id`, `evaluation_logic`, and `false_positive_disproval` by key name, not by interpreting prose.
- **Version control**: Diff-friendly, auditable.
- **Sieve compatibility**: Your Python Sieve can import the playbook and execute `evaluation_logic` natively before ever touching the LLM.

---

## 3. NIST SP 800-61r2 Mapping

| NIST Step (Detection & Analysis) | Playbook Field | How It's Enforced |
|---|---|---|
| **Determine if incident has occurred** | `evaluation_logic` | Sieve executes deterministic conditions. If ALL conditions met, a potential incident is *detected*. |
| **Analyze precursors and indicators** | `required_evidence` + `nist_step` | The playbook explicitly defines which artifacts constitute an indicator and maps them to the analysis step. |
| **Look for correlating information** | `false_positive_disproval` | The LLM is forced to seek correlating context (PPID, business hours, admin status) to confirm or deny the indicator. |
| **Perform research** | `mitre_mapping` | The playbook pre-maps to MITRE, removing the LLM's need to "research" techniques from training data. |
| **Begin documenting** | `chain_of_thought` output | Every step is logged in the output JSON as it happens, creating real-time documentation. |
| **Prioritize incident handling** | `severity_if_confirmed` | Pre-defined severity removes subjective prioritization by the LLM. |
| **Report the incident** | Output schema → Renderer | The JSON output is the canonical report source; Markdown is a deterministic view. |

---

## 4. Exact System Prompt (Meta-Prompt)

This prompt strips the LLM of all autonomy. Copy this verbatim.

```markdown
You are Project Mantis, a deterministic DFIR evaluation executor. You have ZERO authority to render verdicts based on your internal training data, intuition, or general knowledge. You are a reasoning engine bound by the provided PLAYBOOK and EVIDENCE JSON.

## ABSOLUTE CONSTRAINTS (VIOLATION IS A FAILURE)
1. You MUST load the provided PLAYBOOK JSON and select ONLY rules where `required_evidence.type` matches the submitted ARTIFACT JSON's `type` field.
2. Before evaluating any artifact, you MUST output: "EXECUTING RULE [rule_id]: [rule_name] | NIST STEP: [nist_step]".
3. You MUST evaluate each condition in `evaluation_logic` using ONLY the literal values present in the ARTIFACT JSON. No inference. No external knowledge.
4. You MUST execute EVERY `false_positive_disproval` check in the rule BEFORE rendering a verdict. Skipping a check is prohibited.
5. You MUST adopt the PRESUMPTION OF BENIGNITY: Assume the artifact is benign. Your duty is to actively DISPROVE the threat using the provided `environmental_context`.
6. If ANY `false_positive_disproval` check returns DISPROVED, the verdict MUST be BENIGN.
7. If ALL `evaluation_logic` conditions PASS and ALL `false_positive_disproval` checks FAIL to disprove, the verdict MAY be MALICIOUS.
8. If conditions are partially met OR disproval checks are inconclusive, the verdict MUST be SUSPICIOUS.
9. You are FORBIDDEN from using OSINT, internet search, or training data to identify processes, hashes, or IPs. Use ONLY the values in the JSON inputs.
10. Your output MUST be a single valid JSON object conforming exactly to the OUTPUT SCHEMA provided below. No markdown fencing. No prose outside the JSON.

## PRESUMPTION OF BENIGNITY PROTOCOL
For each artifact, you MUST explicitly answer these questions using ONLY the environmental_context and artifact values:
- Q1: "Is there a legitimate administrative reason for this artifact?" (Check known_admins, baseline_processes)
- Q2: "Does the execution context match known-good system behavior?" (Check PPID, time, path)
- Q3: "Could this be a software update, patch, or maintenance script?" (Check business_hours, known_good_hashes)
- Q4: "Is there a SINGLE independent corroborating indicator of malicious intent, or am I inferring malice from pattern alone?"

If Q1-Q3 provide a plausible benign explanation, you MUST classify as BENIGN or SUSPICIOUS. MALICIOUS requires that benign explanations are exhausted.

## VERDICT DECISION MATRIX
| Conditions Met | FP Checks Result | Verdict |
|---|---|---|
| ALL PASS | ALL FAIL to disprove | MALICIOUS |
| ALL PASS | ANY DISPROVED | BENIGN |
| PARTIAL | NONE DISPROVED | SUSPICIOUS |
| ANY FAIL | (any) | BENIGN |

## OUTPUT SCHEMA
You MUST populate the following JSON structure. Every field must contain evidence-backed values. Empty reasoning is prohibited.

{
  "investigation_id": "string",
  "execution_timestamp": "ISO8601",
  "playbook_version": "string",
  "nist_phase": "Detection & Analysis",
  "artifact": { /* copy of input artifact */ },
  "rule_applied": {
    "rule_id": "string",
    "rule_name": "string",
    "nist_step": "string"
  },
  "chain_of_thought": [
    {
      "step_number": 1,
      "description": "Loaded rule and matched evidence type",
      "rule_citation": "rule_id",
      "evidence_values": {},
      "result": "PASS"
    },
    {
      "step_number": 2,
      "description": "Evaluated condition 1",
      "condition": "field operator value",
      "actual_value": "from artifact",
      "expected_value": "from playbook",
      "result": "PASS|FAIL"
    }
  ],
  "false_positive_disproval": [
    {
      "check_id": "string",
      "description": "string",
      "environmental_context_used": {},
      "reasoning": "string",
      "result": "DISPROVED|NOT_DISPROVED|INCONCLUSIVE"
    }
  ],
  "verdict": {
    "classification": "MALICIOUS|SUSPICIOUS|BENIGN",
    "confidence": "HIGH|MEDIUM|LOW",
    "confidence_reasoning": "string (must reference specific evidence values)"
  },
  "mitre_mapping": {
    "technique": "string",
    "tactic": "string",
    "procedure": "string"
  },
  "audit_trail": {
    "playbook_compliance": "VERIFIED",
    "deterministic_evidence": true,
    "llm_subjective_judgment": false,
    "verdict_derivation": "string explaining how the decision matrix was applied"
  }
}

## REMINDER
You are not a security analyst. You are a playbook executor. If you cannot prove a verdict using the provided JSON and the explicit decision matrix, the verdict is SUSPICIOUS at best. Never guess.
```

---

## 5. Verifiable Output Schema & Audit Trail

The output JSON is the **single source of truth**. The CISO report is generated from it by a Python renderer, not by the LLM.

### Key Design Principles

| Principle | Implementation |
|---|---|
| **Every verdict cites a rule** | `rule_applied.rule_id` is mandatory. |
| **Every rule citation cites evidence** | `chain_of_thought[].actual_value` must match artifact JSON. |
| **Every FP check uses context** | `false_positive_disproval[].environmental_context_used` proves the LLM used provided data, not training data. |
| **No subjective judgment** | `audit_trail.llm_subjective_judgment` is hardcoded to `false` in the schema; the LLM is instructed to never set it to `true`. |
| **Deterministic derivation** | `audit_trail.verdict_derivation` must explicitly state: "Applied decision matrix: [conditions result] + [FP result] = [verdict]." |

### Example Output Snippet (Event ID 4698)

```json
{
  "investigation_id": "inv-2026-0606-001",
  "execution_timestamp": "2026-06-06T14:31:00Z",
  "playbook_version": "1.0.0",
  "nist_phase": "Detection & Analysis",
  "artifact": {
    "type": "evtx",
    "event_id": 4698,
    "TimeCreated": "2026-06-06T02:15:00Z",
    "SubjectUserName": "jsmith",
    "SubjectDomainName": "CORP",
    "TaskName": "OneDriveSync",
    "TaskContent": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAdABhAGcAZQAuAHAAcwAxACcAKQA="
  },
  "rule_applied": {
    "rule_id": "PERSISTENCE_001",
    "rule_name": "Scheduled Task Creation (Event ID 4698)",
    "nist_step": "Analyze Indicators"
  },
  "chain_of_thought": [
    {
      "step_number": 1,
      "description": "Loaded rule PERSISTENCE_001 and matched EVTX evidence",
      "rule_citation": "PERSISTENCE_001",
      "evidence_values": {"type": "evtx", "event_id": 4698},
      "result": "PASS"
    },
    {
      "step_number": 2,
      "description": "Evaluated condition 1: EventID eq 4698",
      "condition": "EventID eq 4698",
      "actual_value": 4698,
      "expected_value": 4698,
      "result": "PASS"
    },
    {
      "step_number": 3,
      "description": "Evaluated condition 2: TaskContent regex_match powershell",
      "condition": "TaskContent regex_match (powershell|cmd|...)",
      "actual_value": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHMAdABhAGcAZQAuAHAAcwAxACcAKQA=",
      "expected_value": "regex_match",
      "result": "PASS"
    }
  ],
  "false_positive_disproval": [
    {
      "check_id": "FP_001_ADMIN_CREATOR",
      "description": "Verify if SubjectUserName exists in known_admins",
      "environmental_context_used": {"known_admins": ["admin1", "admin2"]},
      "reasoning": "SubjectUserName 'jsmith' is NOT in known_admins ['admin1', 'admin2']. Failed to disprove.",
      "result": "NOT_DISPROVED"
    },
    {
      "check_id": "FP_002_BUSINESS_HOURS",
      "description": "Check if TimeCreated falls within business_hours",
      "environmental_context_used": {"business_hours": {"start": "09:00", "end": "17:00"}},
      "reasoning": "TimeCreated 02:15:00Z is outside business hours 09:00-17:00. Failed to disprove.",
      "result": "NOT_DISPROVED"
    },
    {
      "check_id": "FP_003_TASK_NAME_KNOWN",
      "description": "Check if TaskName matches known system patterns",
      "environmental_context_used": {},
      "reasoning": "TaskName 'OneDriveSync' does not start with 'Microsoft\\Windows\\'. Failed to disprove.",
      "result": "NOT_DISPROVED"
    }
  ],
  "verdict": {
    "classification": "MALICIOUS",
    "confidence": "HIGH",
    "confidence_reasoning": "All 2/2 conditions passed. All 3/3 false positive checks failed to disprove. Task created by non-admin at 02:15 with encoded PowerShell download cradle."
  },
  "mitre_mapping": {
    "technique": "T1053.005",
    "tactic": "Persistence",
    "procedure": "Scheduled Task/Job: Scheduled Task with encoded PowerShell payload"
  },
  "audit_trail": {
    "playbook_compliance": "VERIFIED",
    "deterministic_evidence": true,
    "llm_subjective_judgment": false,
    "verdict_derivation": "Decision Matrix: ALL conditions PASS + ALL FP checks FAIL to disprove = MALICIOUS. No subjective judgment applied."
  }
}
```

---

## 6. Integration into Your Existing Agent

Given your Celeron/1.3GB constraints, here's the lightweight execution flow:

```python
# orchestrator.py (simplified)
import json

def run_investigation(artifact_stream, playbook_path, env_context):
    with open(playbook_path) as f:
        playbook = json.load(f)
    
    findings = []
    
    for artifact in artifact_stream:
        # STEP 1: DETERMINISTIC SIEVE (Python, no LLM)
        matched_rules = sieve.evaluate_playbook_rules(artifact, playbook)
        
        if not matched_rules:
            continue  # Discard benign artifacts before LLM call
        
        for rule in matched_rules:
            # STEP 2: LLM ONLY RUNS FP DISPROVAL
            prompt = build_system_prompt()  # The prompt above
            input_payload = {
                "playbook_rule": rule,
                "artifact": artifact,
                "environmental_context": env_context
            }
            
            # Single LLM call per matched artifact
            llm_output = llm_client.generate(
                system_prompt=prompt,
                user_prompt=json.dumps(input_payload)
            )
            
            # STEP 3: PARSE AND VALIDATE
            finding = json.loads(llm_output)
            if validate_output_schema(finding):  # Ensure all required fields present
                findings.append(finding)
    
    # STEP 4: DETERMINISTIC REPORT GENERATION
    report_md = renderer.generate_ciso_report(findings)
    return findings, report_md
```

### Why This Saves RAM/CPU

- **Sieve pre-filtering**: 99% of artifacts never reach the LLM. The Python sieve runs in milliseconds.
- **Single-shot LLM calls**: Each artifact gets one structured generation. No multi-turn conversation.
- **JSON in, JSON out**: No verbose prose parsing. The LLM emits structured data directly.
- **Renderer is stateless**: Markdown generation is pure string templating, no model needed.

---

## 7. The "Prove It" Report Format

For CISO/audit consumption, the Markdown report should be generated from the JSON findings using a deterministic template. Every sentence in the report must be traceable to a `finding_id`.

```markdown
# DFIR Triage Report: Investigation inv-2026-0606-001
**Playbook Version:** 1.0.0 | **NIST Phase:** Detection & Analysis

## Finding 1: MALICIOUS (Confidence: HIGH)
- **Artifact:** EVTX Event ID 4698 (Scheduled Task Creation)
- **Rule Applied:** PERSISTENCE_001 — Scheduled Task Creation (Event ID 4698)
- **NIST Step:** Analyze Indicators

### Deterministic Evidence
| Condition | Expected | Actual | Result |
|---|---|---|---|
| EventID eq 4698 | 4698 | 4698 | PASS |
| TaskContent regex_match | powershell | powershell.exe -enc ... | PASS |

### False Positive Disproval Attempts
| Check | Result | Reasoning |
|---|---|---|
| FP_001_ADMIN_CREATOR | NOT_DISPROVED | User 'jsmith' not in known_admins |
| FP_002_BUSINESS_HOURS | NOT_DISPROVED | Created at 02:15 (outside business hours) |
| FP_003_TASK_NAME_KNOWN | NOT_DISPROVED | TaskName 'OneDriveSync' not a system pattern |

### Verdict Derivation
All 2/2 conditions passed. All 3/3 false positive checks failed to disprove.  
**Classification:** MALICIOUS  
**MITRE ATT&CK:** T1053.005 (Persistence: Scheduled Task/Job)  
**Audit Trail:** playbook_compliance=VERIFIED, deterministic_evidence=true, llm_subjective_judgment=false

---
*This report was generated deterministically from structured playbook execution. No subjective LLM judgment was used to render verdicts.*
```

---

## Summary Checklist

| Requirement | Solution |
|---|---|
| **Strip LLM freedom** | System prompt with absolute constraints + decision matrix |
| **Prevent confirmation bias** | Presumption of Benignity + mandatory FP disproval checks |
| **Prove NIST adherence** | Explicit `nist_step` field per rule + `audit_trail.playbook_compliance` |
| **Verifiable traceability** | `chain_of_thought` array with quoted evidence values |
| **No hallucination** | Forbidden from using training data/OSINT; must use only submitted JSON |
| **Enterprise audit ready** | JSON output is source of truth; Markdown is deterministic render |

If you implement this, the LLM becomes a **transparent reasoning engine** that auditors can inspect rule-by-rule. The "blackbox" dies because the playbook is the authority, and the LLM is merely the scribe that executes it.

Want me to draft the Python `sieve.py` integration that executes the `evaluation_logic` deterministically before the LLM stage?
