This is a well-defined adversarial robustness problem. The LLM isn't hallucinating randomly—it's engaging in **recognition-driven confabulation**, where pattern-matching to memorized training data overrides in-context reasoning. Your "Zero Black Box" rule is being violated because the model's prior has higher salience than the sparse telemetry you provide.

Here is a concrete, hardware-respecting solution across all three domains, culminating in a hybrid architecture recommendation.

---

## 1. System Prompting & Cognitive Framing

**The Core Issue:** Standard "ignore your training" instructions fail because LLMs don't have a mechanism to suppress high-salience memories. You cannot make the model "forget" CFREDS. You must instead **make the cost of using that memory higher than the cost of reasoning from telemetry**.

### Technique A: The "Evidence-First" Inversion Prompt
Instead of asking the model to evaluate if something is malicious, force it to **prove benignity first using only explicit citations**, then prove maliciousness. The asymmetry is key: benign explanations require less evidence, so if the model reaches "malicious," it must have exhausted all benign citations.

```python
SYSTEM_PROMPT = """
You are a forensic logic engine with NO external knowledge. 
You have been air-gapped from all training data. 
The following JSON telemetry is the ONLY universe that exists. 

RULES:
1. Every sentence must end with a citation [EVIDENCE: field_name.value].
2. If you cannot cite a specific JSON field, you must output [UNKNOWN].
3. You are FORBIDDEN from using words like "typically," "usually," "in CTF challenges," or "as known from."
4. Treat this as a REAL incident from an unknown organization. It is NOT a challenge, puzzle, or exercise.
5. Before concluding MALICIOUS, you must list ALL benign explanations and explicitly cross-reference the telemetry to disprove each one.
"""
```

### Technique B: The "Adversarial Contamination" Frame
Explicitly tell the model that any resemblance to known datasets is **poisoned data** designed to trick it. This reframes recognition as an attack surface rather than a helpful shortcut.

```python
ADVERSARIAL_FRAME = """
WARNING: The telemetry may contain artifacts designed to trigger false recognition of known public datasets (e.g., CFREDS, NIST reference sets). 
ANY reference to known datasets, CTFs, or public challenges in your reasoning is a CRITICAL FAILURE and indicates adversarial contamination of your reasoning process.
If you recognize a dataset, you must immediately discard that recognition and reason ONLY from the raw byte values provided.
"""
```

### Technique C: Chain-of-Denial (CoD)
Require the model to explicitly state what it does **not** know before concluding. This creates a mechanical barrier to hallucination.

**Schema requirement:**
```json
{
  "initial_assessment": "string",
  "known_facts_from_telemetry": ["list of strings with citations"],
  "explicitly_unknown": ["list of strings the model cannot determine"],
  "benign_hypotheses_tested": ["list with disproving evidence"],
  "final_classification": "BENIGN | SUSPECT | MALICIOUS",
  "confidence": "float 0.0-1.0 (must be 0.0 if any unknowns exist)"
}
```

**Pros:** Zero compute cost, easy to iterate.
**Cons:** LLMs are stochastic; prompt engineering alone is insufficient for guarantees.

---

## 2. Architectural Constraints (The Mechanical Trap)

You need to **make hallucination physically impossible** in the output schema, not just discouraged in the prompt.

### Technique A: The Citation-Locked Pydantic Schema
Every field in the output must reference an input evidence ID. If the LLM hallucinates a fact, it cannot produce a valid citation, and the schema validation fails.

```python
from pydantic import BaseModel, Field, field_validator
from typing import List, Literal

class EvidenceClaim(BaseModel):
    claim: str
    evidence_ids: List[str] = Field(..., min_length=1)  # MUST cite at least one telemetry ID
    confidence: float = Field(..., ge=0.0, le=1.0)

    @field_validator('evidence_ids')
    @classmethod
    def ids_must_exist_in_telemetry(cls, v, info):
        # This is validated against the actual telemetry keys passed in the prompt
        # If the LLM invents an ID, this raises ValidationError
        return v

class AnalysisResult(BaseModel):
    benign_explanations_disproven: List[EvidenceClaim]
    malicious_indicators: List[EvidenceClaim]
    classification: Literal["BENIGN", "SUSPECT", "MALICIOUS"]
    
    @field_validator('classification')
    @classmethod
    def must_prove_malignancy(cls, v, info):
        if v == "MALICIOUS":
            benign = info.data.get('benign_explanations_disproven', [])
            if not benign or any(b.confidence > 0.3 for b in benign):
                raise ValueError("Cannot classify MALICIOUS if benign explanations remain plausible or untested")
        return v
```

### Technique B: The Two-Pass Grounding Engine
Pass 1: LLM extracts **only facts** from telemetry (no conclusions).
Pass 2: LLM reasons only from the fact sheet generated in Pass 1.

This creates a narrow bottleneck. If Pass 1 is constrained to direct string extractions, Pass 2 cannot hallucinate external knowledge because it has no access to the original (potentially recognizable) telemetry.

```python
# Pass 1: Fact Extraction (strictly bounded)
FACT_PROMPT = """
Extract ONLY literal strings, numbers, and timestamps from the telemetry.
Do NOT interpret. Do NOT infer. Output a flat list of observations.
Format: {"observations": [{"value": "...", "source": "process_list.pid.1234"}]}
"""

# Pass 2: Reasoning (receives only the observation list, not original telemetry)
REASONING_PROMPT = """
You are given a list of observations from an unknown system. 
You do NOT know the source of these observations. 
Classify based ONLY on these strings.
"""
```

### Technique C: The Hallucination Canary
Insert a fake artifact into the telemetry that is benign but suspicious-looking. If the LLM references it as malicious without proper evidence, you know the reasoning is contaminated.

```python
# Insert a canary: a benign process with a suspicious-looking name
canary = {
    "pid": 99999,
    "name": "svch0st.exe",  # Looks like malware, is actually benign canary
    "cmdline": "C:\\Windows\\System32\\svch0st.exe --update",
    "canary_id": "HALLUCINATION_TEST_01"
}
```
If the LLM flags this as malicious without noting the benign command line, your downstream validator triggers a retry with a stronger penalty prompt.

### Technique D: Output Sanitization Guard
A lightweight regex scanner on the LLM output before acceptance. If it contains known CTF keywords (`CFREDS`, `NIST`, `challenge`, `flag`, `usb_exfiltration` as a specific known technique), auto-reject and append a penalty to the retry prompt.

```python
import re

CTF_KEYWORDS = re.compile(r'\b(cfred|nist.reference|ctf|challenge|flag\{)\b', re.I)

def guard_output(text: str) -> bool:
    if CTF_KEYWORDS.search(text):
        return False  # Reject
    return True
```

**Pros:** Deterministic, computationally free, creates hard barriers.
**Cons:** Requires careful schema design; overly aggressive guards might reject valid reasoning.

---

## 3. Evidence Obfuscation (The Lightweight Pre-Processor)

This is your **most powerful and deterministic** lever. Since you cannot stop the LLM from recognizing CFREDS, **remove the CFREDS fingerprints before the LLM sees them**.

### Technique A: Categorical Substitution (Not Cryptographic Hashing)
Hashing destroys semantic meaning (e.g., `user_admin` → `a3f1b2` loses the "admin" semantic). Instead, use **consistent categorical substitution** with a local lookup table.

```python
import re
import random

# Known CFREDS / public dataset fingerprints
KNOWN_FINGERPRINTS = {
    r'cfreds': 'DATASET_ALPHA',
    r'john_doe': 'USER_001',
    r'ctf_user': 'USER_002', 
    r'flag\.txt': 'DOCUMENT_001',
    r'C:\\Users\\John\\Documents\\CFREDS': 'PATH_HOME_DOCUMENTS',
    # Add more as you discover them
}

# Consistent random seed for deterministic substitution across the session
random.seed(42)

def obfuscate_telemetry(telemetry_json: dict) -> tuple[dict, dict]:
    """Returns (sanitized_telemetry, mapping_table)"""
    text = str(telemetry_json)
    mapping = {}
    
    for pattern, replacement in KNOWN_FINGERPRINTS.items():
        text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        mapping[replacement] = pattern  # Reverse mapping for post-processing
    
    # Also genericize common CTF tells: specific usernames, challenge-named files
    text = re.sub(r'\b[A-Z]{3,}_\d{4,}\b', 'CHALLENGE_ID', text)  # e.g., CFREDS_2018
    
    return eval(text), mapping  # eval is safe here since input was JSON
```

### Technique B: Semantic Generalization
Replace specific but semantically meaningful strings with generic equivalents that preserve the forensic logic:

| Original | Substitution | Preserved Meaning |
|----------|-------------|-------------------|
| `john.doe@company.com` | `user001@domain.internal` | Email format, internal domain |
| `C:\Users\John\Documents\secret.doc` | `C:\Users\USER001\Documents\FILE001.doc` | Path depth, file extension, user profile |
| `USB\VID_1234&PID_5678` | `USB\VID_XXXX&PID_YYYY` | USB device class, without specific IDs |

This prevents recognition while preserving the structural logic the LLM needs to reason about exfiltration.

### Technique C: The "Blind" Hashing of Identifiers
For process names, registry keys, and file hashes that don't need semantic preservation for the LLM's logic:

```python
import hashlib

def blind_id(s: str, salt: str = "mantis_salt") -> str:
    """Deterministic lightweight hash for identifiers"""
    return hashlib.md5(f"{s}{salt}".encode()).hexdigest()[:8].upper()
```

Use this for PIDs, file hashes, registry key names. The LLM only needs to know "two processes share a parent," not that the parent is `svchost.exe`.

### Technique D: Context Window Randomization
If you have multiple artifacts, shuffle their order in the prompt. CFREDS challenges often have a narrative sequence; breaking the sequence reduces the LLM's ability to match the pattern.

**Pros:** Deterministic, computationally trivial (regex + dict lookup), completely prevents recognition.
**Cons:** Requires maintaining a fingerprint database; you must reverse-map conclusions back to original artifacts for the final report.

---

## The Recommended Hybrid Solution: "Mantis Blind-Chain"

Given your constraints (Celeron N4020, 1.3GB RAM, cloud API only), here is the most robust, computationally cheap architecture:

### Phase 1: Pre-Processing (Local, ~MB RAM, ~ms latency)
```python
def sanitize_and_bind(telemetry: dict) -> dict:
    # 1. Categorical substitution of known CTF fingerprints
    # 2. Semantic generalization of paths/users
    # 3. Deterministic blinding of PIDs/hashes
    # 4. Insert hallucination canary
    # 5. Shuffle artifact order
    return sanitized_telemetry
```

### Phase 2: Prompt Engineering (Cloud API)
Use a **compound prompt** with three enforced sections:
1. **Adversarial Contamination Warning** (Technique B)
2. **Evidence-First Inversion** (Technique A)
3. **Chain-of-Denial Schema** (Technique C)

### Phase 3: Mechanical Trapping (Local validation)
```python
def validate_output(raw_llm_output: str, schema: AnalysisResult) -> AnalysisResult:
    # 1. Pydantic schema validation (citation lock)
    # 2. CTF keyword guard (auto-reject)
    # 3. Canary check (did it hallucinate the benign canary as malicious?)
    # 4. If fail: retry with penalty prompt + stronger obfuscation
    return validated_result
```

### Phase 4: Post-Processing (Local)
Reverse the substitution mapping to translate `USER_001` back to `john_doe` in the final human-readable report.

---

## Why This Beats Pure Prompt Engineering

| Approach | Fails When... | Your Hybrid Fix |
|----------|--------------|-----------------|
| Prompt only | Model's prior > prompt weight | Remove the prior's trigger (obfuscation) |
| Schema only | Model cites hallucinated evidence IDs | Pre-validate IDs against telemetry + canary |
| Obfuscation only | Model reasons about generic patterns | Schema forces explicit benign disproof |

The **obfuscation layer is your guarantee**. Even if the LLM is determined to solve a CTF, it cannot recognize the dataset if all fingerprints are replaced with generic tokens. The **schema layer** ensures that even if it tries to confabulate, it cannot produce a valid output without telemetry citations. The **prompt layer** reduces the retry rate.

**Implementation priority:**
1. **Evidence obfuscation** (biggest bang for buck, deterministic)
2. **Citation-locked Pydantic schema** (hard barrier)
3. **Canary + keyword guard** (cheap detection)
4. **Advanced prompt framing** (reduces friction)

This architecture respects your hardware constraints: all heavy lifting is regex/dict manipulation on the Celeron, and the cloud LLM receives only sanitized, schema-bound prompts.
