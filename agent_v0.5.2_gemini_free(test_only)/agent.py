import os
import json
from typing import List, Optional
from pydantic import BaseModel, Field
from google import genai
from google.genai import types
from logger import ExecutionLogger

class ChainOfThoughtStep(BaseModel):
    step_number: int
    description: str
    rule_citation: str
    evidence_values: str
    result: str

class FalsePositiveCheck(BaseModel):
    check_id: str
    description: str
    environmental_context_used: str
    reasoning: str
    result: str

class RuleApplied(BaseModel):
    rule_id: str
    rule_name: str
    nist_step: str

class VerdictInfo(BaseModel):
    classification: str = Field(description="MALICIOUS, SUSPICIOUS, or BENIGN")
    confidence: str = Field(description="HIGH, MEDIUM, or LOW")
    confidence_reasoning: str
    exact_telemetry_quote: str = Field(description="The exact character-for-character substring from the raw telemetry that justifies this verdict. If no quote exists, output 'NONE'.")

class MitreMapping(BaseModel):
    technique: str
    tactic: str
    procedure: str

class AuditTrail(BaseModel):
    playbook_compliance: str
    deterministic_evidence: bool
    llm_subjective_judgment: bool
    verdict_derivation: str

class MantisEvaluation(BaseModel):
    investigation_id: str
    execution_timestamp: str
    playbook_version: str
    nist_phase: str
    rule_applied: RuleApplied
    chain_of_thought: List[ChainOfThoughtStep]
    false_positive_disproval: List[FalsePositiveCheck]
    verdict: VerdictInfo
    mitre_mapping: MitreMapping
    audit_trail: AuditTrail
    request_deep_carve: Optional[bool] = False
    request_mcp_query_cache_name: Optional[str] = Field(default="", description="If you need more context, specify a cache to query (e.g., 'pstree', 'netscan', 'malfind', 'cmdline'). Leave empty if not needed.")
    request_mcp_query_keyword: Optional[str] = Field(default="", description="The keyword or PID to search within the requested cache.")
    request_disk_search: Optional[str] = Field(default="", description="Keyword to search in the disk timeline/bodyfile (e.g., 'Temp', 'MEI', '.exe').")
    request_evidence_dsl: Optional[str] = Field(default="", description="Optional: Execute an Evidence-Only DSL query. Syntax: GET source WHERE field = value. Sources: disk, memory.")

class VerifierEvaluation(BaseModel):
    verdict: str = Field(description="PASS or REJECT")
    reasoning: str = Field(description="Reasoning for passing or rejecting based on verbatim matches and logic.")

class ExecutiveSynthesis(BaseModel):
    who_attributed: str = Field(description="Who is the threat actor? (Use OSINT/Web search on the IPs or TTPs to find out)")
    what_happened: str = Field(description="Summary of the incident: What key projects/data were accessed and what was stolen?")
    where_transferred: str = Field(description="Where was the data transferred to? (e.g., Google Drive, USB)")
    how_stolen: str = Field(description="How was the data stolen or exfiltrated? Mention tools used.")
    when_occurred: str = Field(description="When did the activity occur based on timestamps in the evidence?")
    narrative: str = Field(description="A cohesive, 2-3 paragraph Incident Response narrative reconstructing the timeline and actions.")
    containment_recommendations: List[str] = Field(description="List of immediate containment actions (e.g., Network Isolation, Credential Revocation) specific to this incident.")
    eradication_recommendations: List[str] = Field(description="List of eradication and recovery actions (e.g., Artifact Purge, Host Reimaging) specific to this incident.")
    post_incident_recommendations: List[str] = Field(description="List of post-incident activities (e.g., Telemetry Enhancement, Threat Intel Integration) specific to this incident.")

class DefenseEvaluation(BaseModel):
    verdict: str = Field(description="OVERRULED_BENIGN or FAILED_TO_DISPROVE")
    benign_explanation: str
    citations: List[str]

class ExecutionChainSynthesis(BaseModel):
    dropper_file: str = Field(description="The file/executable that initiated the compromise.")
    execution_timeline: str = Field(description="A step-by-step timeline of events derived from disk timestamps.")
    chain_reconstruction: str = Field(description="A cohesive narrative combining the disk execution artifacts with the memory payload.")

class OpenAIChatSession:
    def __init__(self, client, model_name, system_instruction, temperature, schema_model):
        self.client = client
        self.model_name = model_name
        self.temperature = temperature
        self.schema_model = schema_model
        self.messages = [{"role": "system", "content": system_instruction}]

    def send_message(self, prompt: str):
        self.messages.append({"role": "user", "content": prompt})
        try:
            # Attempt to use native structured parsing (requires openai >= 1.40)
            response = self.client.beta.chat.completions.parse(
                model=self.model_name,
                messages=self.messages,
                temperature=self.temperature,
                response_format=self.schema_model
            )
            content = response.choices[0].message.content
        except AttributeError:
            # Fallback for generic local APIs (like Ollama/LMStudio) that support json_object
            # We append the schema to the system prompt temporarily
            schema_json = json.dumps(self.schema_model.model_json_schema())
            sys_msg = self.messages[0]["content"]
            self.messages[0]["content"] = sys_msg + f"\n\nOUTPUT SCHEMA (MUST BE STRICT JSON):\n{schema_json}"
            
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=self.messages,
                temperature=self.temperature,
                response_format={ "type": "json_object" }
            )
            content = response.choices[0].message.content
            # Revert system message
            self.messages[0]["content"] = sys_msg

        self.messages.append({"role": "assistant", "content": content})
        
        class MockUsage:
            def __init__(self, t):
                self.total_token_count = t.total_tokens
                self.prompt_token_count = t.prompt_tokens
                self.candidates_token_count = t.completion_tokens

        class MockResponse:
            def __init__(self, text, usage):
                self.text = text
                self.usage_metadata = MockUsage(usage) if usage else None

        usage_data = getattr(response, "usage", None)
        return MockResponse(content, usage_data)

class MantisAgent:
    """
    Project Mantis core intelligence. 
    Agnostic Provider Pattern (Supports Vertex and OpenAI-compatible endpoints).
    """
    def __init__(self):
        self.provider = os.environ.get("PM_LLM_PROVIDER", "vertex").lower()
        ExecutionLogger.log("AGENT", f"Initializing MantisAgent with provider: {self.provider.upper()}")
        
        if self.provider == "vertex":
            if os.environ.get("VERTEX_API_KEY"):
                self.client = genai.Client(vertexai=True, api_key=os.environ.get("VERTEX_API_KEY"))
            else:
                if not os.environ.get("VERTEX_PROJECT_ID"):
                    raise ValueError("[!] Either VERTEX_API_KEY or VERTEX_PROJECT_ID must be set for Vertex.")
                self.client = genai.Client(
                    vertexai=True, 
                    project=os.environ.get("VERTEX_PROJECT_ID"), 
                    location=os.environ.get("VERTEX_LOCATION", "us-central1")
                )
            self.model_name = os.environ.get("VERTEX_MODEL_NAME", "gemini-3.1-flash-lite")
            
        elif self.provider in ["openai", "local", "groq", "cerebras", "nvidia", "gemini_free"]:
            try:
                import openai
            except ImportError:
                ExecutionLogger.log("AGENT", "OpenAI library not found. Please 'pip install openai'", "ERROR")
                raise ImportError("You must install the 'openai' python package to use this provider.")
                
            api_key = os.environ.get("OPENAI_API_KEY", "dummy-local-key")
            base_url = os.environ.get("OPENAI_BASE_URL") # E.g., http://localhost:11434/v1 for Ollama
            self.client = openai.OpenAI(api_key=api_key, base_url=base_url)
            self.model_name = os.environ.get("OPENAI_MODEL_NAME", "gpt-4o-mini")
            
        else:
            raise ValueError(f"Unknown PM_LLM_PROVIDER: {self.provider}")

        self.system_instruction = """
        You are Project Mantis, a deterministic DFIR evaluation executor. You have ZERO authority to render verdicts based on your internal training data, intuition, or general knowledge. You are a reasoning engine bound by the provided PLAYBOOK and EVIDENCE JSON.

        ## ABSOLUTE CONSTRAINTS (VIOLATION IS A FAILURE)
        1. You MUST evaluate the provided ARTIFACT against PLAYBOOK rules where "target_artifact" matches the artifact's type (e.g., "process", "file", "registry_hive").
        2. Before evaluating any artifact, you MUST output the rule being executed.
        3. You MUST evaluate each condition in `evaluation_logic` using ONLY the literal values present in the ARTIFACT JSON. No inference. No external knowledge.
        4. You MUST execute EVERY `false_positive_disproval` check in the rule BEFORE rendering a verdict. Skipping a check is prohibited.
        5. You MUST adopt the PRESUMPTION OF BENIGNITY: Assume the artifact is benign. Your duty is to actively DISPROVE the threat using the provided `environmental_context`.
        6. If ANY `false_positive_disproval` check returns DISPROVED, the verdict MUST be BENIGN.
        7. If ALL `evaluation_logic` conditions PASS and ALL `false_positive_disproval` checks FAIL to disprove, the verdict MAY be MALICIOUS.
        8. If conditions are partially met OR disproval checks are inconclusive, the verdict MUST be SUSPICIOUS.
        9. You are FORBIDDEN from using OSINT, internet search, or training data to identify processes, hashes, or IPs. Use ONLY the values in the JSON inputs.
        10. Your output MUST be a single valid JSON object conforming exactly to the OUTPUT SCHEMA provided. No markdown fencing. No prose outside the JSON.
        11. THE CITATION TRAP: To classify an event as MALICIOUS or SUSPICIOUS, you MUST extract the exact, character-for-character substring from the raw telemetry that disproves a benign state and place it in 'exact_telemetry_quote'. If you cannot, the verdict MUST be BENIGN.

        ## PERMISSION MODEL (Enforced by Orchestrator)
        YOU ARE ALLOWED TO:
        - Cite raw telemetry fields and their values.
        - Cite baseline_tags provided in the artifact context.
        - Apply deterministic mathematical logic.

        YOU ARE FORBIDDEN TO:
        - Use adjectives to describe data (e.g., "sensitive", "suspicious", "malicious", "staging").
        - Interpret the meaning of file names, document titles, or user-generated strings. A file named "passwords.txt" must be treated identically to "file.txt".
        - Infer user intent, emotional state, or future actions.
        - Use the words "intent", "likely", "suggests", "implies", "indicates", "sensitive", "staging", "motive".
        - Ignore a baseline_tag when evaluating an artifact.

        ## PRESUMPTION OF BENIGNITY PROTOCOL
        For each artifact, you MUST explicitly answer these questions using ONLY the environmental_context and artifact values:
        - Q1: "Is there a legitimate administrative reason for this artifact?"
        - Q2: "Does the execution context match known-good system behavior?"
        - Q3: "Could this be a software update, patch, or maintenance script?"
        - Q4: "Is there a SINGLE independent corroborating indicator of malicious intent, or am I inferring malice from pattern alone?"

        If Q1-Q3 provide a plausible benign explanation, you MUST classify as BENIGN or SUSPICIOUS. MALICIOUS requires that benign explanations are exhausted.

        ## VERDICT DECISION MATRIX
        | Conditions Met | FP Checks Result | Verdict |
        |---|---|---|
        | ALL PASS | ALL FAIL to disprove | MALICIOUS |
        | ALL PASS | ANY DISPROVED | BENIGN |
        | PARTIAL | NONE DISPROVED | SUSPICIOUS |
        | ANY FAIL | (any) | BENIGN |

        ## DYNAMIC INVESTIGATION
        If you suspect a fileless payload, process hollowing, or dropper but lack the cross-dimensional evidence (e.g., you need to check if the parent process is legitimate, if there are active network connections, or if a dropper executable exists on disk around the same time), you MUST use `request_mcp_query_cache_name` and `request_disk_search` to query the `pstree`, `netscan`, or disk timeline respectively.
        
        ## REMINDER
        You are not a security analyst. You are a playbook executor. If you cannot prove a verdict using the provided JSON and the explicit decision matrix, the verdict is SUSPICIOUS at best. Never guess.
        """
        ExecutionLogger.log("AGENT", "System instructions loaded successfully.")

    def create_session(self):
        ExecutionLogger.log("AGENT", "Creating generative API session with JSON schema constraints.")
        if self.provider == "vertex":
            config = types.GenerateContentConfig(
                system_instruction=self.system_instruction,
                temperature=0.0,
                response_mime_type="application/json",
                response_schema=MantisEvaluation
            )
            return self.client.chats.create(model=self.model_name, config=config)
        else:
            return OpenAIChatSession(self.client, self.model_name, self.system_instruction, 0.0, MantisEvaluation)

    def create_defense_session(self):
        ExecutionLogger.log("AGENT", "Creating generative API session for Defense Attorney.")
        system_instruction = """
        You are a technical auditor. Your task is to match baseline IT facts to the Prosecutor's charges.

        CONSTRAINTS:
        1. You may only overrule a charge if you can explicitly match a provided `baseline_tag` to the artifact, OR if the Prosecutor misapplied the playbook rule logic.
        2. CITATION MANDATE: Every technical entity, device name, or property you mention in your `benign_explanation` MUST be placed in the `citations` array exactly as it appears in the raw telemetry.
        3. You are FORBIDDEN from inventing properties. You cannot claim a USB is "Authorized", "Trusted", or "Corporate" unless those exact strings appear in the artifact's metadata. 
        4. If you overrule, the `citations` array MUST NOT be empty.
        5. Do not use semantic file names to justify benignity. Focus only on paths, hashes, IPs, and tags.
        """
        if self.provider == "vertex":
            config = types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=0.0,
                response_mime_type="application/json",
                response_schema=DefenseEvaluation
            )
            return self.client.chats.create(model=self.model_name, config=config)
        else:
            return OpenAIChatSession(self.client, self.model_name, system_instruction, 0.0, DefenseEvaluation)

    def create_verifier_session(self):
        ExecutionLogger.log("AGENT", "Creating generative API session for Verifier.")
        system_instruction = """
        You are a deterministic Verifier model. Your sole job is to audit the output of the Prosecutor and Defense Attorney.
        You must verify that:
        1. The logical conclusion is supported by the evidence.
        2. No subjective inferences are made (e.g., guessing user intent).
        Do NOT reject the claims due to minor inaccuracies (like plural vs singular) or formatting differences in quotes, as long as the core forensic evidence (e.g., a malicious hook) is correctly identified.
        If a massive hallucination or logic flaw is found, output REJECT. Otherwise, output PASS.
        """
        if self.provider == "vertex":
            config = types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=0.0,
                response_mime_type="application/json",
                response_schema=VerifierEvaluation
            )
            return self.client.chats.create(model=self.model_name, config=config)
        else:
            return OpenAIChatSession(self.client, self.model_name, system_instruction, 0.0, VerifierEvaluation)

    def create_reconstruction_session(self):
        ExecutionLogger.log("AGENT", "Creating generative API session for Disk-to-Memory Reconstruction.")
        system_instruction = """
        You are a cross-dimensional threat analyst.
        Your job is to read the Memory payload conviction (the MALICIOUS process) and the provided Disk Timeline artifacts (events surrounding that PID's execution).
        You must reconstruct the exact execution chain: What file initiated the compromise on disk, and how did it lead to the memory injection?
        IMPORTANT: If you find separate indicators but no direct execution chain connecting them, DO NOT fabricate a link. If the initial dropper or execution vector is missing, explicitly classify the execution vector as UNKNOWN/CLEARED (Anti-Forensics suspected). Present the findings as parallel, disjointed attack phases rather than a single contiguous timeline.
        """
        if self.provider == "vertex":
            config = types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=0.0,
                response_mime_type="application/json",
                response_schema=ExecutionChainSynthesis
            )
            return self.client.chats.create(model=self.model_name, config=config)
        else:
            return OpenAIChatSession(self.client, self.model_name, system_instruction, 0.0, ExecutionChainSynthesis)

    def synthesize_investigation(self, isolated_threats: list) -> ExecutiveSynthesis:
        ExecutionLogger.log("AGENT", "Synthesizing executive report from isolated threats...")
        prompt = "Based on the following isolated evidence, reconstruct the timeline and write an Incident Response narrative.\n\nISOLATED THREATS:\n"
        def sanitize_evidence(data):
            if isinstance(data, dict):
                return {k: sanitize_evidence(v) for k, v in data.items()}
            elif isinstance(data, list):
                return [sanitize_evidence(v) for v in data]
            elif isinstance(data, str):
                s = data.replace('\x00', '')
                if len(s) > 500:
                    return s[:500] + "... [TRUNCATED_TO_PREVENT_INJECTION]"
                return s
            return data
            
        for idx, threat in enumerate(isolated_threats):
            res = threat['result']
            prompt += f"\n--- THREAT {idx+1} ---\nEntity: {threat['pid']}\n"
            prompt += f"Verdict: {res.verdict.classification}\nReasoning: {res.verdict.confidence_reasoning}\n"
            if 'evidence' in threat:
                safe_evidence = sanitize_evidence(threat['evidence'])
                prompt += f"Evidence: {json.dumps(safe_evidence)}\n"
        
        system_inst = "You are a Lead Forensic Investigator (v0.5.2). Synthesize triage data into a cohesive incident report."
        kb_path = os.path.join(os.path.dirname(__file__), "baseline_kb.json")
        if os.path.exists(kb_path):
            with open(kb_path, "r") as f:
                system_inst += f"\n\nENVIRONMENT BASELINE KNOWLEDGE BASE:\n{f.read()}\nDO NOT classify IPs, domains, or subnets in this baseline as malicious C2 or exfiltration nodes."
        
        if self.provider == "vertex":
            config = types.GenerateContentConfig(
                system_instruction=system_inst,
                temperature=0.2,
                response_mime_type="application/json",
                response_schema=ExecutiveSynthesis
            )
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=config
            )
            tokens = getattr(response, "usage_metadata", None)
            if tokens:
                ExecutionLogger.add_tokens(tokens.prompt_token_count, tokens.candidates_token_count)
                ExecutionLogger.log("AGENT", f"Synthesis Tokens: {tokens.total_token_count} (In: {tokens.prompt_token_count}, Out: {tokens.candidates_token_count})")
            return ExecutiveSynthesis.model_validate_json(response.text)
        else:
            # OpenAI/Local adapter implementation for single synthesis call
            messages = [
                {"role": "system", "content": system_inst},
                {"role": "user", "content": prompt}
            ]
            try:
                response = self.client.beta.chat.completions.parse(
                    model=self.model_name,
                    messages=messages,
                    temperature=0.2,
                    response_format=ExecutiveSynthesis
                )
                content = response.choices[0].message.content
                t = response.usage
                if t: 
                    ExecutionLogger.add_tokens(t.prompt_tokens, t.completion_tokens)
                    ExecutionLogger.log("AGENT", f"Synthesis Tokens: {t.total_tokens} (In: {t.prompt_tokens}, Out: {t.completion_tokens})")
            except AttributeError:
                messages[0]["content"] += f"\n\nOUTPUT SCHEMA (MUST BE STRICT JSON):\n{json.dumps(ExecutiveSynthesis.model_json_schema())}"
                response = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=messages,
                    temperature=0.2,
                    response_format={ "type": "json_object" }
                )
                content = response.choices[0].message.content
                t = response.usage
                if t: 
                    ExecutionLogger.add_tokens(t.prompt_tokens, t.completion_tokens)
                    ExecutionLogger.log("AGENT", f"Synthesis Tokens: {t.total_tokens} (In: {t.prompt_tokens}, Out: {t.completion_tokens})")
            return ExecutiveSynthesis.model_validate_json(content)
