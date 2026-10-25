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

def convert_to_gemini_schema(schema: dict) -> dict:
    defs = schema.get("$defs", {})
    
    def resolve_refs(node):
        if isinstance(node, dict):
            if "$ref" in node:
                ref_path = node["$ref"]
                def_name = ref_path.split("/")[-1]
                resolved = resolve_refs(defs[def_name])
                for k, v in node.items():
                    if k != "$ref":
                        resolved[k] = resolve_refs(v)
                return resolved
            else:
                return {k: resolve_refs(v) for k, v in node.items() if k != "$defs"}
        elif isinstance(node, list):
            return [resolve_refs(item) for item in node]
        return node

    inlined = resolve_refs(schema)
    
    def uppercase_types(node):
        if isinstance(node, dict):
            new_node = {}
            for k, v in node.items():
                if k == "type" and isinstance(v, str):
                    new_node[k] = v.upper()
                else:
                    new_node[k] = uppercase_types(v)
            return new_node
        elif isinstance(node, list):
            return [uppercase_types(item) for item in node]
        return node
        
    return uppercase_types(inlined)

class GeminiInteractionSession:
    def __init__(self, client, model_name, system_instruction, schema_model, temperature=0.0):
        self.client = client
        self.model_name = model_name
        self.system_instruction = system_instruction
        self.schema_model = schema_model
        self.temperature = temperature
        self.previous_interaction_id = None

    def send_message(self, prompt: str):
        raw_schema = self.schema_model.model_json_schema()
        gemini_schema = convert_to_gemini_schema(raw_schema)
        
        response_format = {
            "type": "text",
            "mime_type": "application/json",
            "schema": gemini_schema
        }
        
        try:
            interaction = self.client.interactions.create(
                model=self.model_name,
                input=prompt,
                previous_interaction_id=self.previous_interaction_id,
                system_instruction=self.system_instruction,
                response_format=response_format,
                store=True,
                background=True,
                generation_config={"temperature": self.temperature}
            )
            import time
            while interaction.status in ["in_progress"]:
                time.sleep(1)
                interaction = self.client.interactions.get(id=interaction.id)
                
            if interaction.status == "failed":
                raise Exception("Google GenAI Interaction failed.")
        except Exception as e:
            if "does not support background" in str(e).lower() or "background" in str(e).lower():
                interaction = self.client.interactions.create(
                    model=self.model_name,
                    input=prompt,
                    previous_interaction_id=self.previous_interaction_id,
                    system_instruction=self.system_instruction,
                    response_format=response_format,
                    store=True,
                    background=False,
                    generation_config={"temperature": self.temperature}
                )
            else:
                raise e

        self.previous_interaction_id = interaction.id

        content_text = ""
        if interaction.steps:
            for step in reversed(interaction.steps):
                if step.type == 'model_output' and step.content:
                    text_parts = []
                    for part in step.content:
                        if part.type == 'text':
                            text_parts.append(part.text)
                    if text_parts:
                        content_text = "".join(text_parts)
                        break

        class MockUsage:
            def __init__(self, u):
                self.total_token_count = getattr(u, "total_tokens", 0) or 0
                self.prompt_token_count = getattr(u, "total_input_tokens", 0) or 0
                self.candidates_token_count = getattr(u, "total_output_tokens", 0) or 0

        class MockResponse:
            def __init__(self, text, usage):
                self.text = text
                self.usage_metadata = MockUsage(usage) if usage else None

        return MockResponse(content_text, getattr(interaction, "usage", None))

class MantisAgent:
    """
    Project Mantis core intelligence. 
    Agnostic Provider Pattern (Supports Vertex, Gemini Free, and OpenAI-compatible endpoints).
    """
    def __init__(self):
        self.provider = os.environ.get("PM_LLM_PROVIDER", "vertex").lower()
        ExecutionLogger.log("AGENT", f"Initializing MantisAgent with provider: {self.provider.upper()}")
        
        if self.provider in ["vertex", "gemini_free"]:
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
            else:
                api_key = os.environ.get("OPENAI_API_KEY") or os.environ.get("GEMINI_API_KEY")
                if not api_key:
                    raise ValueError("[!] Either OPENAI_API_KEY or GEMINI_API_KEY must be set for gemini_free.")
                self.client = genai.Client(api_key=api_key)
                self.model_name = os.environ.get("OPENAI_MODEL_NAME", "gemini-3.1-flash-lite")
            
        elif self.provider in ["openai", "local", "groq", "cerebras", "nvidia"]:
            try:
                import openai
            except ImportError:
                ExecutionLogger.log("AGENT", "OpenAI library not found. Please 'pip install openai'", "ERROR")
                raise ImportError("You must install the 'openai' python package to use this provider.")
                
            api_key = os.environ.get("OPENAI_API_KEY", "dummy-local-key")
            base_url = os.environ.get("OPENAI_BASE_URL")
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
        if self.provider in ["vertex", "gemini_free"]:
            return GeminiInteractionSession(self.client, self.model_name, self.system_instruction, MantisEvaluation)
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
        if self.provider in ["vertex", "gemini_free"]:
            return GeminiInteractionSession(self.client, self.model_name, system_instruction, DefenseEvaluation)
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
        if self.provider in ["vertex", "gemini_free"]:
            return GeminiInteractionSession(self.client, self.model_name, system_instruction, VerifierEvaluation)
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
        if self.provider in ["vertex", "gemini_free"]:
            return GeminiInteractionSession(self.client, self.model_name, system_instruction, ExecutionChainSynthesis)
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
        
        if self.provider in ["vertex", "gemini_free"]:
            raw_schema = ExecutiveSynthesis.model_json_schema()
            gemini_schema = convert_to_gemini_schema(raw_schema)
            response_format = {
                "type": "text",
                "mime_type": "application/json",
                "schema": gemini_schema
            }
            
            try:
                ExecutionLogger.log("AGENT", "Synthesizing investigation with Google Search grounding tool...")
                interaction = self.client.interactions.create(
                    model=self.model_name,
                    input=prompt,
                    system_instruction=system_inst,
                    response_format=response_format,
                    tools=[{"type": "google_search"}],
                    generation_config={"temperature": 0.2},
                    store=True
                )
            except Exception as e:
                ExecutionLogger.log("AGENT", f"Google Search grounding failed or unsupported: {e}. Falling back to standard interaction.", "WARN")
                interaction = self.client.interactions.create(
                    model=self.model_name,
                    input=prompt,
                    system_instruction=system_inst,
                    response_format=response_format,
                    generation_config={"temperature": 0.2},
                    store=True
                )
                
            content_text = ""
            if interaction.steps:
                for step in reversed(interaction.steps):
                    if step.type == 'model_output' and step.content:
                        text_parts = []
                        for part in step.content:
                            if part.type == 'text':
                                text_parts.append(part.text)
                        if text_parts:
                            content_text = "".join(text_parts)
                            break
            
            u = getattr(interaction, "usage", None)
            if u:
                input_tokens = getattr(u, "total_input_tokens", 0) or 0
                output_tokens = getattr(u, "total_output_tokens", 0) or 0
                total_tokens = getattr(u, "total_tokens", 0) or 0
                ExecutionLogger.add_tokens(input_tokens, output_tokens)
                ExecutionLogger.log("AGENT", f"Synthesis Tokens: {total_tokens} (In: {input_tokens}, Out: {output_tokens})")
                
            return ExecutiveSynthesis.model_validate_json(content_text)
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
