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

class MantisAgent:
    """
    Project Mantis core intelligence. 
    Manages the Vertex AI Gemini context and iterative investigation loops.
    """
    def __init__(self):
        ExecutionLogger.log("AGENT", "Initializing Gemini MantisAgent with Playbook Deterministic Engine.")
        if os.environ.get("VERTEX_API_KEY"):
            self.client = genai.Client(
                vertexai=True, 
                api_key=os.environ.get("VERTEX_API_KEY")
            )
        else:
            if not os.environ.get("VERTEX_PROJECT_ID"):
                ExecutionLogger.log("AGENT", "VERTEX_PROJECT_ID or VERTEX_API_KEY environment variables not set.", "ERROR")
                raise ValueError("[!] Either VERTEX_API_KEY or VERTEX_PROJECT_ID must be set.")
            
            self.client = genai.Client(
                vertexai=True, 
                project=os.environ.get("VERTEX_PROJECT_ID"), 
                location=os.environ.get("VERTEX_LOCATION", "us-central1")
            )
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
        ExecutionLogger.log("AGENT", "Creating generative API session with Pydantic JSON schema constraints.")
        config = types.GenerateContentConfig(
            system_instruction=self.system_instruction,
            temperature=0.0,
            response_mime_type="application/json",
            response_schema=MantisEvaluation
        )
        return self.client.chats.create(model=os.environ.get("VERTEX_MODEL_NAME", "gemini-3.1-flash-lite"), config=config)

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
        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            temperature=0.0,
            response_mime_type="application/json",
            response_schema=DefenseEvaluation
        )
        return self.client.chats.create(model=os.environ.get("VERTEX_MODEL_NAME", "gemini-3.1-flash-lite"), config=config)

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
        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            temperature=0.0,
            response_mime_type="application/json",
            response_schema=VerifierEvaluation
        )
        return self.client.chats.create(model=os.environ.get("VERTEX_MODEL_NAME", "gemini-3.1-flash-lite"), config=config)

    def create_reconstruction_session(self):
        ExecutionLogger.log("AGENT", "Creating generative API session for Disk-to-Memory Reconstruction.")
        system_instruction = """
        You are a cross-dimensional threat analyst.
        Your job is to read the Memory payload conviction (the MALICIOUS process) and the provided Disk Timeline artifacts (events surrounding that PID's execution).
        You must reconstruct the exact execution chain: What file initiated the compromise on disk, and how did it lead to the memory injection?
        IMPORTANT: If you find separate indicators but no direct execution chain connecting them, DO NOT fabricate a link. If the initial dropper or execution vector is missing, explicitly classify the execution vector as UNKNOWN/CLEARED (Anti-Forensics suspected). Present the findings as parallel, disjointed attack phases rather than a single contiguous timeline.
        """
        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            temperature=0.0,
            response_mime_type="application/json",
            response_schema=ExecutionChainSynthesis
        )
        return self.client.chats.create(model=os.environ.get("VERTEX_MODEL_NAME", "gemini-3.1-flash-lite"), config=config)

    def synthesize_investigation(self, isolated_threats: list) -> ExecutiveSynthesis:
        ExecutionLogger.log("AGENT", "Synthesizing executive report from isolated threats and performing OSINT attribution...")
        prompt = "Based on the following isolated evidence, reconstruct the timeline and write an Incident Response narrative.\n\nISOLATED THREATS:\n"
        for idx, threat in enumerate(isolated_threats):
            res = threat['result']
            prompt += f"\n--- THREAT {idx+1} ---\nEntity: {threat['pid']}\n"
            prompt += f"Verdict: {res.verdict.classification}\nReasoning: {res.verdict.confidence_reasoning}\n"
            if 'evidence' in threat:
                prompt += f"Evidence: {json.dumps(threat['evidence'])}\n"
        
        config = types.GenerateContentConfig(
            system_instruction="You are a Lead Forensic Investigator (v0.4.4.3). Synthesize triage data into a cohesive incident report. You have access to Google Search.",
            temperature=0.2,
            response_mime_type="application/json",
            response_schema=ExecutiveSynthesis,
            tools=[{"google_search": {}}]
        )
        response = self.client.models.generate_content(
            model=os.environ.get("VERTEX_MODEL_NAME", "gemini-3.1-flash-lite"),
            contents=prompt,
            config=config
        )
        return ExecutiveSynthesis.model_validate_json(response.text)
