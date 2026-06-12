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
    evidence_values: dict
    result: str

class FalsePositiveCheck(BaseModel):
    check_id: str
    description: str
    environmental_context_used: dict
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

class ExecutiveSynthesis(BaseModel):
    who_attributed: str = Field(description="Who is the threat actor? (Use OSINT/Web search on the IPs or TTPs to find out)")
    what_happened: str = Field(description="Summary of the incident: What key projects/data were accessed and what was stolen?")
    where_transferred: str = Field(description="Where was the data transferred to? (e.g., Google Drive, USB)")
    how_stolen: str = Field(description="How was the data stolen or exfiltrated? Mention tools used.")
    when_occurred: str = Field(description="When did the activity occur based on timestamps in the evidence?")
    narrative: str = Field(description="A cohesive, 2-3 paragraph Incident Response narrative reconstructing the timeline and actions.")

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
        return self.client.chats.create(model='gemini-3.1-flash-lite', config=config)

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
            system_instruction="You are a Lead Forensic Investigator (v0.3.0). Synthesize triage data into a cohesive incident report. You have access to Google Search.",
            temperature=0.2,
            response_mime_type="application/json",
            response_schema=ExecutiveSynthesis,
            tools=[{"google_search": {}}]
        )
        response = self.client.models.generate_content(
            model='gemini-3.1-flash-lite',
            contents=prompt,
            config=config
        )
        return ExecutiveSynthesis.model_validate_json(response.text)
