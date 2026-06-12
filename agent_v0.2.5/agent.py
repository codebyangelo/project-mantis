import os
from typing import List
from pydantic import BaseModel, Field
from google import genai
from google.genai import types
from logger import ExecutionLogger

class AgentCommand(BaseModel):
    verdict: str = Field(description="Must be 'benign' or 'malicious'. Null hypothesis defaults to 'benign'.")
    confidence_score: float = Field(description="Float from 0.0 to 1.0 indicating certainty in the verdict based on evidence weight.")
    severity_level: str = Field(description="Categorical severity: 'None', 'Low', 'Medium', 'High', 'Critical'. Use 'None' for benign verdicts.")
    reasoning: str = Field(description="Detailed explanation of the verdict, justifying the confidence score and severity.")
    request_deep_carve: bool = Field(description="True if surgical extraction (memory strings or registry DLL carve) is required to prove a hypothesis.")
    mitre_techniques: List[str] = Field(description="List of applicable MITRE ATT&CK technique IDs (e.g. ['T1055', 'T1036']). Empty if benign.")

class ExecutiveSynthesis(BaseModel):
    what_happened: str = Field(description="Summary of the incident: What key projects/data were accessed and what was stolen?")
    where_transferred: str = Field(description="Where was the data transferred to? (e.g., Google Drive, USB)")
    how_stolen: str = Field(description="How was the data stolen or exfiltrated? Mention tools used.")
    when_occurred: str = Field(description="When did the activity occur based on timestamps in the evidence?")
    narrative: str = Field(description="A cohesive, 2-3 paragraph Incident Response narrative reconstructing the timeline and actions of the threat actor.")

class FindEvilAgent:
    def __init__(self):
        ExecutionLogger.log("AGENT", "Initializing Gemini FindEvilAgent with Exhaustive Search & Scoring.")
        if not os.environ.get("GEMINI_API_KEY"):
            ExecutionLogger.log("AGENT", "GEMINI_API_KEY environment variable not set.", "ERROR")
            raise ValueError("[!] GEMINI_API_KEY environment variable not set.")
            
        self.client = genai.Client()
        self.system_instruction = """
        You are the Universal Forensic Engine (v0.2.5). 
        You act as an evaluator for DFIR triage.
        You will receive context about a single Suspect Entity (which could be a process PID, a File Path, or a Registry Hive).
        
        Your ONLY task is to classify this Entity based on the provided evidence.
        
        SCORING RULES:
        - If the Entity has benign origins and no severe heuristic signals, output 'benign'.
        - If anomalous DLLs are injected (SIG_RWX_INJECTION), highly suspicious outbound network connections exist, or malicious persistence is found in a Registry Hive, output 'malicious'.
        - DATA LEAKAGE: If you observe sensitive documents (e.g. .pdf, .xls) being accessed from non-standard or removable drives (e.g. D:, E:, F:) in the Registry or file path, output 'malicious' with 'Critical' severity, as this indicates an Insider Threat/Data Exfiltration.
          - Set `severity_level` to 'Critical' for known C2/Dropper patterns or Data Leakage.
        - Set `request_deep_carve` to True ONLY if you need concrete string evidence (like URLs or domains from a PID) OR if you need to extract anomalous DLL paths/USB Document paths from a Registry Hive to prove your verdict. The Carver will extract strings directly from the relevant asset.
        
        MITRE ATT&CK TAGGING:
        - Assign T1055 (Process Injection) if SIG_RWX_INJECTION is present.
        - Assign T1036 (Masquerading) if SIG_MASQUERADING or filename truncations (e.g. .ex) are present.
        - Assign T1071 (Application Layer Protocol) if suspicious outbound network connections are identified.
        - Assign T1547 (Boot or Logon Autostart Execution) for Registry Persistence.
        - Assign T1048 (Exfiltration Over Alternative Protocol) or T1119 (Automated Collection) if USB Data Leakage is observed.
        
        FOLLOW-UP RULES:
        - When evaluating FOLLOW-UP MEMORY/DISK INDICATORS, you MUST consider them alongside the original evidence.
        - If the new carved strings contain C2 infrastructure, malicious DLL paths, or USB document leakage paths, output 'malicious'.
        """
        ExecutionLogger.log("AGENT", "System instructions loaded successfully.")

    def create_session(self):
        ExecutionLogger.log("AGENT", "Creating generative API session with Pydantic JSON schema constraints.")
        config = types.GenerateContentConfig(
            system_instruction=self.system_instruction,
            temperature=0.0,
            response_mime_type="application/json",
            response_schema=AgentCommand
        )
        return self.client.chats.create(model='gemini-3.1-flash-lite', config=config)

    def synthesize_investigation(self, isolated_threats: list) -> ExecutiveSynthesis:
        ExecutionLogger.log("AGENT", "Synthesizing executive report from isolated threats...")
        prompt = "Based on the following isolated evidence, reconstruct the timeline and write an Incident Response narrative. Answer: What key projects were accessed? What was stolen? Where was it transferred to? How was it stolen? When did this occur? If the evidence does not support an answer, state 'Unknown based on evidence'.\n\nISOLATED THREATS:\n"
        for idx, threat in enumerate(isolated_threats):
            prompt += f"\n--- THREAT {idx+1} ---\nPID/Entity: {threat['pid']}\nSeverity: {threat['result'].severity_level}\nReasoning: {threat['result'].reasoning}\n"
        
        config = types.GenerateContentConfig(
            system_instruction="You are a Lead Forensic Investigator (v0.2.5). Synthesize triage data into a cohesive incident report.",
            temperature=0.2,
            response_mime_type="application/json",
            response_schema=ExecutiveSynthesis
        )
        response = self.client.models.generate_content(
            model='gemini-3.1-flash-lite',
            contents=prompt,
            config=config
        )
        return ExecutiveSynthesis.model_validate_json(response.text)
