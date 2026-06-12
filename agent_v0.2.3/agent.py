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
    request_memory_carve: bool = Field(description="True if surgical memory string extraction is required to prove a hypothesis.")
    mitre_techniques: List[str] = Field(description="List of applicable MITRE ATT&CK technique IDs (e.g. ['T1055', 'T1036']). Empty if benign.")
class FindEvilAgent:
    def __init__(self):
        ExecutionLogger.log("AGENT", "Initializing Gemini FindEvilAgent with Exhaustive Search & Scoring.")
        if not os.environ.get("GEMINI_API_KEY"):
            ExecutionLogger.log("AGENT", "GEMINI_API_KEY environment variable not set.", "ERROR")
            raise ValueError("[!] GEMINI_API_KEY environment variable not set.")
            
        self.client = genai.Client()
        self.system_instruction = """
        You are the Universal Forensic Engine (v0.2.3). 
        You act as an evaluator for DFIR triage.
        You will receive context about a single suspect PID, including its command line, pstree, heuristic signals, and network bindings.
        
        Your ONLY task is to classify this PID based on the provided evidence.
        
        SCORING RULES:
        - If the PID has benign origins and no severe heuristic signals (like SIG_RWX_INJECTION or SIG_MASQUERADING), output 'benign'.
        - If anomalous DLLs are injected (SIG_RWX_INJECTION) OR highly suspicious outbound network connections exist with process masquerading, output 'malicious'.
          - Set `severity_level` to 'Critical' for known C2/Dropper patterns.
        - Set `request_memory_carve` to True ONLY if you need concrete string evidence (like URLs or domains) from the process memory to prove your verdict. The Surgical Carver will extract strings directly from injected memory regions.
        
        MITRE ATT&CK TAGGING:
        - Assign T1055 (Process Injection) if SIG_RWX_INJECTION is present.
        - Assign T1036 (Masquerading) if SIG_MASQUERADING or filename truncations (e.g. .ex) are present.
        - Assign T1071 (Application Layer Protocol) if suspicious outbound network connections (C2 beacons) are identified.
        
        FOLLOW-UP RULES:
        - When evaluating FOLLOW-UP MEMORY INDICATORS, you MUST consider them alongside the original PSTREE and HEURISTIC evidence.
        - If the new strings contain C2 infrastructure OR the initial evidence (like masquerading names, SIG_RWX_INJECTION) remains highly suspicious, output 'malicious'.
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
