import os
from pydantic import BaseModel, Field
from google import genai
from google.genai import types
from logger import ExecutionLogger

class AgentCommand(BaseModel):
    verdict: str = Field(description="Must be 'benign' or 'malicious'. Null hypothesis defaults to 'benign'.")
    confidence_score: float = Field(description="Float from 0.0 to 1.0 indicating certainty in the verdict based on evidence weight.")
    severity_level: str = Field(description="Categorical severity: 'None', 'Low', 'Medium', 'High', 'Critical'. Use 'None' for benign verdicts.")
    reasoning: str = Field(description="Detailed explanation of the verdict, justifying the confidence score and severity.")
    request_memory_carve: bool = Field(description="True if active network indicators are present and memory carving is required.")

class FindEvilAgent:
    def __init__(self):
        ExecutionLogger.log("AGENT", "Initializing Gemini FindEvilAgent with Exhaustive Search & Scoring.")
        if not os.environ.get("GEMINI_API_KEY"):
            ExecutionLogger.log("AGENT", "GEMINI_API_KEY environment variable not set.", "ERROR")
            raise ValueError("[!] GEMINI_API_KEY environment variable not set.")
            
        self.client = genai.Client()
        self.system_instruction = """
        You are the Universal Forensic Engine (v0.1.7). 
        You act as an evaluator for DFIR triage.
        You will receive context about a single suspect PID, including its command line, pstree, registry anomalies, and network bindings.
        
        Your ONLY task is to classify this PID based on the provided evidence.
        
        SCORING RULES:
        - If the registry carve is clean AND there are no outbound network connections, output 'benign'.
          - Set `confidence_score` high (e.g., 0.9) if evidence overwhelmingly proves it's benign.
          - Set `confidence_score` low (e.g., 0.4) if evidence is sparse or ambiguous.
        - If anomalous DLLs are injected OR suspicious outbound network connections exist, output 'malicious'.
          - Set `severity_level` to 'Critical' for known C2/Dropper patterns (e.g., UAC.dll in %Temp%).
          - Set `severity_level` to 'High' or 'Medium' for lesser anomalies.
        - Set `request_memory_carve` to True ONLY if active external network connections exist and you need to carve memory for C2 strings.
        
        FOLLOW-UP RULES:
        - If you are provided with FOLLOW-UP MEMORY INDICATORS (strings carved from RAM), evaluate them to determine the FINAL verdict.
        - If the strings are standard Microsoft, Google, or generic CDNs, output 'benign'.
        - If the strings contain explicit C2 infrastructure, suspicious IPs, or malware domains, output 'malicious'.
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
