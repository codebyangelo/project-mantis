import os
from pydantic import BaseModel, Field
from google import genai
from google.genai import types

class AgentCommand(BaseModel):
    verdict: str = Field(description="Must be 'benign' or 'malicious'. Null hypothesis defaults to 'benign'.")
    reasoning: str = Field(description="One-sentence explanation of the verdict based on evidence.")
    request_memory_carve: bool = Field(description="True if active network indicators are present and memory carving is required.")

class FindEvilAgent:
    def __init__(self):
        if not os.environ.get("GEMINI_API_KEY"):
            raise ValueError("[!] GEMINI_API_KEY environment variable not set.")
            
        self.client = genai.Client()
        self.system_instruction = """
        You are the Universal Forensic Engine (v0.1.5). 
        You act as an evaluator for DFIR triage.
        You will receive context about a single suspect PID, including its command line, pstree, registry anomalies, and network bindings.
        
        Your ONLY task is to classify this PID based on the provided evidence.
        - If the registry carve is clean AND there are no outbound network connections to external addresses, you MUST output 'benign' (Null Hypothesis).
        - If anomalous DLLs are injected OR suspicious outbound network connections exist, output 'malicious'.
        - Set `request_memory_carve` to True ONLY if active external network connections exist and you need to carve memory for C2 strings.
        """

    def create_session(self):
        config = types.GenerateContentConfig(
            system_instruction=self.system_instruction,
            temperature=0.0,
            response_mime_type="application/json",
            response_schema=AgentCommand
        )
        return self.client.chats.create(model='gemini-3.1-flash-lite', config=config)
