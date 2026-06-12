# agent.py
import os
from google import genai
from google.genai import types

class FindEvilAgent:
    def __init__(self):
        print("\n" + "-"*60)
        print("[BLOCK] Agent Initialization")
        print("[ACTION] Verifying API authentication and loading system instructions.")
        print("[REASON] Establishing the core ReAct cognitive engine.")
        
        if not os.environ.get("GEMINI_API_KEY"):
            print("[STATUS] [FAILED] GEMINI_API_KEY environment variable missing.")
            print("-" * 60)
            raise ValueError("[!] GEMINI_API_KEY environment variable not set.")
        
        self.client = genai.Client()
        self.system_instruction = """
        You are 'Project Find Evil', an autonomous DFIR agent operating in a CLI.
        You act as the primary investigator triaging a memory dump.
        
        CRITICAL OPERATING DIRECTIVES (The ReAct Loop):
        1. REASON: Use `record_cognitive_process` to log your exact hypothesis, capability check, and intended action. Translate the user's natural language into a technical DFIR strategy.
        2. ACT: Use `query_forensic_evidence` to execute your strategy. 
        3. OBSERVE: Analyze the raw telemetry returned to you.
        4. REPEAT: Follow the technical trail autonomously until you reach a definitive conclusion or physically exhaust your capabilities.
        
        ENVIRONMENTAL CONSTRAINTS:
        - You ONLY have access to three plugins: 'windows.malfind', 'windows.pstree', and 'windows.netscan'. 
        - You completely lack disk forensics, string extraction, registry parsing, or file system metadata capabilities. If a user query requires these, inform them of your hard limitations.
        - 'windows.pstree' and 'windows.netscan' are massive datasets. You MUST provide a specific `search_term` (like a PID or IP address) when querying them to avoid token exhaustion. 
        - 'windows.malfind' can be queried without a search term to establish initial footholds.
        
        Do not ask the user for permission or step-by-step guidance. You are the investigator. Hunt.
        """

        print("[STATUS] [SUCCESS] Agent core initialized securely.")
        print("-" * 60)
        
    def create_session(self, tools_list):
        config = types.GenerateContentConfig(
            system_instruction=self.system_instruction,
            tools=tools_list,
            temperature=0.1
        )
        return self.client.chats.create(
            model='gemini-3.1-flash-lite',
            config=config
        )
