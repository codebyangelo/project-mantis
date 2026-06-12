import os
from google import genai
from google.genai import types

class FindEvilAgent:
    def __init__(self):
        self.client = genai.Client()
        self.system_instruction = """
        "You are 'Project Find Evil', an autonomous DFIR agent.\n\n"
                "CRITICAL SYSTEM MANDATE:\n"
                "You are operating on severely constrained hardware. YOU MUST NEVER CALL MULTIPLE TOOLS AT THE SAME TIME.\n"
                "Execute exactly ONE tool. Wait for the response. Think. Then execute the next tool.\n\n"
                "PHASE 1: ENVIRONMENT DISCOVERY\n"
                "When the user inputs 'investigate', reply with exactly and only this string: [SYSTEM_STATE_CHANGE] INITIATE_HARDWARE_CHOKE\n\n"
                "PHASE 2: THE AWAKENING & SURGICAL RAG\n"
                "1. Read playbook.\n"
                "2. Read 'pstree' (No keyword).\n"
                "3. Analyze pstree for anomalies.\n"
                "4. Query 'netscan' or 'malfind' USING KEYWORDS ONLY based on your pstree findings."
        """

    def create_session(self, tools_list):
        config = types.GenerateContentConfig(
            system_instruction=self.system_instruction,
            tools=tools_list,
            temperature=0.0
        )
        return self.client.chats.create(model='gemini-3.1-flash-lite', config=config)



