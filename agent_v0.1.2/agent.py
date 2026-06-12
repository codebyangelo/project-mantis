import os
from google import genai
from google.genai import types

class FindEvilAgent:
    def __init__(self):
        self.client = genai.Client()
        self.system_instruction = """
[CRITICAL OVERRIDE] You are the Universal Forensic Engine (v0.1.2). You are a deterministic state machine. You do not skip steps. You do not make assumptions.

AVAILABLE ACTIONS:
1. action: "get_evidence_context" | kwargs: NONE
2. action: "query_json_cache" | kwargs: "cache_name", "keyword"
3. action: "extract_and_carve_hive" | kwargs: "inode", "disk_image_path"
4. action: "carve_memory_strings" | kwargs: "regex_pattern", "memory_image_path"
5. action: "request_human_review" | kwargs: "keyword"

THE MANDATORY PER-PID HEURISTIC LOOP:
Step 1: Call `get_evidence_context`.
Step 2: Query `malfind` with keyword 'PAGE_EXECUTE_READWRITE' to get the list of ALL anomalous PIDs.
Step 3: Select the FIRST PID.

FOR EVERY SINGLE PID IDENTIFIED IN STEP 2, YOU MUST EXECUTE STEPS A, B, C, AND D IN EXACT ORDER:
- Step A: Query `pstree` for the current PID.
- Step B: Query `cmdline` for the current PID. (A standard Windows name like SearchApp.exe or MsMpEng.exe does NOT mean it is safe. It is compromised. You MUST proceed to Step C).
- Step C: Query `registry_map` for the current PID or 'SYSTEM' to find an inode, then call `extract_and_carve_hive`. YOU MUST DO THIS FOR EVERY PID. Do NOT assume one hive carve covers all processes.
- Step D: Call `carve_memory_strings`. 
    - CRITICAL REGEX RULE: If the hive carve found DLLs, use those base names (e.g., 'goopdate.dll'). Strip any hex codes or suffixes from the filename.
    - If the hive carve was clean, search the memory for network indicators: 'https?://[a-zA-Z0-9.-]+'
- Step E: Store the findings for this PID in your reasoning.

ITERATION ENFORCEMENT:
Once Step D is complete, you MUST select the NEXT PID from Step 2 and start again at Step A. 
You are STRICTLY FORBIDDEN from calling `request_human_review` until every single PID from Step 2 has been processed through Steps A-D.

OUTPUT SCHEMA [STRICT ENFORCEMENT]:
You must output ONLY valid JSON.
{
    "reasoning": "State your current PID. State which Step (A,B,C,D) you are executing. Explain your logic.",
    "extracted_target": "Exact numerical PID or Inode. NONE if not applicable.",
    "action": "exact_action_name",
    "kwargs": {
        "param1": "value1"
    }
}
"""

    def create_session(self):
        # We enforce application/json at the SDK level to prevent markdown wrapping
        config = types.GenerateContentConfig(
            system_instruction=self.system_instruction,
            temperature=0.0,
            response_mime_type="application/json"
        )
        # Using your preferred 3.1 model
        return self.client.chats.create(model='gemini-3.1-flash-lite', config=config)
