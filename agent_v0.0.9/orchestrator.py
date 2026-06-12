import sys
import os
import json
import re
import subprocess
import time
import datetime
from agent import FindEvilAgent
from mcp_server import (
    read_evidence_cache, extract_and_hash_inode, 
    initiate_global_extraction, read_dfir_playbook
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "extractor.log")
EXTRACTOR_SCRIPT = os.path.join(BASE_DIR, "extractor.py")

def safe_api_call(chat_session, prompt: str, max_retries=4) -> str:
    print(f"\n[API BOUNDARY START] Transmitting payload to Google Gateway...")
    delay = 5
    for attempt in range(max_retries):
        try:
            response = chat_session.send_message(prompt)
            print(f"[API BOUNDARY END] Response received successfully.")
            return response.text
        except Exception as e:
            error_msg = str(e)
            print(f"[API FAIL] Exception caught: {error_msg}")
            if "503" in error_msg or "429" in error_msg or "Quota" in error_msg:
                print(f"[!] API Gateway Constraint. Attempt {attempt + 1}/{max_retries}.")
                print(f"[*] Suspending pipeline for {delay} seconds...")
                time.sleep(delay)
                delay *= 2 
            else:
                raise e
    raise SystemError("[FATAL] API failed to respond after maximum retries. Pipeline halted.")

def clean_json_payload(raw_response: str) -> str:
    """Strips markdown formatting and isolates the JSON dictionary natively."""
    cleaned = re.sub(r'```json\s*', '', raw_response)
    cleaned = re.sub(r'```\s*', '', cleaned)
    start = cleaned.find('{')
    end = cleaned.rfind('}')
    
    if start != -1 and end != -1:
        return cleaned[start:end+1]
    return "{}"

def build_cache_natively():
    print("\n" + "="*60)
    print("[SYSTEM LOCK] LLM session suspended. Initiating native hardware choke.")
    print("="*60 + "\n")
    start_time = time.time()
    
    with open(LOG_PATH, "w") as log_file:
        process = subprocess.Popen(
            ["python3", EXTRACTOR_SCRIPT, "--deep"], 
            stdout=log_file, stderr=subprocess.STDOUT
        )
        try:
            while process.poll() is None:
                elapsed = int(time.time() - start_time)
                sys.stdout.write(f"\r[STATUS] Hardware Choke Active... Time Elapsed: {datetime.timedelta(seconds=elapsed)} ")
                sys.stdout.flush()
                time.sleep(1)
        except KeyboardInterrupt:
            process.terminate()
            print("\n\n[!] Extraction manually aborted.")
            raise

def main():
    print("[ PROJECT FIND EVIL - ASYNCHRONOUS AUTONOMY ENGINE (V0.0.9) ]")
    print("------------------------------------------------------------")
    print("[BLOCK] Agent Core Initialization (v0.0.9)")
    
    agent_system = FindEvilAgent()
    tools = [read_evidence_cache, extract_and_hash_inode, initiate_global_extraction, read_dfir_playbook]
    chat_session = agent_system.create_session(tools_list=tools)

    print("[STATUS] Core logic initialized.")
    print("------------------------------------------------------------")
    print("[*] Ready. Type 'investigate' to initiate total autonomy.\n")
    
    while True:
        try:
            user_input = input("\n[Investigator] > ")
            if user_input.lower() in ['exit', 'quit']: break
            if not user_input.strip(): continue

            # 1. API BOUNDARY
            response_text = safe_api_call(chat_session, user_input)
            
            # 2. THE SANITIZER INJECTION
            # Immediately scrub the payload before the orchestrator attempts to read it.
            clean_payload = clean_json_payload(response_text)
            
            # 3. DETERMINISTIC PARSING & ROUTING (THE INNER AUTONOMY LOOP)
            # This closed-circuit loop allows the agent to chain actions infinitely 
            # until it requires human intervention.
            while True:
                try:
                    command_dict = json.loads(clean_payload)
                    
                    # Extract telemetry
                    reasoning = command_dict.get("reasoning", "NO_REASONING_PROVIDED")
                    action = command_dict.get("action", "UNKNOWN")
                    plugin = command_dict.get("plugin", "NONE")
                    keyword = command_dict.get("keyword", "")
                    
                    print(f"\n[ COGNITIVE ROUTER ] {reasoning}")
                    print(f"[ TELEMETRY ] Action: {action} | Plugin: {plugin} | Keyword: '{keyword}'")
                    
                    # Deterministic Execution Gate
                    if action == "read_dfir_playbook":
                        print(f"[*] STATE: EXECUTING -> read_dfir_playbook")
                        
                        try:
                            playbook_data = read_dfir_playbook()
                            print("[*] Playbook loaded into memory.")
                        except Exception as e:
                            playbook_data = f"ERROR reading playbook: {e}"
                            print(f"[!] {playbook_data}")

                        system_feedback = (
                            f"[SYSTEM DATA: PLAYBOOK READ SUCCESS]\n"
                            f"{playbook_data}\n\n"
                            f"[DIRECTIVE] You have read the standard operating procedures. "
                            f"Evaluate the state and output your NEXT action in strict JSON format."
                        )
                        
                        print("[*] Passing context back to cognitive core...")
                        response_text = safe_api_call(chat_session, system_feedback)
                        clean_payload = clean_json_payload(response_text)
                        
                        # [!] THE AUTONOMY TRIGGER
                        # This 'continue' bypasses the human prompt and forces the loop 
                        # to instantly parse the new clean_payload.
                        continue 

                    elif action == "initiate_global_extraction":
                        print(f"[*] STATE: EXECUTING -> initiate_global_extraction")
                        # result = initiate_global_extraction()
                        # until we fully wire this specific tool up.
                        break 
                        
                    elif action == "read_evidence_cache":
                        if plugin in ['pstree', 'cmdline', 'netscan', 'malfind']:
                            print(f"[*] STATE: EXECUTING -> read_evidence_cache | {plugin}")
                            # result = read_evidence_cache(plugin=plugin, keyword=keyword)
                            break # Drop to manual prompt until tool is wired
                        else:
                            print(f"[!] SYSTEM HALT: Agent attempted illegal plugin: {plugin}")
                            error_prompt = f"[SYSTEM OVERRIDE] Illegal plugin '{plugin}'. Allowed: pstree, cmdline, netscan, malfind."
                            print("[*] Re-aligning cognitive pipeline...")
                            response_text = safe_api_call(chat_session, error_prompt)
                            clean_payload = clean_json_payload(response_text)
                            continue # Auto-correct without human input
                            
                    elif action == "extract_and_hash_inode":
                        print(f"[*] STATE: EXECUTING -> extract_and_hash_inode | {keyword}")
                        # result = extract_and_hash_inode(inode=keyword)
                        break # Drop to manual prompt until tool is wired
                        
                    else:
                        print(f"[!] SYSTEM HALT: Agent attempted illegal action: {action}")
                        error_prompt = f"[SYSTEM OVERRIDE] Illegal action '{action}'. You must use an action from the allowed list."
                        print("[*] Re-aligning cognitive pipeline...")
                        response_text = safe_api_call(chat_session, error_prompt)
                        clean_payload = clean_json_payload(response_text)
                        continue # Auto-correct without human input

                except json.JSONDecodeError:
                    print(f"\n[!] FATAL ERROR: Agent broke schema. Raw text:\n{clean_payload}")
                    error_prompt = "[SYSTEM OVERRIDE] JSONDecodeError. You failed to output valid JSON. Output ONLY valid JSON matching the schema."
                    print("[*] Re-aligning cognitive pipeline...")
                    response_text = safe_api_call(chat_session, error_prompt)
                    clean_payload = clean_json_payload(response_text)
                    continue # Auto-correct without human input
            
            # 4. EXISTING HARDWARE CHOKE LOGIC
            # Update this to trigger via the JSON action, not a text string match.
            if action == "INITIATE_HARDWARE_CHOKE":
                print(f"\n[ AGENT SIGNAL RECEIVED ] Agent requested global extraction.")
                
                json_cache = os.path.join(BASE_DIR, "evidence_cache", "netscan.json")
                txt_cache = os.path.join(BASE_DIR, "evidence_cache", "netscan.txt")
                
                if os.path.exists(json_cache) or os.path.exists(txt_cache):
                    print("[SYSTEM OPTIMIZATION] Pre-computed global cache detected on disk.")
                else:
                    build_cache_natively()
                
                # ... (wake prompt and re-establishing context logic remains unchanged) ...

        except KeyboardInterrupt: 
            print("\n\n[*] Manual interrupt detected. Terminating session.")
            break
        except Exception as e: 
            print(f"\n[!] Orchestrator Error: {e}")

if __name__ == "__main__":
    main()
