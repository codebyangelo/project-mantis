import sys
import os
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
    print("[ PROJECT FIND EVIL - ASYNCHRONOUS AUTONOMY ENGINE (V0.0.8) ]")
    print("------------------------------------------------------------")
    print("[BLOCK] Agent Core Initialization (v0.0.8)")
    
    agent_system = FindEvilAgent()
    tools = [read_evidence_cache, extract_and_hash_inode, initiate_global_extraction, read_dfir_playbook]
    chat_session = agent_system.create_session(tools_list=tools)

    print("[STATUS] Core logic initialized.")
    print("------------------------------------------------------------")
    print("[*] Ready. Type 'investigate' to initiate total autonomy.")
    
    while True:
        try:
            user_input = input("\n[Investigator] > ")
            if user_input.lower() in ['exit', 'quit']: break
            if not user_input.strip(): continue

            response_text = safe_api_call(chat_session, user_input)
            
            if "[SYSTEM_STATE_CHANGE] INITIATE_HARDWARE_CHOKE" in response_text:
                print(f"\n[ AGENT SIGNAL RECEIVED ] Agent requested global extraction.")
                
                json_cache = os.path.join(BASE_DIR, "evidence_cache", "netscan.json")
                txt_cache = os.path.join(BASE_DIR, "evidence_cache", "netscan.txt")
                
                if os.path.exists(json_cache) or os.path.exists(txt_cache):
                    print("[SYSTEM OPTIMIZATION] Pre-computed global cache detected on disk.")
                else:
                    build_cache_natively()
                
                wake_prompt = (
                    "SYSTEM NOTIFICATION: Extraction complete. "
                    "Action Required: Read playbook, ingest memory cache sequentially, and report."
                )
                print("\n[Agent re-establishing context...]")
                response_text = safe_api_call(chat_session, wake_prompt)

            print(f"\n[{'='*60}]\n[ AGENT PAYLOAD ]\n[{'='*60}]\n{response_text}")

        except KeyboardInterrupt: 
            print("\n\n[*] Manual interrupt detected. Terminating session.")
            break
        except Exception as e: 
            print(f"\n[!] Orchestrator Error: {e}")

if __name__ == "__main__":
    main()
