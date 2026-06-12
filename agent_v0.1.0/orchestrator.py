import sys
import os
import json
import re
import subprocess
import time
import datetime
import hashlib
import getpass
from agent import FindEvilAgent
from mcp_server import (
    read_evidence_cache, extract_and_hash_inode, 
    initiate_global_extraction, read_dfir_playbook
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "extractor.log")
EXTRACTOR_SCRIPT = os.path.join(BASE_DIR, "extractor.py")

# --- V0.1.0 AUDIT LEDGER ENGINE ---
def write_thought_ledger(phase: str, component: str, details: str):
    """Append-only physical ledger for zero-trust transparency."""
    timestamp = datetime.datetime.now().astimezone().isoformat()
    log_path = os.path.join(BASE_DIR, "thoughts.txt")
    entry = f"[{timestamp}] | {phase} | {component}\n{details}\n{'-'*80}\n"
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(entry)

def safe_api_call(chat_session, prompt: str, max_retries: int = 5) -> str:
    """Executes the API call with native exponential backoff and transparent logging."""
    write_thought_ledger("TX_OUTBOUND", "GOOGLE_GATEWAY", prompt)
    print("\n[API BOUNDARY START] Transmitting payload to Google Gateway...")
    
    base_delay = 2 
    for attempt in range(max_retries):
        try:
            response = chat_session.send_message(prompt)
            response_text = response.text
            write_thought_ledger("RX_INBOUND", "LLM_RAW_OUTPUT", response_text)
            print("[API BOUNDARY END] Response received successfully.")
            return response_text
        except Exception as e:
            error_msg = str(e)
            if any(err in error_msg for err in ["429", "503", "500", "Resource has been exhausted", "timeout"]):
                delay = base_delay * (2 ** attempt)
                log_entry = f"Attempt {attempt + 1}/{max_retries} failed ({error_msg[:50]}...). Backing off for {delay}s."
                write_thought_ledger("API_THROTTLED", "NETWORK_CHOKE", log_entry)
                print(f"[*] API Jitter/Quota limit hit. Enforcing physical backoff: {delay} seconds...")
                time.sleep(delay)
                continue 
            else:
                write_thought_ledger("FATAL_ERROR", "API_EXCEPTION", error_msg)
                print(f"[!] UNRECOVERABLE API ERROR: {error_msg}")
                return "{}"
                
    exhaust_msg = f"Failed to connect after {max_retries} attempts."
    write_thought_ledger("FATAL_ERROR", "MAX_RETRIES_EXHAUSTED", exhaust_msg)
    print(f"[!] {exhaust_msg}")
    return "{}"

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
    print("[ PROJECT FIND EVIL - ASYNCHRONOUS AUTONOMY ENGINE (V0.1.0) ]")
    print("------------------------------------------------------------")
    print("[BLOCK] Agent Core Initialization (v0.1.0)")
    
    agent_system = FindEvilAgent()
    tools = [read_evidence_cache, extract_and_hash_inode, initiate_global_extraction, read_dfir_playbook]
    chat_session = agent_system.create_session(tools_list=tools)

    print("[STATUS] Core logic initialized. Logging to thoughts.txt.")
    print("------------------------------------------------------------")
    print("[*] Ready. Type 'investigate' to initiate total autonomy.\n")
    
    while True:
        try:
            user_input = input("\n[Investigator] > ")
            if user_input.lower() in ['exit', 'quit']: break
            if not user_input.strip(): continue

            response_text = safe_api_call(chat_session, user_input)
            clean_payload = clean_json_payload(response_text)
            
            while True:
                try:
                    command_dict = json.loads(clean_payload)
                    
                    reasoning = command_dict.get("reasoning", "NO_REASONING_PROVIDED")
                    action = command_dict.get("action", "UNKNOWN")
                    plugin = command_dict.get("plugin", "NONE")
                    keyword = command_dict.get("keyword", "")
                    
                    router_state = f"Reasoning: {reasoning}\nAction: {action} | Plugin: {plugin} | Keyword: {keyword}"
                    write_thought_ledger("ROUTING_DECISION", "COGNITIVE_CORE", router_state)
                    
                    print(f"\n[ COGNITIVE ROUTER ] {reasoning}")
                    print(f"[ TELEMETRY ] Action: {action} | Plugin: {plugin} | Keyword: '{keyword}'")
                    
                    if action == "read_dfir_playbook":
                        print(f"[*] STATE: EXECUTING -> read_dfir_playbook")
                        try:
                            playbook_data = read_dfir_playbook()
                            print("[*] Playbook loaded into memory.")
                        except Exception as e:
                            playbook_data = f"ERROR reading playbook: {e}"
                            print(f"[!] {playbook_data}")

                        system_feedback = (
                            f"[SYSTEM DATA: PLAYBOOK READ SUCCESS]\n{playbook_data}\n\n"
                            f"[DIRECTIVE] You have read the standard operating procedures. "
                            f"Evaluate state and output NEXT action in strict JSON."
                        )

                    elif action == "initiate_global_extraction":
                        print(f"[*] STATE: EXECUTING -> initiate_global_extraction")
                        try:
                            extract_status = initiate_global_extraction()
                            print(f"[*] Signal executed: {extract_status}")
                        except Exception as e:
                            extract_status = f"ERROR initiating extraction: {e}"
                            print(f"[!] {extract_status}")

                        system_feedback = (
                            f"[SYSTEM DATA: EXTRACTION SIGNAL]\n{extract_status}\n\n"
                            f"[DIRECTIVE] Global extraction sequence initiated. "
                            f"Proceed with targeted cache reads in strict JSON format."
                        )

                    elif action == "read_evidence_cache":
                        if plugin in ['pstree', 'cmdline', 'netscan', 'malfind']:
                            print(f"[*] STATE: EXECUTING -> read_evidence_cache | {plugin} | Target: '{keyword}'")
                            try:
                                cache_data = read_evidence_cache(plugin_name=plugin, keyword=keyword)
                                print("[*] Target data extracted from cache.")
                                write_thought_ledger("TOOL_EXECUTION", f"NATIVE_{plugin.upper()}", cache_data[:1000] + "\n...[TRUNCATED IN LOG]")
                            except Exception as e:
                                cache_data = f"ERROR reading cache for {plugin}: {e}"
                                write_thought_ledger("TOOL_ERROR", f"NATIVE_{plugin.upper()}", cache_data)
                                print(f"[!] {cache_data}")

                            system_feedback = (
                                f"[SYSTEM DATA: CACHE READ - {plugin}]\n{cache_data}\n\n"
                                f"[DIRECTIVE] Analyze this data strictly. Do not hallucinate. "
                                f"Output your NEXT command in strict JSON."
                            )
                        else:
                            print(f"[!] SYSTEM HALT: Agent attempted illegal plugin: {plugin}")
                            system_feedback = f"[SYSTEM OVERRIDE] Illegal plugin '{plugin}'. Allowed: pstree, cmdline, netscan, malfind."

                    elif action == "extract_and_hash_inode":
                        print(f"[*] STATE: EXECUTING -> extract_and_hash_inode | Target: {keyword}")
                        try:
                            inode_data = extract_and_hash_inode(inode=keyword)
                            print("[*] Inode hash calculated and secured.")
                        except Exception as e:
                            inode_data = f"ERROR hashing inode {keyword}: {e}"
                            print(f"[!] {inode_data}")

                        system_feedback = (
                            f"[SYSTEM DATA: INODE EXTRACTION]\n{inode_data}\n\n"
                            f"[DIRECTIVE] Inode extraction complete. Evaluate state and output NEXT command in strict JSON."
                        )

                    elif action == "request_human_review":
                        print(f"\n[{'='*60}]")
                        print(f"[ INVESTIGATION COMPLETE - EXAMINER REVIEW REQUIRED ]")
                        print(f"[*] Agent Summary: {keyword}")
                        print(f"[{'='*60}]")
                        
                        examiner_key = getpass.getpass("\n[?] Enter Examiner Key to sign and commit (or 'R' to reject): ")
                        
                        if examiner_key.lower() == 'r':
                            print("[!] Findings rejected by human examiner. Re-aligning pipeline...")
                            system_feedback = "[SYSTEM OVERRIDE] The examiner REJECTED your final finding. Re-evaluate the evidence cache and pivot."
                            print("[*] Passing context back to cognitive core...")
                            response_text = safe_api_call(chat_session, system_feedback)
                            clean_payload = clean_json_payload(response_text)
                            continue
                            
                        timestamp = datetime.datetime.now().astimezone().isoformat()
                        payload_string = f"{timestamp}|{keyword}|{examiner_key}".encode('utf-8')
                        signature = hashlib.sha256(payload_string).hexdigest()
                        
                        print(f"[*] EVIDENTIARY COMMIT SUCCESS.")
                        print(f"[*] SHA-256 SIGNATURE: {signature}")
                        
                        with open(os.path.join(BASE_DIR, "verified_findings.log"), "a", encoding="utf-8") as f:
                            f.write(f"[{timestamp}] SIGNATURE: {signature} | FINDING: {keyword}\n")
                        
                        print("\n[*] Compiling final MITRE ATT&CK intelligence product...")
                        report_prompt = (
                            f"[CRITICAL OVERRIDE] You are a Tier 3 DFIR Lead writing a formal incident report. "
                            f"Generate a final Markdown document based strictly on this cryptographically verified finding: '{keyword}'. "
                            f"Include an Executive Summary, MITRE ATT&CK mappings (Tactic & Technique), and remediation steps. "
                            f"Do not output JSON. Output pure Markdown."
                        )
                        
                        report_text = safe_api_call(chat_session, report_prompt)
                        report_filename = os.path.join(BASE_DIR, f"PFE_Final_Report_{timestamp.replace(':', '').replace('-', '')}.md")
                        
                        with open(report_filename, "w", encoding="utf-8") as f:
                            f.write(f"**CHAIN OF CUSTODY SIGNATURE:** `{signature}`\n")
                            f.write(f"**TIMESTAMP:** {timestamp}\n\n")
                            f.write(report_text)
                            
                        print(f"[*] MISSION ACCOMPLISHED. Report written to: {report_filename}")
                        break

                    else:
                        print(f"[!] SYSTEM HALT: Agent attempted illegal action: {action}")
                        system_feedback = f"[SYSTEM OVERRIDE] Illegal action '{action}'. You must use an action from the allowed list."

                    print("[*] Passing context back to cognitive core...")
                    response_text = safe_api_call(chat_session, system_feedback)
                    clean_payload = clean_json_payload(response_text)
                    continue 

                except json.JSONDecodeError:
                    print(f"\n[!] FATAL ERROR: Agent broke schema. Raw text:\n{clean_payload}")
                    error_prompt = "[SYSTEM OVERRIDE] JSONDecodeError. You failed to output valid JSON. Output ONLY valid JSON matching the schema."
                    print("[*] Re-aligning cognitive pipeline...")
                    response_text = safe_api_call(chat_session, error_prompt)
                    clean_payload = clean_json_payload(response_text)
                    continue

        except KeyboardInterrupt: 
            print("\n\n[*] Manual interrupt detected. Terminating session.")
            break
        except Exception as e: 
            print(f"\n[!] Orchestrator Error: {e}")
            break

if __name__ == "__main__":
    main()
