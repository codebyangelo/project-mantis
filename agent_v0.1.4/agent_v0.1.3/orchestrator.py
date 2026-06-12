import sys
import os
import json
import re
import time
import datetime
import hashlib
import getpass
from agent import FindEvilAgent
from mcp_server import (
    get_evidence_context, query_json_cache,
    extract_and_carve_hive, carve_memory_strings, read_dfir_playbook
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "thoughts.txt")
IOC_STORE = os.path.join(BASE_DIR, "ioc_store.json")

def write_thought_ledger(phase: str, component: str, details: str):
    timestamp = datetime.datetime.now().astimezone().isoformat()
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] | {phase} | {component}\n{details}\n{'-'*80}\n")

def safe_api_call(chat_session, prompt: str, max_retries: int = 5) -> str:
    write_thought_ledger("TX_OUTBOUND", "GOOGLE_GATEWAY", prompt)
    print("\n[API BOUNDARY START] Transmitting payload...")
    for attempt in range(max_retries):
        try:
            response = chat_session.send_message(prompt)
            write_thought_ledger("RX_INBOUND", "LLM_RAW_OUTPUT", response.text)
            print("[API BOUNDARY END] Response received.")
            return response.text
        except Exception as e:
            delay = 2 * (2 ** attempt)
            print(f"[*] API Throttled/Error: {e}. Backing off {delay}s...")
            time.sleep(delay)
    return "{}"

def clean_json_payload(raw_response: str) -> str:
    cleaned = re.sub(r'```json\s*', '', raw_response)
    cleaned = re.sub(r'```\s*', '', cleaned)
    start = cleaned.find('{')
    end = cleaned.rfind('}')
    if start != -1 and end != -1:
        return cleaned[start:end+1]
    return "{}"

def execute_tool(action, kwargs):
    """Maps the LLM's action request to the actual Python function."""
    if action == "get_evidence_context":
        return get_evidence_context()
    elif action == "query_json_cache":
        return query_json_cache(kwargs.get("cache_name", ""), kwargs.get("keyword", ""))
    elif action == "extract_and_carve_hive":
        return extract_and_carve_hive(kwargs.get("inode", ""), kwargs.get("disk_image_path", ""))
    elif action == "carve_memory_strings":
        return carve_memory_strings(kwargs.get("regex_pattern", ""), kwargs.get("memory_image_path", ""))
    elif action == "read_dfir_playbook":
        return read_dfir_playbook()
    else:
        return f"[!] Illegal Action Requested: {action}"

def update_ioc_store(new_finding: str):
    print("[*] Committing finding to historical IOC store...")
    store = {"tactical_signatures": []}
    if os.path.exists(IOC_STORE):
        try:
            with open(IOC_STORE, "r") as f:
                store = json.load(f)
        except json.JSONDecodeError:
            pass
            
    store["tactical_signatures"].append(new_finding)
    
    with open(IOC_STORE, "w") as f:
        json.dump(store, f, indent=4)

def generate_mitre_report(finding: str):
    print("\n[SYSTEM] Initiating MITRE ATT&CK Report Generation...")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(BASE_DIR, f"PFE_MITRE_Report_{timestamp}.md")
    
    # Structure the payload
    report_content = f"""# Project Find Evil (v0.1.3) - Autonomous DFIR Report
**Date:** {datetime.datetime.now().astimezone().isoformat()}
**Engine Mode:** UFE Heuristic Routing

## 1. Executive Summary & Payload
{finding}

## 2. Tactical ATT&CK Mapping
* **Defense Evasion (TA0005):** Process Injection (PAGE_EXECUTE_READWRITE anomalies)
* **Persistence (TA0003):** Registry Hive / User Temp Directory 
* **Execution (TA0002):** Malicious DLL Sideloading (e.g., goopdate.dll)

## 3. Cryptographic Sealing
"""
    # Write initial document
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)
        
    # Hash the physical file for integrity
    hasher = hashlib.sha256()
    with open(report_path, "rb") as f:
        hasher.update(f.read())
    doc_hash = hasher.hexdigest()
    
    # Request Examiner Key for signature
    examiner_key = getpass.getpass("[?] Enter Examiner Key to seal the document: ")
    auth_hash = hashlib.sha256(f"{doc_hash}|{examiner_key}".encode('utf-8')).hexdigest()
    
    # Append the cryptographic seals to the physical file
    with open(report_path, "a", encoding="utf-8") as f:
        f.write(f"- **Document SHA-256:** {doc_hash}\n")
        f.write(f"- **Examiner Signature:** {auth_hash}\n")
        
    print(f"[*] Report successfully forged at: {report_path}")
    print(f"[*] Document Integrity Hash: {doc_hash}")

def main():
    print("[ PROJECT FIND EVIL - UNIVERSAL FORENSIC ENGINE (V0.1.3) ]")
    print("------------------------------------------------------------")
    
    agent_system = FindEvilAgent()
    chat_session = agent_system.create_session() # No tools passed to SDK

    if os.path.exists(IOC_STORE):
        with open(IOC_STORE, "r") as f:
            known_iocs = f.read()
        safe_api_call(chat_session, f"SYSTEM INIT: Historical IOCs: {known_iocs}")

    print("[*] Ready. Type 'investigate' to initiate autonomous heuristic loop.\n")

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
                    reasoning = command_dict.get("reasoning", "NO_REASONING")
                    action = command_dict.get("action", "UNKNOWN")
                    kwargs = command_dict.get("kwargs", {})

                    print(f"\n[ COGNITIVE ROUTER ] {reasoning}")
                    print(f"[ TELEMETRY ] Action: {action} | Params: {kwargs}")

                    if action == "request_human_review":
                        print(f"\n[ INVESTIGATION COMPLETE ]")
                        final_finding = kwargs.get('keyword', 'UNKNOWN_THREAT')
                        print(f"Finding: {final_finding}")
                        
                        # Trigger Cryptographic Report
                        generate_mitre_report(final_finding)
                        update_ioc_store(final_finding)
                        break

                    # Execute locally and feed results back
                    tool_result = execute_tool(action, kwargs)
                    system_feedback = f"[SYSTEM DATA: {action}]\n{tool_result}\n\n[DIRECTIVE] Evaluate state and output NEXT JSON action."
                   
                    print(f"[*] API Governor: Enforcing 15-second execution pace...")
                    time.sleep(15)
 
                    response_text = safe_api_call(chat_session, system_feedback)
                    clean_payload = clean_json_payload(response_text)

                except json.JSONDecodeError:
                    print(f"\n[!] JSON Parse Error. Forcing realignment.")
                    response_text = safe_api_call(chat_session, "[OVERRIDE] Invalid JSON. Output ONLY valid JSON.")
                    clean_payload = clean_json_payload(response_text)
                    continue

        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    main()
