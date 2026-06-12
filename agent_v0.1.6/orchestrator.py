import sys
import os
import json
import time
import datetime
import hashlib
import subprocess
from pydantic import ValidationError

from agent import FindEvilAgent, AgentCommand
from mcp_server import (
    get_evidence_context, query_json_cache,
    extract_and_carve_hive, carve_memory_strings, read_dfir_playbook
)
from config import EVIDENCE_DIR, CACHE_DIR, PLAYBOOK_PATH, IOC_STORE_PATH, THOUGHTS_PATH
from logger import ExecutionLogger

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = THOUGHTS_PATH
IOC_STORE = IOC_STORE_PATH

def write_thought_ledger(phase: str, component: str, details: str):
    # Purely for LLM interaction history (separating thoughts from execution mechanics)
    timestamp = datetime.datetime.now().astimezone().isoformat()
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] | {phase} | {component}\n{details}\n{'-'*80}\n")

def safe_api_call(chat_session, prompt: str, max_retries: int = 3) -> AgentCommand:
    write_thought_ledger("TX_OUTBOUND", "LLM_EVALUATION", prompt)
    ExecutionLogger.log("ORCHESTRATOR", "Querying Gemini 3.1 Flash-Lite Classifier (Pydantic enforced)...")
    for attempt in range(max_retries):
        try:
            response = chat_session.send_message(prompt)
            write_thought_ledger("RX_INBOUND", "LLM_RAW_OUTPUT", response.text)
            parsed = AgentCommand.model_validate_json(response.text)
            ExecutionLogger.log("ORCHESTRATOR", "Received and successfully validated LLM JSON response.", "SUCCESS")
            return parsed
        except Exception as e:
            delay = 2 * (attempt + 1)
            ExecutionLogger.log("ORCHESTRATOR", f"API Error/Validation Failed: {e}. Retrying in {delay}s...", "WARN")
            time.sleep(delay)
            
    ExecutionLogger.log("ORCHESTRATOR", "API Exhaustion. Falling back to benign state.", "ERROR")
    return AgentCommand(verdict="benign", reasoning="API Exhaustion Fallback", request_memory_carve=False)

def update_ioc_store(new_finding: str):
    ExecutionLogger.log("ORCHESTRATOR", "Committing finding to historical IOC store (atomic write).")
    store = {"tactical_signatures": []}
    if os.path.exists(IOC_STORE):
        try:
            with open(IOC_STORE, "r") as f:
                store = json.load(f)
        except json.JSONDecodeError:
            pass
            
    store["tactical_signatures"].append(new_finding)
    
    tmp_path = IOC_STORE + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(store, f, indent=4)
    os.rename(tmp_path, IOC_STORE)
    ExecutionLogger.log("ORCHESTRATOR", "IOC Store commit successful.", "SUCCESS")

def generate_mitre_report(finding: str):
    ExecutionLogger.log("ORCHESTRATOR", "Initiating MITRE ATT&CK Report Generation...")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(BASE_DIR, f"PFE_MITRE_Report_{timestamp}.md")
    
    report_content = f"""# Project Find Evil (v0.1.6) - Autonomous DFIR Report
**Date:** {datetime.datetime.now().astimezone().isoformat()}
**Engine Mode:** UFE Hardened Python State Machine (Transparent Logging)

## 1. Executive Summary & Payload
{finding}

## 2. Tactical ATT&CK Mapping
* **Defense Evasion (TA0005):** Process Injection (PAGE_EXECUTE_READWRITE anomalies)
* **Persistence (TA0003):** Registry Hive / User Temp Directory 
* **Execution (TA0002):** Malicious DLL Sideloading
"""
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)
        
    hasher = hashlib.sha256()
    with open(report_path, "rb") as f:
        hasher.update(f.read())
    doc_hash = hasher.hexdigest()
    
    ExecutionLogger.log("ORCHESTRATOR", f"Report forged at: {report_path}", "SUCCESS")
    ExecutionLogger.log("ORCHESTRATOR", f"Document Integrity Hash (SHA-256): {doc_hash}")
    
    with open(report_path, "a", encoding="utf-8") as f:
        f.write(f"- **Document SHA-256:** {doc_hash}\n")

def get_disk_image() -> str:
    context_path = os.path.join(CACHE_DIR, "context.json")
    if os.path.exists(context_path):
        try:
            with open(context_path, "r") as f:
                return json.load(f).get("Evidence_Files", {}).get("Disk_Image", "")
        except: pass
    return ""

def get_memory_image() -> str:
    context_path = os.path.join(CACHE_DIR, "context.json")
    if os.path.exists(context_path):
        try:
            with open(context_path, "r") as f:
                return json.load(f).get("Evidence_Files", {}).get("Memory", "")
        except: pass
    return ""

def run_fsm_loop(chat_session):
    ExecutionLogger.log("ORCHESTRATOR", "Initializing Deterministic State Machine...")
    
    ctx = get_evidence_context()
    ExecutionLogger.log("ORCHESTRATOR", "Evidence Context Acquired.")
    
    malfind_out = query_json_cache("malfind", "PAGE_EXECUTE_READWRITE")
    ExecutionLogger.log("ORCHESTRATOR", f"Malfind query executed for RWX anomalies.")
    
    pids = []
    malfind_path = os.path.join(CACHE_DIR, "malfind.json")
    if os.path.exists(malfind_path):
        try:
            with open(malfind_path, "r") as f:
                data = json.load(f)
                pids = list({str(e["PID"]) for e in data if e.get("Protection") == "PAGE_EXECUTE_READWRITE"})
        except: pass
        
    if not pids:
        ExecutionLogger.log("ORCHESTRATOR", "No RWX anomalies found. Investigation Complete.", "SUCCESS")
        return
        
    ExecutionLogger.log("ORCHESTRATOR", f"Proceeding to iterate {len(pids)} PIDs deterministically.")
    
    for pid in sorted(pids, key=int):
        ExecutionLogger.log("ORCHESTRATOR", f"EVALUATING PID: {pid}", "WARN")
        
        pstree_ev = query_json_cache("pstree", pid)
        cmdline_ev = query_json_cache("cmdline", pid)
        reg_map_ev = query_json_cache("registry_map", pid)
        
        hive_evidence = "[*] No registry targets found."
        try:
            reg_dict = json.loads(reg_map_ev)
            targets = []
            if "SYSTEM" in reg_dict and reg_dict["SYSTEM"]: targets.append(reg_dict["SYSTEM"][0].get("inode"))
            if "NTUSER" in reg_dict and reg_dict["NTUSER"]: targets.append(reg_dict["NTUSER"][0].get("inode"))
            
            disk_img = get_disk_image()
            hive_carves = []
            for inode in set(targets):
                if inode:
                    res = extract_and_carve_hive(inode, disk_img)
                    hive_carves.append(f"Inode {inode}: {res}")
            if hive_carves:
                hive_evidence = "\n".join(hive_carves)
        except Exception as e: 
            ExecutionLogger.log("ORCHESTRATOR", f"Registry carve preparation failed: {e}", "WARN")
        
        netscan_ev = query_json_cache("netscan", pid)
        
        prompt = f"""
        Analyze the following evidence for PID {pid}:
        
        PSTREE:
        {pstree_ev[:1000]}
        
        CMDLINE:
        {cmdline_ev[:1000]}
        
        REGISTRY CARVE:
        {hive_evidence[:2000]}
        
        NETSCAN:
        {netscan_ev[:1000]}
        """
        
        eval_result = safe_api_call(chat_session, prompt)
        ExecutionLogger.log("ORCHESTRATOR", f"LLM Verdict for PID {pid}: {eval_result.verdict.upper()}")
        ExecutionLogger.log("ORCHESTRATOR", f"LLM Reasoning: {eval_result.reasoning}")
        
        if eval_result.request_memory_carve:
            ExecutionLogger.log("ORCHESTRATOR", "LLM requested dynamic memory carve for NETWORK indicators.")
            mem_img = get_memory_image()
            carve_ev = carve_memory_strings("NETWORK", mem_img, pid)
            ExecutionLogger.log("ORCHESTRATOR", "Dynamic memory carve completed.")
            if "NULL HYPOTHESIS" not in carve_ev:
                ExecutionLogger.log("ORCHESTRATOR", "Network indicators found in memory. Overriding verdict to MALICIOUS.", "WARN")
                eval_result.verdict = "malicious"
        
        if eval_result.verdict == "malicious":
            ExecutionLogger.log("ORCHESTRATOR", f"THREAT ISOLATED: PID {pid} is MALICIOUS.", "ERROR")
            finding = f"PID {pid} | Reason: {eval_result.reasoning}"
            generate_mitre_report(finding)
            update_ioc_store(finding)
            return 
            
    ExecutionLogger.log("ORCHESTRATOR", "All suspect PIDs analyzed. Null Hypothesis stands. No threats confirmed.", "SUCCESS")

def verify_and_trigger_cache():
    context_path = os.path.join(CACHE_DIR, "context.json")
    if not os.path.exists(context_path):
        ExecutionLogger.log("ORCHESTRATOR", f"Cache context missing at: {context_path}", "ERROR")
        ExecutionLogger.log("ORCHESTRATOR", "Please run extractor.py manually to build cache.", "WARN")
        sys.exit(1)
    ExecutionLogger.log("ORCHESTRATOR", "Cache context verified.", "SUCCESS")

def main():
    print(f"\033[96m[ PROJECT FIND EVIL - V0.1.6 (TRANSPARENT MODE) ]\033[0m")
    print("------------------------------------------------------------")
    
    verify_and_trigger_cache()
    
    try:
        with open(LOG_PATH, "w") as f:
            f.write("=== PROJECT FIND EVIL: HARDENED LOG ===\n\n")
    except Exception as e:
        ExecutionLogger.log("ORCHESTRATOR", f"Failed to initialize thoughts.txt: {e}", "ERROR")
        sys.exit(1)
        
    agent_system = FindEvilAgent()
    chat_session = agent_system.create_session()

    print("\n\033[96m[*] Ready. Type 'investigate' to initiate Hardened Python FSM loop.\033[0m")

    while True:
        try:
            user_input = input("\n[Investigator] > ")
            if user_input.lower() in ['exit', 'quit']: break
            if not user_input.strip(): continue

            if user_input.lower() == 'investigate':
                run_fsm_loop(chat_session)
            else:
                ExecutionLogger.log("CLI", "Command not recognized. Type 'investigate' or 'exit'.", "WARN")

        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    main()
