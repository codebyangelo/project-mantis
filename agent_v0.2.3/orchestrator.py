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
    timestamp = datetime.datetime.now().astimezone().isoformat()
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] | {phase} | {component}\n{details}\n{'-'*80}\n")

def safe_api_call(chat_session, prompt: str, max_retries: int = 3) -> AgentCommand:
    time.sleep(4)  # Give the API 4 seconds to breathe (RPM limit pacing)
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
    return AgentCommand(verdict="benign", confidence_score=0.0, severity_level="None", reasoning="API Exhaustion Fallback", request_memory_carve=False, mitre_techniques=[])

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

def generate_mitre_report(results: list):
    ExecutionLogger.log("ORCHESTRATOR", "Initiating Exhaustive MITRE ATT&CK Report Generation...")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(BASE_DIR, f"PFE_MITRE_Report_{timestamp}.md")
    
    total_pids = len(results)
    isolated_threats = [r for r in results if r['result'].verdict == "malicious"]
    suspicious_pids = [r for r in results if r['result'].verdict == "suspicious"]
    cleared_pids = [r for r in results if r['result'].verdict == "benign"]
    
    report_content = f"""# Project Find Evil (v0.2.3) - Autonomous DFIR Report
**Date:** {datetime.datetime.now().astimezone().isoformat()}
**Engine Mode:** Exhaustive Python State Machine (Transparent Logging)

## 1. Executive Summary
* **Total PIDs Evaluated:** {total_pids}
* **Threats Isolated:** {len(isolated_threats)}
* **Suspicious (Human Review Required):** {len(suspicious_pids)}
* **Cleared Entities:** {len(cleared_pids)}

---

## 2. Isolated Threats (Malicious)
"""
    if isolated_threats:
        for item in isolated_threats:
            res = item['result']
            report_content += f"### PID {item['pid']}\n"
            report_content += f"- **Severity:** {res.severity_level}\n"
            report_content += f"- **Confidence Score:** {res.confidence_score:.2f}\n"
            report_content += f"- **Reasoning:** {res.reasoning}\n\n"
    else:
        report_content += "*No threats detected.*\n\n"

    report_content += "## 3. Suspicious / Needs Human Review\n"
    if suspicious_pids:
        for item in suspicious_pids:
            res = item['result']
            report_content += f"### PID {item['pid']}\n"
            report_content += f"- **Severity:** {res.severity_level}\n"
            report_content += f"- **Confidence Score:** {res.confidence_score:.2f} (Low Confidence Benign)\n"
            report_content += f"- **Reasoning:** {res.reasoning}\n\n"
    else:
        report_content += "*No suspicious entities requiring review.*\n\n"

    report_content += "## 4. Cleared Entities (Benign)\n"
    if cleared_pids:
        for item in cleared_pids:
            res = item['result']
            report_content += f"- **PID {item['pid']}** | Confidence: {res.confidence_score:.2f} | Reason: {res.reasoning}\n"
    else:
        report_content += "*No entities fully cleared.*\n\n"

    report_content += """
---
## 5. Tactical ATT&CK Mapping
"""
    if isolated_threats:
        unique_techs = set()
        for item in isolated_threats:
            res = item['result']
            if hasattr(res, 'mitre_techniques') and res.mitre_techniques:
                unique_techs.update(res.mitre_techniques)
        
        if not unique_techs:
            report_content += "* No specific MITRE ATT&CK techniques identified by the analyzer.\n"
        else:
            MITRE_NAMES = {
                "T1055": "Process Injection",
                "T1036": "Masquerading",
                "T1071": "Application Layer Protocol"
            }
            for t in sorted(unique_techs):
                name = MITRE_NAMES.get(t, "Unknown Technique")
                report_content += f"* **{name} ({t})**\n"
    else:
        report_content += "* No threats identified, therefore no techniques mapped.\n"

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)
        
    hasher = hashlib.sha256()
    with open(report_path, "rb") as f:
        hasher.update(f.read())
    doc_hash = hasher.hexdigest()
    
    ExecutionLogger.log("ORCHESTRATOR", f"Report forged at: {report_path}", "SUCCESS")
    ExecutionLogger.log("ORCHESTRATOR", f"Document Integrity Hash (SHA-256): {doc_hash}")
    
    with open(report_path, "a", encoding="utf-8") as f:
        f.write(f"\n- **Document SHA-256:** {doc_hash}\n")

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
    ExecutionLogger.log("ORCHESTRATOR", "Initializing Exhaustive Deterministic State Machine...")
    
    ctx = get_evidence_context()
    ExecutionLogger.log("ORCHESTRATOR", "Evidence Context Acquired.")
    
    from sieve import get_suspect_pids
    pids_int, pid_table = get_suspect_pids(api_budget=30)
    pids = [str(p) for p in pids_int]
    
    if not pids:
        ExecutionLogger.log("ORCHESTRATOR", "No anomalies crossed the heuristic threshold. Investigation Complete.", "SUCCESS")
        return
        
    ExecutionLogger.log("ORCHESTRATOR", f"Proceeding to iterate {len(pids)} highly-suspect PIDs deterministically.")
    
    investigation_results = []
    
    for pid in sorted(pids, key=int):
        ExecutionLogger.log("ORCHESTRATOR", f"EVALUATING PID: {pid}", "WARN")
        
        data = pid_table.get(int(pid), {})
        signals_str = ", ".join(data.get("signals", [])) if data.get("signals") else "None"
        
        prompt = f"""
        Analyze the following evidence for PID {pid}:
        
        HEURISTIC SIGNALS (Score {data.get('score', 0)}/250):
        {signals_str}
        
        PSTREE:
        {json.dumps(data.get('pstree', {}), indent=2)[:1000]}
        
        CMDLINE:
        {json.dumps(data.get('cmdline', {}), indent=2)[:1000]}
        
        NETSCAN:
        {json.dumps(data.get('netscan', []), indent=2)[:1000]}
        
        MALFIND:
        {json.dumps(data.get('malfind', []), indent=2)[:1000]}
        
        Note: Focus primarily on the Heuristic Signals and the provided context. Does this confirm a threat?
        """
        
        eval_result = safe_api_call(chat_session, prompt)
        ExecutionLogger.log("ORCHESTRATOR", f"LLM Verdict for PID {pid}: {eval_result.verdict.upper()} (Confidence: {eval_result.confidence_score:.2f})")
        ExecutionLogger.log("ORCHESTRATOR", f"LLM Reasoning: {eval_result.reasoning}")
        
        if eval_result.request_memory_carve:
            ExecutionLogger.log("ORCHESTRATOR", "LLM requested dynamic memory carve for NETWORK indicators.")
            mem_img = get_memory_image()
            carve_ev = carve_memory_strings("NETWORK", mem_img, pid)
            ExecutionLogger.log("ORCHESTRATOR", "Dynamic memory carve completed.")
            
            if "NULL HYPOTHESIS" in carve_ev:
                ExecutionLogger.log("ORCHESTRATOR", "No memory indicators found. Retaining initial LLM verdict.", "WARN")
            else:
                ExecutionLogger.log("ORCHESTRATOR", "Feeding memory carve results back to LLM for final verdict.")
                followup_prompt = f"""
                FOLLOW-UP MEMORY INDICATORS FOR PID {pid}:
                {carve_ev[:3000]}
                
                Re-evaluate the PID. Consider BOTH these new memory strings AND the previous evidence. Do these new strings confirm or deny your initial suspicion?
                """
                eval_result = safe_api_call(chat_session, followup_prompt)
                ExecutionLogger.log("ORCHESTRATOR", f"Final LLM Verdict for PID {pid}: {eval_result.verdict.upper()} (Confidence: {eval_result.confidence_score:.2f})")
                
        # Reclassify low confidence benign as suspicious
        if eval_result.verdict == "benign" and eval_result.confidence_score < 0.6:
            ExecutionLogger.log("ORCHESTRATOR", f"Low confidence benign result ({eval_result.confidence_score:.2f}). Flagging as SUSPICIOUS.", "WARN")
            eval_result.verdict = "suspicious"
            eval_result.severity_level = "Review Required"
        
        if eval_result.verdict == "malicious":
            ExecutionLogger.log("ORCHESTRATOR", f"THREAT ISOLATED: PID {pid} is MALICIOUS.", "CRITICAL")
            finding = f"PID {pid} | Severity: {eval_result.severity_level} | Reason: {eval_result.reasoning}"
            update_ioc_store(finding)
            
        investigation_results.append({"pid": pid, "result": eval_result})
            
    ExecutionLogger.log("ORCHESTRATOR", "All suspect PIDs analyzed. Processing final exhaustive report.", "SUCCESS")
    generate_mitre_report(investigation_results)

def verify_and_trigger_cache():
    context_path = os.path.join(CACHE_DIR, "context.json")
    if not os.path.exists(context_path):
        ExecutionLogger.log("ORCHESTRATOR", f"Cache context missing at: {context_path}", "ERROR")
        ExecutionLogger.log("ORCHESTRATOR", "Please run extractor.py manually to build cache.", "WARN")
        sys.exit(1)
    ExecutionLogger.log("ORCHESTRATOR", "Cache context verified.", "SUCCESS")

def main():
    print(f"\033[96m[ PROJECT FIND EVIL - V0.2.3 (EXHAUSTIVE MODE) ]\033[0m")
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

    print("\n\033[96m[*] Ready. Type 'investigate' to initiate Exhaustive FSM loop.\033[0m")

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
