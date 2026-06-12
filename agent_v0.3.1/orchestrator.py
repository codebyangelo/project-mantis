import sys
import os
import json
import time
import datetime
import hashlib
import subprocess
import argparse
from pydantic import ValidationError

from agent import MantisAgent, MantisEvaluation
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

def safe_api_call(chat_session, prompt: str, max_retries: int = 3) -> MantisEvaluation:
    time.sleep(4)  # Give the API 4 seconds to breathe (RPM limit pacing)
    write_thought_ledger("TX_OUTBOUND", "LLM_EVALUATION", prompt)
    ExecutionLogger.log("ORCHESTRATOR", "Querying Gemini 3.1 Flash-Lite Classifier (Pydantic enforced)...")
    for attempt in range(max_retries):
        try:
            response = chat_session.send_message(prompt)
            write_thought_ledger("RX_INBOUND", "LLM_RAW_OUTPUT", response.text)
            parsed = MantisEvaluation.model_validate_json(response.text)
            ExecutionLogger.log("ORCHESTRATOR", "Received and successfully validated LLM JSON response.", "SUCCESS")
            return parsed
        except Exception as e:
            delay = 2 * (attempt + 1)
            ExecutionLogger.log("ORCHESTRATOR", f"API Error/Validation Failed: {e}. Retrying in {delay}s...", "WARN")
            time.sleep(delay)
            
    ExecutionLogger.log("ORCHESTRATOR", "API Exhaustion. Raising Exception.", "ERROR")
    raise Exception("API Exhaustion Fallback")

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

def generate_mitre_report(results: list, agent_system=None):
    ExecutionLogger.log("ORCHESTRATOR", "Initiating Exhaustive MITRE ATT&CK Report Generation...")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(BASE_DIR, f"PFE_MITRE_Report_{timestamp}.md")
    
    total_pids = len(results)
    isolated_threats = [r for r in results if r['result'].verdict.classification.upper() == "MALICIOUS"]
    suspicious_pids = [r for r in results if r['result'].verdict.classification.upper() == "SUSPICIOUS"]
    cleared_pids = [r for r in results if r['result'].verdict.classification.upper() == "BENIGN"]
    
    report_content = f"""# Project Mantis (v0.3.0) - Autonomous DFIR Report
**Date:** {datetime.datetime.now().astimezone().isoformat()}
**Engine Mode:** Playbook Deterministic Engine (Zero Blackbox)

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
            report_content += f"### Entity: {item['pid']}\n"
            report_content += f"- **Verdict:** {res.verdict.classification} ({res.verdict.confidence} Confidence)\n"
            report_content += f"- **Reasoning:** {res.verdict.confidence_reasoning}\n"
            report_content += f"- **Playbook Rule Applied:** {res.rule_applied.rule_id} ({res.rule_applied.rule_name})\n"
            report_content += f"- **Audit Trail Derivation:** {res.audit_trail.verdict_derivation}\n\n"
    else:
        report_content += "*No threats detected.*\n\n"

    report_content += "## 3. Suspicious / Needs Human Review\n"
    if suspicious_pids:
        for item in suspicious_pids:
            res = item['result']
            report_content += f"### Entity: {item['pid']}\n"
            report_content += f"- **Verdict:** {res.verdict.classification} ({res.verdict.confidence} Confidence)\n"
            report_content += f"- **Reasoning:** {res.verdict.confidence_reasoning}\n"
            report_content += f"- **Playbook Rule Applied:** {res.rule_applied.rule_id} ({res.rule_applied.rule_name})\n"
            report_content += f"- **Audit Trail Derivation:** {res.audit_trail.verdict_derivation}\n\n"
    else:
        report_content += "*No suspicious entities requiring review.*\n\n"

    report_content += "## 4. Cleared Entities (Benign)\n"
    if cleared_pids:
        for item in cleared_pids:
            res = item['result']
            report_content += f"- **Entity {item['pid']}** | Confidence: {res.verdict.confidence} | Reason: {res.verdict.confidence_reasoning}\n"
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
            if hasattr(res, 'mitre_mapping') and res.mitre_mapping:
                unique_techs.add(res.mitre_mapping.technique)
        if not unique_techs:
            report_content += "* No specific MITRE ATT&CK techniques identified by the analyzer.\n"
        else:
            MITRE_NAMES = {
                "T1055": "Process Injection",
                "T1036": "Masquerading",
                "T1071": "Application Layer Protocol",
                "T1048": "Exfiltration Over Alternative Protocol",
                "T1119": "Automated Collection",
                "T1547": "Boot or Logon Autostart Execution",
                "T1059": "Command and Scripting Interpreter",
                "T1204": "User Execution",
                "T1485": "Data Destruction",
                "T1070": "Indicator Removal",
                "T1136": "Create Account"
            }
            for t in sorted(unique_techs):
                name = MITRE_NAMES.get(t, "Unknown Technique")
                report_content += f"* **{name} ({t})**\n"
    else:
        report_content += "* No threats identified, therefore no techniques mapped.\n"

    if agent_system and isolated_threats:
        try:
            synthesis = agent_system.synthesize_investigation(isolated_threats)
            report_content += "\n---\n## 6. Executive Incident Synthesis\n"
            report_content += f"**Who Attributed:** {synthesis.who_attributed}\n\n"
            report_content += f"**What Happened:** {synthesis.what_happened}\n\n"
            report_content += f"**Where Transferred:** {synthesis.where_transferred}\n\n"
            report_content += f"**How Stolen:** {synthesis.how_stolen}\n\n"
            report_content += f"**When Occurred:** {synthesis.when_occurred}\n\n"
            report_content += f"**Incident Narrative:**\n{synthesis.narrative}\n\n"
            
            report_content += "---\n## 7. NIST SP 800-61r2 Alignment & Containment Recommendations\n"
            report_content += "**Incident Lifecycle Phase:** Detection & Analysis -> Transitioning to Containment, Eradication, & Recovery\n\n"
            
            report_content += "### Immediate Containment Actions\n"
            for rec in synthesis.containment_recommendations:
                report_content += f"* {rec}\n"
                
            report_content += "\n### Eradication & Recovery\n"
            for rec in synthesis.eradication_recommendations:
                report_content += f"* {rec}\n"
                
            report_content += "\n### Post-Incident Activity\n"
            for rec in synthesis.post_incident_recommendations:
                report_content += f"* {rec}\n"
                
            ExecutionLogger.log("ORCHESTRATOR", "Executive Synthesis and Dynamic Recommendations appended successfully.", "SUCCESS")
        except Exception as e:
            ExecutionLogger.log("ORCHESTRATOR", f"Synthesis failed: {e}", "ERROR")

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

def run_fsm_loop(chat_session, agent_system=None):
    ExecutionLogger.log("ORCHESTRATOR", "Initializing Exhaustive Deterministic State Machine...")
    
    ctx = get_evidence_context()
    ExecutionLogger.log("ORCHESTRATOR", "Evidence Context Acquired.")
    
    from sieve import get_suspect_entities
    entities = get_suspect_entities(api_budget=30)
    
    if not entities:
        ExecutionLogger.log("ORCHESTRATOR", "No anomalies crossed the heuristic threshold. Investigation Complete.", "SUCCESS")
        return
        
    ExecutionLogger.log("ORCHESTRATOR", f"Proceeding to iterate {len(entities)} highly-suspect Entities deterministically.")
    
    playbook_content = "{}"
    playbook_path = os.path.join(BASE_DIR, "dfir_playbook.json")
    if os.path.exists(playbook_path):
        with open(playbook_path, "r") as f:
            playbook_content = f.read()

    environmental_context = {
        "known_admins": ["SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"],
        "known_good_hashes": [],
        "baseline_processes": ["MsMpEng.exe", "SearchApp.exe", "LockApp.exe", "smartscreen.exe", "lsass.exe", "svchost.exe", "explorer.exe", "cmd.exe"]
    }

    investigation_results = []
    
    for ent in entities:
        ent_id = ent["id"]
        ent_type = ent["type"]
        ExecutionLogger.log("ORCHESTRATOR", f"EVALUATING {ent_type.upper()}: {ent['label']}", "WARN")
        
        prompt = f"""
        Analyze the following ARTIFACT against the PLAYBOOK rules.
        
        ENVIRONMENTAL CONTEXT:
        {json.dumps(environmental_context, indent=2)}
        
        PLAYBOOK:
        {playbook_content}
        
        ARTIFACT ({ent_type.upper()}):
        {json.dumps(ent['evidence'], indent=2)[:3000]}
        """
        
        try:
            eval_result = safe_api_call(chat_session, prompt)
        except Exception:
            continue
            
        ExecutionLogger.log("ORCHESTRATOR", f"LLM Verdict for {ent_type} '{ent['label']}': {eval_result.verdict.classification.upper()} (Confidence: {eval_result.verdict.confidence})")
        ExecutionLogger.log("ORCHESTRATOR", f"LLM Reasoning: {eval_result.verdict.confidence_reasoning}")
        ExecutionLogger.log("ORCHESTRATOR", f"Rule Applied: {eval_result.rule_applied.rule_id}")
        
        if getattr(eval_result, "request_deep_carve", False):
            ExecutionLogger.log("ORCHESTRATOR", "LLM requested dynamic deep carve for indicators.")
            
            carve_ev = "[!] Unsupported entity type for carving."
            if ent_type == "process":
                mem_img = get_memory_image()
                carve_ev = carve_memory_strings("NETWORK", mem_img, ent_id)
            elif ent_type == "registry_hive":
                disk_img_name = ent["evidence"].get("disk_image")
                if disk_img_name:
                    # Resolve real image path
                    cache_context_path = os.path.join(CACHE_DIR, "context.json")
                    real_disk_path = ""
                    if os.path.exists(cache_context_path):
                        with open(cache_context_path, "r") as f:
                            ctx_data = json.load(f)
                            for d_path in ctx_data.get("Evidence_Files", {}).get("Disk_Images", []):
                                if disk_img_name in os.path.basename(d_path):
                                    real_disk_path = d_path
                                    break
                    if real_disk_path:
                        carve_ev = extract_and_carve_hive(ent_id, real_disk_path)
                    else:
                        carve_ev = f"[!] Could not map '{disk_img_name}' to physical disk path for carve."
                else:
                    carve_ev = "[!] Missing disk_image reference in evidence."
            
            ExecutionLogger.log("ORCHESTRATOR", "Dynamic deep carve completed.")
            
            ExecutionLogger.log("ORCHESTRATOR", "Feeding carve results back to LLM for final verdict.")
            followup_prompt = f"""
            FOLLOW-UP CARVE INDICATORS FOR {ent_type.upper()} '{ent['label']}':
            {carve_ev[:3000]}
            
            Re-evaluate the entity. Consider BOTH these new carved indicators AND the previous evidence. Do these confirm or deny your initial suspicion? Follow the same JSON format.
            """
            try:
                eval_result = safe_api_call(chat_session, followup_prompt)
                ExecutionLogger.log("ORCHESTRATOR", f"Final LLM Verdict for {ent_type} '{ent['label']}': {eval_result.verdict.classification.upper()} (Confidence: {eval_result.verdict.confidence})")
            except Exception:
                pass
                
        if eval_result.verdict.classification.upper() == "MALICIOUS":
            ExecutionLogger.log("ORCHESTRATOR", f"THREAT ISOLATED: {ent_type} '{ent['label']}' is MALICIOUS.", "CRITICAL")
            finding = f"Entity [{ent_type}] {ent['label']} | Verdict: MALICIOUS | Reason: {eval_result.verdict.confidence_reasoning}"
            update_ioc_store(finding)
            
        investigation_results.append({"pid": ent["label"], "result": eval_result, "evidence": ent.get("evidence", {})})
            
    ExecutionLogger.log("ORCHESTRATOR", "All suspect entities analyzed. Processing final exhaustive report.", "SUCCESS")
    generate_mitre_report(investigation_results, agent_system=agent_system)

def verify_and_trigger_cache():
    context_path = os.path.join(CACHE_DIR, "context.json")
    if not os.path.exists(context_path):
        ExecutionLogger.log("ORCHESTRATOR", f"Cache context missing at: {context_path}", "ERROR")
        ExecutionLogger.log("ORCHESTRATOR", "Please run extractor.py manually to build cache.", "WARN")
        sys.exit(1)
    ExecutionLogger.log("ORCHESTRATOR", "Cache context verified.", "SUCCESS")

def main():
    parser = argparse.ArgumentParser(description="Project Mantis Orchestrator")
    parser.add_argument("--deep", action="store_true", help="Run with deep forensics mode (EVTX, Registry, etc)")
    args = parser.parse_args()

    mode_str = "EXHAUSTIVE MODE + DEEP FORENSICS" if args.deep else "EXHAUSTIVE MODE"
    print(f"\033[96m[ PROJECT MANTIS - V0.3.0 ({mode_str}) ]\033[0m")
    print("------------------------------------------------------------")
    
    verify_and_trigger_cache()
    
    try:
        with open(LOG_PATH, "w") as f:
            f.write("=== PROJECT MANTIS: HARDENED LOG ===\n\n")
    except Exception as e:
        ExecutionLogger.log("ORCHESTRATOR", f"Failed to initialize thoughts.txt: {e}", "ERROR")
        sys.exit(1)
        
    agent_system = MantisAgent()
    chat_session = agent_system.create_session()

    print("\n\033[96m[*] Ready. Type 'investigate' to initiate Exhaustive FSM loop.\033[0m")

    while True:
        try:
            user_input = input("\n[Investigator] > ")
            if user_input.lower() in ['exit', 'quit']: break
            if not user_input.strip(): continue

            if user_input.lower() == 'investigate':
                run_fsm_loop(chat_session, agent_system)
            else:
                ExecutionLogger.log("CLI", "Command not recognized. Type 'investigate' or 'exit'.", "WARN")

        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    main()
