#!/usr/bin/env python3
# orchestrator.py
import sys
import os
import time
from mcp_server import execute_live_mcp_restricted
from agent import FindEvilAgent

# --- AGENT TOOLS ---

def record_cognitive_process(thought_process: str) -> str:
    print("\n" + "-"*60)
    print("[BLOCK] Cognitive State Logging")
    print("[ACTION] Writing agent hypothesis and intended action to 'thoughts.txt'.")
    print("[REASON] Enforcing ReAct loop transparency for auditable grading.")
    
    try:
        with open("thoughts.txt", "a", encoding='utf-8') as f:
            f.write(f"[THOUGHT] {thought_process}\n")
        print(f"    └── \"{thought_process[:60]}...\"")
        print("[STATUS] [SUCCESS] Thought committed to disk.")
        time.sleep(5)
        print("-" * 60)
        return "Thought logged successfully. Proceed with your intended action."
    except Exception as e:
        print(f"[STATUS] [FAILED] File I/O Error: {str(e)}")
        time.sleep(5)
        print("-" * 60)
        return f"Error logging thought: {str(e)}"

def query_forensic_evidence(plugin_name: str, search_term: str = "") -> str:
    """
    Retrieves the forensic evidence for a specific Volatility 3 plugin.
    
    Args:
        plugin_name: The target plugin (e.g., 'windows.malfind', 'windows.pstree', 'windows.netscan').
        search_term: (Optional) A specific PID or string to filter the results. HIGHLY RECOMMENDED for large files.
    """
    print("\n" + "-"*60)
    print(f"[BLOCK] Forensic Evidence Retrieval: {plugin_name}")
    
    if search_term:
        print(f"[ACTION] Executing targeted grep-style search for: '{search_term}'")
    else:
        print(f"[ACTION] Attempting bulk cache load...")
        
    print(f"[REASON] Bypassing memory I/O bottleneck while protecting LLM token context limits.")
    
    file_map = {
        'windows.malfind': 'windows_malfind_manual_verify.txt',
        'windows.pstree': 'windows_pstree_manual_verify.txt',
        'windows.netscan': 'windows_netscan_manual_verify.txt'
    }
    
    target_file = file_map.get(plugin_name)
    
    if not target_file or not os.path.exists(target_file):
        print(f"[STATUS] [FAILED] Cache file not found on disk.")
        time.sleep(5)
        print("-" * 60)
        return f"Error: Cache file for {plugin_name} not found."
        
    try:
        # [TOKEN DEFENSE SYSTEM]
        # Prevent the LLM from blowing out its context window with the 1.1MB pstree
        if plugin_name in ['windows.pstree', 'windows.netscan'] and not search_term:
            print("[STATUS] [FAILED] API Defense: Blocked bulk ingestion of pstree.")
            time.sleep(5)
            print("-" * 60)
            return f"SYSTEM ERROR: The {plugin_name} file is too large to load into memory at once. You MUST provide a specific 'search_term' (like a suspect PID) to query this file."

        with open(target_file, 'r', encoding='utf-8') as f:
            if search_term:
                # Deterministic Pruning: Only keep lines that match the search term or headers
                matched_lines = [line for line in f if search_term.lower() in line.lower() or "PID" in line.upper()]
                data = "".join(matched_lines)
                if not data.strip():
                    data = f"No results found for '{search_term}' in {plugin_name}."
            else:
                # Safe bulk load for smaller files (like malfind)
                data = f.read()
                
        print(f"[STATUS] [SUCCESS] Extracted {len(data)} bytes of targeted telemetry.")
        print(f"[ACTION] Throttling agent execution for 12 seconds to defend API TPM limits...")
        time.sleep(12)
        print("-" * 60)
        return data
        
    except Exception as e:
        print(f"[STATUS] [FAILED] File Read Error: {str(e)}")
        time.sleep(5)
        print("-" * 60)
        return f"Error reading file: {str(e)}"

def test_live_mcp_connection(plugin_name: str) -> str:
    return execute_live_mcp_restricted(plugin_name)

# --- CLI INTERFACE ---

def main():
    print(f"\n[{'='*60}]")
    print("[ PROJECT FIND EVIL - AUTONOMOUS ORCHESTRATOR V1.5 ]")
    print(f"[{'='*60}]\n")
    
    try:
        with open("thoughts.txt", "w") as f:
            f.write("=== PROJECT FIND EVIL: AGENT COGNITIVE LOG ===\n\n")
    except Exception as e:
        print(f"[!] Failed to initialize thoughts.txt: {e}")
        sys.exit(1)
    
    try:
        agent_system = FindEvilAgent()
        chat_session = agent_system.create_session(
            tools_list=[record_cognitive_process, query_forensic_evidence, test_live_mcp_connection]
        )
    except ValueError as e:
        print(e)
        sys.exit(1)
        
    print("[*] Command prompt ready. Type 'investigate' to begin autonomous triage.")
    print("=" * 62)

    while True:
        try:
            user_input = input("\n[Investigator] > ")
            
            if user_input.lower() in ['exit', 'quit']:
                print("\n[*] Terminating session.")
                break
                
            if not user_input.strip():
                continue

            print("\n[Agent is processing telemetry...]")
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    response = chat_session.send_message(user_input)
                    
                    print(f"\n[{'='*60}]")
                    print("[ FINAL TRIAGE REPORT ]")
                    print(f"[{'='*60}]")
                    print(response.text)
                    break # Success, break out of the retry loop
                    
                except Exception as e:
                    error_msg = str(e)
                    if '503' in error_msg or 'UNAVAILABLE' in error_msg:
                        if attempt < max_retries - 1:
                            print(f"    [!] 503 Server Unavailable. Retrying in 12 seconds... (Attempt {attempt + 1}/{max_retries})")
                            import time
                            time.sleep(12)
                        else:
                            print(f"\n[!] Agent Error: Google API servers remain overloaded after 3 attempts. Please try again later.")
                    else:
                        # If it's a 429 or other error, do not retry. Surface it immediately.
                        raise e
            
        except KeyboardInterrupt:
            print("\n\n[*] Manual interrupt detected. Terminating session.")
            break
        except Exception as e:
            print(f"\n[!] Orchestrator Error: {str(e)}")

if __name__ == "__main__":
    main()
