import sys
import time
from mcp_server import execute_deterministic_pipeline
from agent import FindEvilAgent

# --- AGENT TOOLS ---

def record_cognitive_process(thought_process: str) -> str:
    print("\n" + "-"*60)
    print("[BLOCK] Cognitive State Logging")
    try:
        with open("thoughts.txt", "a", encoding='utf-8') as f:
            f.write(f"[THOUGHT] {thought_process}\n")
        print(f"    └── \"{thought_process[:60]}...\"")
        print("[STATUS] [SUCCESS] Thought committed to disk.")
        print("-" * 60)
        return "Thought logged successfully. Proceed."
    except Exception as e:
        return f"Error logging thought: {str(e)}"

# --- CLI INTERFACE ---

def main():
    print(f"\n[{'='*60}]")
    print("[ PROJECT FIND EVIL - NATIVE ORCHESTRATOR V0.0.5 ]")
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
            tools_list=[record_cognitive_process, execute_deterministic_pipeline]
        )
    except ValueError as e:
        print(e)
        sys.exit(1)

    print("[*] Command prompt ready. Type 'investigate' to trigger the autonomous pipeline.")
    print("=" * 62)

    while True:
        try:
            user_input = input("\n[Investigator] > ")

            if user_input.lower() in ['exit', 'quit']:
                print("\n[*] Terminating session.")
                break

            if not user_input.strip():
                continue

            # Intercept 'investigate' to provide a clean prompt without railroading
            if user_input.lower() == 'investigate':
                system_prompt = "Initiate triage. Execute the deterministic pipeline to retrieve system state, analyze the telemetry according to your strict heuristics, and report the findings."
                print("\n[Agent is executing the deterministic pipeline...]")
                response = chat_session.send_message(system_prompt)
            else:
                print("\n[Agent is processing query...]")
                response = chat_session.send_message(user_input)

            print(f"\n[{'='*60}]")
            print("[ AGENT PAYLOAD ]")
            print(f"[{'='*60}]")
            print(response.text)

        except KeyboardInterrupt:
            print("\n\n[*] Manual interrupt detected. Terminating session.")
            break
        except Exception as e:
            print(f"\n[!] Orchestrator Error: {str(e)}")

if __name__ == "__main__":
    main()
