import sys
from mcp_server import read_evidence_cache, extract_and_hash_inode
from agent import FindEvilAgent

def record_thought(thought: str) -> str:
    print(f"\n[THOUGHT] {thought}")
    return "Logged."

def main():
    print("[ PROJECT FIND EVIL - V0.0.6 DECOUPLED RAG ]")
    
    agent_system = FindEvilAgent()
    chat_session = agent_system.create_session(
        tools_list=[record_thought, read_evidence_cache, extract_and_hash_inode]
    )

    print("[*] Ready. Type 'investigate' to trigger autonomous analysis of the cache.")
    
    while True:
        try:
            user_input = input("\n[Investigator] > ")
            if user_input.lower() in ['exit', 'quit']: break
            if not user_input.strip(): continue

            print("\n[Agent processing...]")
            response = chat_session.send_message(user_input)
            print(f"\n[ AGENT PAYLOAD ]\n{response.text}")

        except KeyboardInterrupt: break
        except Exception as e: print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
