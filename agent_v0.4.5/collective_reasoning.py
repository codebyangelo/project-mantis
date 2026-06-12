import os
import time
import sys
from openai import OpenAI

def safe_api_call(client_func, max_retries=3):
    time.sleep(4)  # 4 second delay pacing
    for attempt in range(max_retries):
        try:
            return client_func()
        except Exception as e:
            delay = 2 * (attempt + 1)
            print(f"[-] API Error: {e}. Retrying in {delay}s...")
            time.sleep(delay)
    print("[-] API Exhausted. Fallback triggered.")
    return "[ERROR] LLM Failed to respond."

def query_groq(prompt, role_prompt):
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key: return "GROQ_API_KEY missing in environment."
    client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")
    def _call():
        resp = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": role_prompt},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2
        )
        return resp.choices[0].message.content
    return safe_api_call(_call)

def query_cerebras(prompt, role_prompt):
    api_key = os.environ.get("CEREBRAS_API_KEY")
    if not api_key: return "CEREBRAS_API_KEY missing in environment."
    client = OpenAI(api_key=api_key, base_url="https://api.cerebras.ai/v1")
    def _call():
        resp = client.chat.completions.create(
            model="gpt-oss-120b",
            messages=[
                {"role": "system", "content": role_prompt},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2
        )
        return resp.choices[0].message.content
    return safe_api_call(_call)

def query_nvidia(prompt, role_prompt):
    api_key = os.environ.get("NVIDIA_API_KEY")
    if not api_key: return "NVIDIA_API_KEY missing in environment."
    client = OpenAI(api_key=api_key, base_url="https://integrate.api.nvidia.com/v1")
    def _call():
        resp = client.chat.completions.create(
            model="meta/llama-3.1-8b-instruct",
            messages=[
                {"role": "system", "content": role_prompt},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2
        )
        return resp.choices[0].message.content
    return safe_api_call(_call)

def delegate_problem(problem_statement: str):
    print(f"[*] Delegating problem to collective counsel...\n")
    
    roles = {
        "Architect (Groq Llama3-70B)": {
            "func": query_groq,
            "system": "You are a System Architect. Focus on structural, architectural, and logic flow flaws. Provide high-level recommendations to solve the user's problem."
        },
        "Red Teamer (Cerebras Llama3.1-70B)": {
            "func": query_cerebras,
            "system": "You are an Adversarial Red Teamer. Focus on how the problem could be exploited, bypassed, or jailbroken. Provide robust constraints and strict instructions."
        },
        "Implementer (NVIDIA Llama3.1-405B)": {
            "func": query_nvidia,
            "system": "You are a Pragmatic Code Implementer. Focus on concrete Python code, regex, and exact execution logic to solve the user's problem."
        }
    }
    
    results = {}
    for role_name, config in roles.items():
        print(f"[*] Querying {role_name}...")
        response = config["func"](problem_statement, config["system"])
        results[role_name] = response
        print(f"[+] {role_name} responded.\n")
        
    print("="*80)
    print("COLLECTIVE REASONING OUTPUT")
    print("="*80)
    for role_name, response in results.items():
        print(f"\n--- {role_name} ---\n{response}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 collective_reasoning.py \"<problem statement>\"")
        sys.exit(1)
    
    problem = sys.argv[1]
    
    # If the argument is a file path, read its contents
    if os.path.isfile(problem):
        print(f"[*] Reading problem statement from file: {problem}")
        with open(problem, "r") as f:
            problem = f.read()
            
    delegate_problem(problem)
