# mcp_server.py
import subprocess

def execute_live_mcp_restricted(plugin: str) -> str:
    """Executes a live Volatility command but restricts it to --help."""
    print("\n" + "-"*60)
    print(f"[BLOCK] MCP Server Execution: {plugin}")
    print(f"[ACTION] Triggering live OS tool execution restricted to dry-run (-h).")
    print(f"[REASON] Validating live pipeline integrity without inducing I/O choke.")
    
    try:
        result = subprocess.run(
            ['vol', plugin, '-h'],
            capture_output=True, text=True, check=True
        )
        print("[STATUS] [SUCCESS] Tool pipe is active and responsive.")
        print("-" * 60)
        return f"[SYSTEM CONFIRMATION] Tool pipe is active. Help documentation returned:\n{result.stdout[:500]}..."
        
    except subprocess.CalledProcessError as e:
        print(f"[STATUS] [FAILED] Subprocess error detected.")
        print("-" * 60)
        return f"[!] MCP Execution Failed.\nError: {e.stderr}"
    except FileNotFoundError:
        print(f"[STATUS] [FAILED] 'vol' binary not found in environment.")
        print("-" * 60)
        return "[!] FATAL: 'vol' command not found."
