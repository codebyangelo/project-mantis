import sys
import datetime
from config import EXECUTION_LOG_PATH

class ExecutionLogger:
    @staticmethod
    def log(component: str, message: str, level: str = "INFO"):
        timestamp = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")
        formatted = f"[{timestamp}] [{level}] [{component}] {message}"
        
        # Print to terminal with basic ANSI colors for transparency
        if level == "ERROR":
            print(f"\033[91m{formatted}\033[0m")
        elif level == "WARN":
            print(f"\033[93m{formatted}\033[0m")
        elif level == "SUCCESS":
            print(f"\033[92m{formatted}\033[0m")
        else:
            print(formatted)
            
        # Append to execution log
        try:
            with open(EXECUTION_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(formatted + "\n")
        except Exception as e:
            # Fallback if logging fails
            print(f"[!] Logger IO Error: {e}")
