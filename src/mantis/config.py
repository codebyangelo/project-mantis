import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Base directory for the evidence (images, etc.)
EVIDENCE_DIR = os.environ.get("PM_EVIDENCE_DIR", "/sdcard/Download/evidence")

# Directory where generated caches are stored
CACHE_DIR = os.environ.get("PM_CACHE_DIR", os.path.join(EVIDENCE_DIR, "evidence_cache"))

# Path to the DFIR playbook
def _get_playbook_path():
    import json
    context_path = os.path.join(CACHE_DIR, "context.json")
    if os.path.exists(context_path):
        try:
            with open(context_path, "r") as f:
                if json.load(f).get("OS", "windows").lower() == "linux":
                    return os.path.join(BASE_DIR, "dfir_playbook_linux.json")
        except:
            pass
    return os.path.join(BASE_DIR, "dfir_playbook.json")

PLAYBOOK_PATH = os.environ.get("PM_PLAYBOOK_PATH", _get_playbook_path())

# Path to the IOC store
IOC_STORE_PATH = os.path.join(BASE_DIR, "ioc_store.json")

# Path to the agent's thought ledger
THOUGHTS_PATH = os.path.join(BASE_DIR, "thoughts.txt")
EXECUTION_LOG_PATH = os.path.join(BASE_DIR, "execution.log")

if not os.path.exists(EVIDENCE_DIR):
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

if not os.path.exists(CACHE_DIR):
    os.makedirs(CACHE_DIR, exist_ok=True)
