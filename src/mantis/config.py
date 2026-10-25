import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _resolve_evidence_dir() -> str:
    if "PM_EVIDENCE_DIR" in os.environ:
        return os.environ["PM_EVIDENCE_DIR"]
    if os.path.isdir("/sdcard/Download"):
        return "/sdcard/Download/evidence"
    return os.path.expanduser("~/.cache/mantis/evidence")


def _resolve_cache_dir(evidence_dir: str) -> str:
    if "PM_CACHE_DIR" in os.environ:
        return os.environ["PM_CACHE_DIR"]
    return os.path.join(evidence_dir, "evidence_cache")


# Base directory for the evidence (images, etc.)
EVIDENCE_DIR = _resolve_evidence_dir()

# Directory where generated caches are stored
CACHE_DIR = _resolve_cache_dir(EVIDENCE_DIR)


# Path to the DFIR playbook
def _get_playbook_path():
    import json
    context_path = os.path.join(CACHE_DIR, "context.json")
    if os.path.exists(context_path):
        try:
            with open(context_path, "r") as f:
                if json.load(f).get("OS", "windows").lower() == "linux":
                    return os.path.join(BASE_DIR, "dfir_playbook_linux.json")
        except (json.JSONDecodeError, OSError):
            pass
    return os.path.join(BASE_DIR, "dfir_playbook.json")


PLAYBOOK_PATH = os.environ.get("PM_PLAYBOOK_PATH", _get_playbook_path())

# Path to the IOC store
IOC_STORE_PATH = os.path.join(BASE_DIR, "ioc_store.json")

# Path to the agent's thought ledger
THOUGHTS_PATH = os.path.join(BASE_DIR, "thoughts.txt")
EXECUTION_LOG_PATH = os.path.join(BASE_DIR, "execution.log")

try:
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
except (PermissionError, OSError):
    EVIDENCE_DIR = os.path.expanduser("~/.cache/mantis/evidence")
    try:
        os.makedirs(EVIDENCE_DIR, exist_ok=True)
    except OSError:
        pass

try:
    os.makedirs(CACHE_DIR, exist_ok=True)
except (PermissionError, OSError):
    CACHE_DIR = os.path.join(EVIDENCE_DIR, "evidence_cache")
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
    except OSError:
        pass
