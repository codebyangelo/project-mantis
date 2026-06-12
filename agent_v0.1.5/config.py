import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Base directory for the evidence (images, etc.)
EVIDENCE_DIR = os.environ.get("PFE_EVIDENCE_DIR", "/media/analyst/external_drive/project_data")

# Directory where generated caches are stored
CACHE_DIR = os.environ.get("PFE_CACHE_DIR", os.path.join(EVIDENCE_DIR, "evidence_cache"))

# Path to the DFIR playbook
PLAYBOOK_PATH = os.environ.get("PFE_PLAYBOOK_PATH", "/mnt/sift_ext4/dfir_playbook.json")

# Path to the IOC store
IOC_STORE_PATH = os.path.join(BASE_DIR, "ioc_store.json")

# Path to the agent's thought ledger
THOUGHTS_PATH = os.path.join(BASE_DIR, "thoughts.txt")
