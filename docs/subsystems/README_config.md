# Documentation for `config.py`

## Overview
This file, `config.py`, serves as the configuration and environment setup module for `agent_v0.5.2` of project mantis. Its primary responsibility is managing the initialization of vital file and directory paths utilized throughout the agent's execution. By utilizing environment variables combined with fallback mechanisms, it guarantees flexibility in varied execution environments, ensuring data such as evidence, caches, and logs are organized correctly.

## Architecture & Flow
From a top-down perspective, the module acts as a static configuration hub that performs immediate setup operations upon import:
1.  **Dynamic Anchoring:** The script establishes a baseline anchor (`BASE_DIR`) dynamically based on its own location in the filesystem using `__file__`.
2.  **Environment Variable Priority:** For critical external dependencies (Evidence, Caches, Playbooks), the configuration attempts to read from system environment variables (prefixed with `PM_`). This allows external orchestration tools or users to control the agent's context without modifying the source code.
3.  **Hardcoded Fallbacks:** If the respective environment variables are missing, the module falls back to predefined default absolute and relative paths structured for the expected development or deployment filesystem layout.
4.  **Local Path Generation:** It generates paths for application-specific outputs (logs, IOC stores, thought ledgers) relative to the `BASE_DIR`.
5.  **Filesystem Initialization:** The script acts preemptively by ensuring that the crucial base directories (`EVIDENCE_DIR` and `CACHE_DIR`) physically exist on the file system upon initialization, creating them if they are absent.

## Variables & Components

Here is a highly detailed breakdown of every component initialized within the module:

### `BASE_DIR`
*   **Definition:** `os.path.dirname(os.path.abspath(__file__))`
*   **Purpose:** The absolute directory path where `config.py` resides. This acts as the foundational root for localized application files.

### `EVIDENCE_DIR`
*   **Definition:** `os.environ.get("PM_EVIDENCE_DIR", "/media/analyst/external_drive/home/angelo/Desktop/project_data/evidence")`
*   **Purpose:** The designated directory path for storing and accessing evidence data, such as images. 
*   **Environment Variable:** `PM_EVIDENCE_DIR`
*   **Default:** `/media/analyst/external_drive/home/angelo/Desktop/project_data/evidence`

### `CACHE_DIR`
*   **Definition:** `os.environ.get("PM_CACHE_DIR", os.path.join(EVIDENCE_DIR, "evidence_cache"))`
*   **Purpose:** The designated directory path for storing generated caching data, reducing redundant processing operations.
*   **Environment Variable:** `PM_CACHE_DIR`
*   **Default:** A subdirectory named `evidence_cache` situated within the resolved `EVIDENCE_DIR`.

### `PLAYBOOK_PATH`
*   **Definition:** `os.environ.get("PM_PLAYBOOK_PATH", "/mnt/sift_ext4/dfir_playbook.json")`
*   **Purpose:** The exact file path mapping to the Digital Forensics and Incident Response (DFIR) playbook JSON file.
*   **Environment Variable:** `PM_PLAYBOOK_PATH`
*   **Default:** `/mnt/sift_ext4/dfir_playbook.json`

### `IOC_STORE_PATH`
*   **Definition:** `os.path.join(BASE_DIR, "ioc_store.json")`
*   **Purpose:** The precise path resolving to the Indicator of Compromise (IOC) storage file, persisting state or discovered intelligence. Anchored to `BASE_DIR`.

### `THOUGHTS_PATH`
*   **Definition:** `os.path.join(BASE_DIR, "thoughts.txt")`
*   **Purpose:** The path resolving to the agent's thought ledger, utilized to document the agent's reasoning processes or steps taken. Anchored to `BASE_DIR`.

### `EXECUTION_LOG_PATH`
*   **Definition:** `os.path.join(BASE_DIR, "execution.log")`
*   **Purpose:** The path resolving to the master execution log, storing errors, debugging information, and runtime states. Anchored to `BASE_DIR`.

## Initialization Logic (Bottom-Up execution)

At the bottom of the script, execution flow occurs upon import. The script invokes `os.path.exists()` and `os.makedirs(..., exist_ok=True)` on the `EVIDENCE_DIR` and `CACHE_DIR`.
*   This ensures no downstream script will fail due to a `FileNotFoundError` when attempting to write to these foundational data stores.
*   The `exist_ok=True` parameter prevents an exception if the directories already exist.
