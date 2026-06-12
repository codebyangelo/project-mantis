# Project Mantis v0.5.2

Project Mantis is an autonomous Digital Forensics and Incident Response (DFIR) agent designed to analyze memory dumps and disk images. It extracts artifacts using Volatility and SleuthKit, deterministically filters findings using `sieve_deterministic.py`, and orchestrates an LLM to synthesize final MITRE ATT&CK incident reports.

## Validated Scope
**Important:** This agent version (v0.5.2) has been strictly tested and validated against the following datasets:
- **CFReDS Data Leakage Case** (Insider Threat & Removable Media)
- **ROCBA Memory Dataset** (Process Injection & Code Execution)

Any other datasets fall outside the current verified scope of the project and may produce unpredictable results.

## Setup & Usage

Project Mantis is designed to be highly portable. You do not need to move your massive evidence files; simply tell the agent where your evidence is located using environment variables.

### 1. Set the Evidence Directory
Point the `PM_EVIDENCE_DIR` environment variable to the directory containing your `.raw`, `.dd`, or `.e01` images.
```bash
export PM_EVIDENCE_DIR="/path/to/your/evidence_directory"
```

### 2. Run the Extractor
The extractor will automatically classify the images, run Volatility 3 and FLS, and build the `evidence_cache` in the same directory.
```bash
python3 extractor.py
```
*(Note: Running this will overwrite any existing cache and rebuild it from scratch, which can take a while for large images.)*

### 3. Run the Orchestrator
The orchestrator reads the cache, passes suspicious artifacts through the deterministic sieve, and consults the LLM to write the final incident report.
```bash
python3 orchestrator.py
```

The final report will be generated as a Markdown file in the project directory.
