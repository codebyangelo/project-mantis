# Implementation Plan - low-overhead Evolved Automation Engine for v0.0.4

This plan outlines the technical changes to migrate `agent_v0.0.4` from dry-run simulations and static cache parsing into a real-time, resource-conscious automation engine. It strictly honors the system constraints of the target Celeron hardware (2 cores, 3.6 GiB RAM).

---

## User Review Required

> [!IMPORTANT]
> The automation engine will run **live Volatility 3** and **fls** commands against the 19GB memory dump and 23GB E01 disk images.
>
> To support low-resource hardware:
> 1. We enforce **strict sequential execution** (no multi-threading/concurrency to prevent storage choke).
> 2. We use **dynamic path node resolution** in the E01 image by walking directory parts sequentially (no recursive `fls -r` scans).
> 3. We persist intermediate progress to `/mnt/sift_ext4/findevil_triage_profile.json` so the tool can resume execution seamlessly after any power loss or crash.

---

## Open Questions

None. The system parameters and tool interfaces are verified.

---

## Proposed Changes

### Component: Find Evil CLI Orchestrator

We will modify [orchestrator.py](file:///mnt/sift_ext4/sift_home/projects/findevil_agent/agent_v0.0.4/orchestrator.py) to incorporate the 3-Phase pipeline, structured regex parsers, and state persistence.

#### [MODIFY] [orchestrator.py](file:///mnt/sift_ext4/sift_home/projects/findevil_agent/agent_v0.0.4/orchestrator.py)

We will rewrite `orchestrator.py` to:
1. **Define Default Image Paths**:
   * Memory dump: `/mnt/sift_ext4/evidence/Rocba-Memory/Rocba-Memory.raw`
   * Disk image: `/media/analyst/external_drive/project_data/rocba-cdrive.e01`
2. **Implement Persistent State Loading & Saving**:
   * Load/save state to `/mnt/sift_ext4/findevil_triage_profile.json`.
3. **Implement Phase 1: High-Speed Triage**:
   * Run `windows.pstree` and `windows.cmdline` sequentially.
   * Write raw outputs to `/mnt/sift_ext4/` cache files to isolate storage reads.
4. **Implement Phase 2: In-Memory Parsing & Filtering**:
   * Clean up visual tree dashes (`.---`) and stars (`*`) from `pstree` using regex.
   * Map process arguments by PID.
   * Scan executable paths for `AppData`, `Temp`, or `Public`.
5. **Implement Phase 3: Precision Strikes**:
   * Walk E01 directories path parts starting from the root to dynamically resolve nodes for `fls`.
   * Run targeted `windows.malfind --pid <PID>` and targeted `fls` node lookups.
   * Save the strikes' output into the JSON profile.
6. **Pass Telemetry to Gemini**:
   * Start `FindEvilAgent` and feed it the compiled JSON telemetry profile to write the final assessment/containment report.

### Component: ReAct Agent Cognitive Instructions

We will modify [agent.py](file:///mnt/sift_ext4/sift_home/projects/findevil_agent/agent_v0.0.4/agent.py) to reflect that the triage and strikes are fully integrated into the automation engine, instructing the agent to focus on analyzing the structured telemetry profile rather than trying to fetch raw cache datasets.

#### [MODIFY] [agent.py](file:///mnt/sift_ext4/sift_home/projects/findevil_agent/agent_v0.0.4/agent.py)

Update system instructions to reflect the automated ingestion and focus the ReAct reasoning loop on evaluating the compiled JSON profile for IOC containment.

---

## Verification Plan

### Automated Tests
* Execute the new build of the orchestrator to verify:
  1. Sequential execution of the phases.
  2. JSON profile creation/persistence in `/mnt/sift_ext4/findevil_triage_profile.json`.
  3. Seamless recovery when restarting the orchestrator.
  4. Final telemetry hand-off to Gemini and report printing.
