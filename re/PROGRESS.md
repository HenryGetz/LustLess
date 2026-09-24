# PROGRESS — Covenant Eyes "Victory Shield" RE tracker

Master tracker. **Orchestrator-owned**: subagents must not edit this file.
Status: ✅ done · 🔍 in progress · ⬜ pending. Evidence pointers land in `findings/`.

## Phase status

| Phase | Status | Notes |
|---|---|---|
| Recon | 🔍 | Surface enumerated (`INVENTORY.md`); WFP/driver details in flight |
| Scaffold | ✅ | `re/` layout, README, INVENTORY, this tracker |
| Intake | 🔍 | Ghidra import + auto-analysis of 11 programs in flight |
| StaticRE | ⬜ | Per-subsystem passes (wave B after Intake) |
| Dynamic | 🔍 | Live-surface recon in flight; API/network tracing in wave C |
| Consolidation | ⬜ | Master architecture + Linux mapping |

## Work items

### Recon
- [x] Enumerate CE filesystem artifacts — `INVENTORY.md` §6
- [x] Enumerate services, drivers, processes — `INVENTORY.md` §3–4
- [x] Enumerate registry, persistence, config — `INVENTORY.md` §5
- [ ] Enumerate network filtering surface — WFP/winsock verdict → `findings/01-dynamic-recon/live-surface.md` §b–c
- [ ] Hash and pull CE binaries — `re/samples/MANIFEST.sha256`

### Scaffold
- [x] Create `re/` folder structure
- [x] Write PROGRESS.md tracker
- [x] Write inventory (`INVENTORY.md`) + conventions (`README.md`)

### Intake
- [ ] Import binaries into Ghidra (11 programs incl. `CEA.sys`)
- [ ] Run auto-analysis all binaries
- [ ] Baseline metadata/imports/strings docs → `findings/00-baseline/`

### StaticRE (wave B — one pass each)
- [ ] Screen capture + classifier pipeline (`VictoryShieldClassifier.exe`) → `findings/10-classifier/`
- [ ] Kernel driver behavior (`CEA.sys`) → `findings/11-driver/`
- [ ] Network filtering / DNS / proxy surface → `findings/12-network/`
- [ ] Service + IPC architecture (`VictoryShieldCommService.exe`, `ce-file`, local endpoint) → `findings/13-service-ipc/`
- [ ] Watchdog, persistence, anti-tamper (`VSWD.*`, `RestartVS*.exe`, `ProcessPrivileges.dll`) → `findings/14-watchdog/`
- [ ] UI client + local storage + sign-in (`VictoryShield.exe`, `UWPApp.dll`) → `findings/15-ui/`
- [ ] Updater / telemetry / upload protocol (`WinSparkle` usage, BugSplat, comm logs) → `findings/16-updater-telemetry/`

### Dynamic (wave C)
- [ ] Runtime process + API tracing (capture path, IPC live)
- [ ] Runtime network capture (endpoints, TLS, payloads)
- [ ] Driver + filter enumeration live (merged into `live-surface.md`, deepened here)

### Consolidation
- [ ] Master architecture doc → `findings/90-architecture.md`
- [ ] Linux reimplementation mapping → `findings/91-linux-mapping.md`
- [ ] Finalize tracker + samples manifest

## In-flight subagent passes

| Pass | Output | Status |
|---|---|---|
| GhidraIntake | `findings/00-baseline/` | 🔍 |
| LiveDynamicRecon | `findings/01-dynamic-recon/live-surface.md` | 🔍 |
| ArtifactDbState | `findings/02-artifacts/{local-db,event-queue,user-file}.md` | 🔍 |
| ArtifactClassifierLogs | `findings/02-artifacts/{classifier-data,enc-data,logs}.md` | 🔍 |
