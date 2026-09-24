# PROGRESS — Covenant Eyes "Victory Shield" RE tracker

Master tracker. **Orchestrator-owned**: subagents must not edit this file.
Status: ✅ done · 🔍 in progress · ⬜ pending. Evidence pointers land in `findings/`.

## Phase status

| Phase | Status | Notes |
|---|---|---|
| Recon | ✅ | Surface enumerated (`INVENTORY.md`); live verdicts in `findings/01-dynamic-recon/live-surface.md` (pure user-mode product) |
| Scaffold | ✅ | `re/` layout, README, INVENTORY, this tracker |
| Intake | 🔍 | Ghidra import + auto-analysis of 11 programs in flight |
| StaticRE | ⬜ | Per-subsystem passes (wave B after Intake) |
| Dynamic | 🔍 | Live recon + network capture done; Procmon API-trace pass remains (wave C) |
| Consolidation | ⬜ | Master architecture + Linux mapping |

## Work items

### Recon
- [x] Enumerate CE filesystem artifacts — `INVENTORY.md` §6
- [x] Enumerate services, drivers, processes — `INVENTORY.md` §3–4
- [x] Enumerate registry, persistence, config — `INVENTORY.md` §5
- [x] Enumerate network filtering surface — verdict: NO CE WFP/winsock/proxy footprint → `findings/01-dynamic-recon/live-surface.md` §b–c, §e
- [x] Hash and pull CE binaries — `re/samples/MANIFEST.sha256`

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
- [x] Kernel driver behavior — ANSWERED: CE ships no kernel component; `CEA.sys` is stock Windows Event Aggregation (live-surface §a)
- [ ] Network filtering / DNS / proxy surface → `findings/12-network/`
- [ ] Service + IPC architecture (`VictoryShieldCommService.exe`, `ce-file`, local endpoint) → `findings/13-service-ipc/`
- [x] Watchdog, persistence, anti-tamper (`VSWD.*`, `RestartVS*.exe`, `ProcessPrivileges.dll`) → `findings/14-watchdog/`
- [x] UI client + local storage + sign-in (`VictoryShield.exe`, `UWPApp.dll`) → `findings/15-ui/`
- [ ] Updater / telemetry / upload protocol (`WinSparkle` usage, BugSplat, comm logs) → `findings/16-updater-telemetry/`

### Dynamic (wave C)
- [ ] Runtime process + API tracing — process/IPC half done (`findings/03-runtime/process-observation.md`); Procmon API-trace pass deferred to wave C
- [x] Runtime network capture — single-endpoint stack, idle-silent, 601 s heartbeat local-only (`findings/03-runtime/network-capture.md`)
- [x] Driver + filter enumeration live — merged into `findings/01-dynamic-recon/live-surface.md`

### Consolidation
- [ ] Master architecture doc → `findings/90-architecture.md`
- [ ] Linux reimplementation mapping → `findings/91-linux-mapping.md`
- [ ] Finalize tracker + samples manifest

## In-flight subagent passes

| Pass | Output | Status |
|---|---|---|
| GhidraIntake | `findings/00-baseline/` | 🔍 |
| LiveDynamicRecon | `findings/01-dynamic-recon/live-surface.md` | ✅ |
| ArtifactDbState | `findings/02-artifacts/{local-db,event-queue,user-file}.md` | ✅ |
| ArtifactClassifierLogs | `findings/02-artifacts/{classifier-data,enc-data,logs}.md` | ✅ |
| RuntimeObservability | `findings/03-runtime/process-observation.md` | ✅ |
| NetworkCapture | `findings/03-runtime/network-capture.md` | ✅ |
| WatchdogPass | `findings/14-watchdog/{watchdog,protectors}.md` | ✅ |
| UiPass | `findings/15-ui/{ui-architecture,signin-and-settings}.md` | ✅ |
