# CEA.sys — baseline

> **STOCK WINDOWS COMPONENT — not Covenant Eyes; do not RE as CE.**
> Cross-reference: `re/findings/01-dynamic-recon/live-surface.md` §a (byte-identical to WinSxS `microsoft-windows-eventaggregation` copy per LiveDynamicRecon).

## What it does

Windows kernel driver implementing **Event Aggregation** (brokered-event / WNF-driven aggregate event conditions) for the Windows Background Broker infrastructure. Despite living at the session's presumed "CE driver" path `C:\Windows\System32\drivers\CEA.sys`, everything about the binary says Microsoft inbox component: Microsoft Windows Authenticode signature, version info exactly matching the host OS build, `EventAggregation.sys` internal name, ETW provider `Microsoft.Windows.EventAggregation`. The "CEA" acronym is not "Covenant Eyes Agent" [INFERENCE: conflation of acronyms in the original tasking].

## Mechanism

### Metadata

| Field | Value | Source |
|---|---|---|
| Source path | `C:\Windows\System32\drivers\CEA.sys` (108,016 bytes) | VM file |
| Language | `x86:LE:64:default` (x86-64, little-endian), compiler spec `windows` (`visualstudio:unknown`) | Ghidra `get_metadata` |
| Image base | `0x140000000` | Ghidra `get_metadata` |
| Format / layout | PE, 14 memory blocks, 104,528 bytes mapped | Ghidra `get_metadata` |
| Functions / symbols | 233 functions (post-analysis), 1,836 symbols | Ghidra `get_metadata`, `analysis_status` |
| PE TimeDateStamp | `3077124930` → **2067-07-05 20:55:30 UTC** (anomaly, see below) | PE header `e_lfanew+8` (PowerShell read) |
| Authenticode signer | `CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US` | `Get-AuthenticodeSignature` |
| MD5 / SHA256 | `bcdaf42120153d90a3d6949d5240bfd3` / `c82628cc7e768b28c3ff57c429e7735d345a0611be07e529188058b6eca95b9f` | Ghidra `get_program_options` "Program Information" |
| PDB | `CEA.pdb`, RSDS GUID `e3ba3bfe-ac30-5592-36ed-cb014ef971fe`, age 1 | Ghidra `get_program_options` |
| Version info | CompanyName `Microsoft Corporation`; FileDescription `Event Aggregation Kernel Mode Library`; FileVersion `10.0.26100.9444 (WinBuild.160101.0800)`; InternalName/OriginalFilename `EventAggregation.sys`; ProductName `Microsoft® Windows® Operating System` | Ghidra `get_program_options` |

**Timestamp anomaly:** PE TimeDateStamp reads 2067-07-05 — far in the future and inconsistent with the FileVersion's WinBuild stamp. [INFERENCE] build-environment clock skew in the Microsoft build pipeline (or an intentionally non-standard stamp); recorded verbatim, not corrected.

### Imports grouped by DLL

65 imports total (Ghidra `list_imports` = 65; `list_external_locations` supplies the library per symbol). IAT addresses below are as returned by `list_external_locations` (`address_space: ram`; add image base `0x140000000`).

**NTOSKRNL.EXE (59 imports)**

- Registry (kernel key/value): `ZwCreateKey`, `ZwOpenKey`, `ZwClose`, `ZwDeleteKey`, `ZwSetValueKey`, `ZwQueryValueKey`, `ZwEnumerateKey`, `ZwEnumerateValueKey`
- ETW tracing: `EtwRegister`, `EtwUnregister`, `EtwSetInformation`, `EtwWriteTransfer`
- WNF state: `ExSubscribeWnfStateChange`, `ExUnsubscribeWnfStateChange`, `ExQueryWnfStateData`, `ZwQueryWnfStateData`
- Pool/sync/timers: `ExAllocatePool2`, `ExFreePoolWithTag`, `ExQueueWorkItem`, `ExAcquirePushLockExclusiveEx`/`SharedEx`, `ExReleasePushLockExclusiveEx`/`SharedEx`, `KeInitializeDpc`, `KeInitializeTimer`, `KeSetTimer`, `KeCancelTimer`, `PsGetCurrentThreadId`
- Hash tables: `RtlCreateHashTable`, `RtlDeleteHashTable`, `RtlInsertEntryHashTable`, `RtlLookupEntryHashTable`, `RtlRemoveEntryHashTable`, `RtlEnumerateEntryHashTable`, `RtlGetNextEntryHashTable`, `RtlInitEnumerationHashTable`, `RtlEndEnumerationHashTable`
- Misc: `RtlInitUnicodeString(Ex)`, `RtlFreeUnicodeString`, `RtlCompareUnicodeString`, `RtlStringFromGUID`, `RtlGUIDFromString`, `RtlValidSid`, `RtlLengthSid`, `RtlCompareMemory`, `RtlComputeCrc32`, `RtlNtStatusToDosError`, `RtlRunOnceExecuteOnce`, `RtlQueryFeatureConfiguration(ChangeStamp)`, `RtlRegisterFeatureUsageProvider`/`Unregister…`, `RtlRegisterFeatureConfigurationChangeNotification`/`Unregister…`, `RtlRecordFeatureUsage`, `RtlNotifyFeatureUsage`, `RtlArmFeatureUsageProviderFlushNotification`, `wcsnlen`

**MSRPC.SYS (6 imports)** — kernel RPC client: `NdrClientCall3` (IAT `0x00010be8`), `RpcBindingCreateW` (`0x00010b78`), `RpcBindingBind` (`0x00010b98`), `RpcBindingFree` (`0x00010baa`), `UuidCreate` (`0x00010b6a`), `UuidEqual` (`0x00010b8c`)

Notable-API category scan: **no** networking (winsock/HTTP), **no** crypto (bcrypt/ncrypt/CNG), **no** process/thread injection (Ps*Create/OpenProcess), **no** service-control (SCM), **no** user-mode IOCTL surface (no Io* device APIs beyond driver lifecycle), **no** GDI/screenshot, **no** browser APIs. The only "driver IOCTL"-class surface is the driver lifecycle exports below.

### Exports (31 named + 32 ordinal aliases; Ghidra `list_exports`)

| Group | Export | Address |
|---|---|---|
| Driver lifecycle | `entry` | `0x140014010` |
| Driver lifecycle | `DllInitialize` | `0x140014080` |
| Driver lifecycle | `DllUnload` | `0x140011320` |
| Broker RPC buffers | `BriAllocateRpcBuffer` | `0x140004eb0` |
| Broker RPC buffers | `BriFreeRpcBuffer` | `0x140005190` |
| Broker registry | `BriCreateBrokeredEvent` | `0x140004f00` |
| Broker registry | `BriCreateBrokeredEventEx` | `0x140004f50` |
| Broker registry | `BriDeleteBrokeredEvent` | `0x140005020` |
| Broker registry | `BriIsBrokerRegistered` | `0x1400051b0` |
| Broker registry | `BriResolveBrokerIdByEventId` | `0x140005280` |
| Broker registry | `BriCleanup` | `0x140004ed0` |
| Aggregation mgmt | `EaCreateAggregation` | `0x140001b60` |
| Aggregation mgmt | `EaDeleteAggregation` | `0x140001de0` |
| Aggregation mgmt | `EaGetAggregation` | `0x1400020d0` |
| Aggregate events | `EACreateAggregateEvent` | `0x140001220` |
| Aggregate events | `EADeleteAggregateEvent` | `0x140001640` |
| Aggregate events | `EAEnumerateAggregateEvents` | `0x140001720` |
| Aggregate events | `EAQueryAggregateEventData` | `0x140001910` |
| Aggregate events | `EaCreateAggregatedEvent` | `0x140004690` |
| Aggregate events | `EaDeleteAggregatedEvent` | `0x140004760` |
| Aggregate events | `EaEnableAggregatedEvent` | `0x140001fb0` |
| Aggregate events | `EaDisableAggregatedEvent` | `0x140001e90` |
| Aggregate events | `EaSignalAggregatedEvent` | `0x140002230` |
| Aggregate events | `EaQueryAggregatedEvent` | `0x140002220` |
| Aggregate events | `EaQueryAggregateEventConditionState` | `0x1400020f0` |
| Event parameters | `EaStoreAggregatedEventParameters` | `0x140006a30` |
| Event parameters | `EaQueryAggregatedEventParameters` | `0x1400066c0` |
| Event parameters | `EaDeleteAggregatedEventParameters` | `0x1400063d0` |
| Event parameters | `EaFreeAggregatedEventParameters` | `0x1400065f0` |
| Codec/buffers | `EaEncodeBrokeredEvent` | `0x1400110d0` |
| Codec/buffers | `EaDecodeBrokeredEvent` | `0x140011010` |
| Codec/buffers | `EaFreeBuffer` | `0x140006130` |

(Each named export also appears as an `Ordinal_NN` alias at the same address; 63 export entries total.)

### Representative strings (Ghidra `list_strings`, 244 total, all fetched)

| Address | String | Category |
|---|---|---|
| `0x14000ba60` | `\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion\BackgroundModel\Brokers` | registry key (kernel form) |
| `0x14000cfa8` | `Microsoft.Windows.EventAggregation` | ETW provider name |
| `0x14001315e` | `CEA.sys` | module self-name (export table) |
| `0x140010b5c` | `ntoskrnl.exe` | import DLL name |
| `0x140010bbc` | `msrpc.sys` | import DLL name |
| `0x14000c5d4` | `Aggregate_Signal` | ETW trace field |
| `0x14000c5f5` | `Aggregate_Query` | ETW trace field |
| `0x14000c62b` | `Aggregate_CreateAggregationFailed` | ETW trace field |
| `0x14000cb36` | `Event_ProcessNotification` | ETW trace field |
| `0x14000cbf7` | `Event_WnfCallback` | ETW trace field |
| `0x14000cd5e` | `TraceRundown_AggregateEvent` | ETW trace field |
| `0x14000cf1e` | `Event_TimeLimitReached` | ETW trace field |
| `0x14000d090` / `0x14000d0a8` | `.rdata$zETW1` / `.rdata$zETW2` | section names |

No URLs/IPs, no named pipes (`\\.\pipe\...`), no mutexes, no service names, no `C:\` file paths, and no `HKLM`/`HKU` user-mode registry paths appear among the 244 strings — consistent with a kernel infrastructure driver.

## Evidence

- Ghidra MCP (project `CE`, program `CEA.sys`): `get_metadata`, `get_program_options("Program Information")`, `list_imports` (65), `list_external_locations` (65 with libraries), `list_exports` (63), `list_strings` (244, offsets 0 and 60) — addresses as tabulated above.
- VM command output (2026-09-24, `Get-AuthenticodeSignature`): `CEA.sys | ts=3077124930 | 2067-07-05 20:55:30Z | signer=CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Was…`
- Corroboration (not mine): `re/findings/01-dynamic-recon/live-surface.md` §a — SHA256 byte-identical to WinSxS `microsoft-windows-eventaggregation` copy; no SCM service/INF/device objects of its own.
- Checkpoint: `C:\Users\dolphin\ghidra-ckpt\CEA.sys.gzf` (396,690 B) + project `CE:/CEA.sys` (saved).

## Linux-reimplementation notes

Nothing to port — this is Windows infrastructure with no accountability semantics [INFERENCE]. LustLess has no analog; treat the path/name as a red herring. If any CE component actually *calls* into brokered-event aggregation, that is a user-mode Windows API dependency to note in the calling component's doc, not a reimplementation target here.
