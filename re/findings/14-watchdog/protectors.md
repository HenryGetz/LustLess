# Tamper protectors — Registry Protector ('RP') and Folder Protector ('FP')

Scope: `VSWD.dll` (implementation; CIL methods cited by Ghidra method VA, IL disassembled from
`re/samples/00-baseline/VSWD.dll`), `VSWD.exe` (duplicate copy of the same managed code —
identical method set minus the `WatchdogControl` exports and the embedded `ProcessPrivileges`
classes; its `RegistryProtector` uses the external `ProcessPrivileges 1.5.7.0` assembly),
plus call-site tracing in read-only `vs-config.exe`. Builds on
`re/findings/00-baseline/VSWD.dll.md` (metadata/strings) — this doc documents behavior.

## What it does

Two tamper-repair subsystems inside the `VSWD` service (`WatchdogService.ProtectionService`):

- **Registry Protector (RP)** — 22 value-level "protectors" (`WatchdogService.RegistryProtector`)
  over 4 registry keys: each watches its key via `RegNotifyChangeKeyValue` and, on any change
  event, rewrites the protected value from a known-good copy held in memory, logging
  `Anomaly Detected.  Repairing [<key>\<value> with <expected>]`. The expected values come from
  compiled-in constants (service config, autostart paths), not from on-disk copies.
- **Folder Protector (FP)** — one `WatchdogService.FolderProtector` over the install directory
  (`C:\Program Files\CE\`): locks its ACL (Everyone: read/execute but **deny delete**), watches
  the tree for ACL changes (`FileSystemWatcher` with `NotifyFilter = Security`), and re-applies
  the lock whenever it changes. Foreign files dropped into the folder are *not* removed — the
  tree's ACLs are simply re-locked so deletions stay blocked.

Both can be switched off administratively: the `disableFileProtection` /
`disableRegistryProtection` exports of `VSWD.dll` (called by `vs-config.exe`'s
`disableWatchdogProtection`), or in-process via SCM custom command **243** (see `watchdog.md` §10).

## Mechanism

### Startup (ProtectionService)

`StartWatching_Elapsed` (IL @0x10002a04) runs `ProtectRegistrySettings` then `ProtectFolders`:

- `ProtectRegistrySettings` (IL @0x10002b44): builds a `List<RegistryProtector>` from
  `registrySettingsToProtect_` (4 tuples filled by `ProtectAutostartup` @0x1000249f,
  `ProtectAutostartupExplorer` @0x100024cc, `ProtectWatchdogService` @0x10002654,
  `ProtectCommService` @0x100026f8; each tuple = `(keyPath, valueName, expectedValue,
  disableWow64Redirection=true)`), creates one `RegistryProtector` per tuple and sets
  `Enabled = true`; failures logged `"Failed adding RegProt: "`; finally logs
  **`"RP startup complete"`**.
- `ProtectFolders` (IL @0x10002c3c): `folderProtectors_ = { new FolderProtector(
  AppDomain.CurrentDomain.BaseDirectory) }` — **exactly one folder** (capacity-1 list),
  `Enable()` each, logs **`"FP startup complete"`**.

### Registry Protector — watch mechanism

`RegistryProtector::.ctor` (IL @0x10004b74): splits the path on `\` into hive + subkey
(hive map `HKEY_CLASSES_ROOT`…`HKEY_CURRENT_CONFIG`, IL @0x1000510c);
`OpenBaseKey(hive, Registry64)` (all tuples pass `disableWow64Redirection = true`); creates a
`RegistryUtils.RegistryMonitor(path, disableWow64Redirection)` and subscribes `OnRegChanged`;
arms `repairSettingTimer_` = `Timers.Timer(1000 ms)` → `RepairRegistryEntry`, initially disabled.

`RegistryUtils.RegistryMonitor::ThreadLoop` (IL @0x100034b8) — event-driven, **not polling**:

```
RegOpenKeyEx(hive, subkey, 0, KEY_QUERY_VALUE|KEY_NOTIFY|READ_CONTROL [| KEY_WOW64_64KEY])
loop:
  RegNotifyChangeKeyValue(hKey, fWatchSubtree=TRUE, filter=15, hEvent, fAsynchronous=TRUE)
  WaitAny([notifyEvent(AutoResetEvent), _eventTerminate])
  if notified: OnRegChanged(); if _eventTerminate.WaitOne(0): exit
```

Filter `15` = `REG_NOTIFY_CHANGE_NAME | _LAST_SET | _ATTRIBUTES | _SECURITY` (all four; ctor
default `_regFilter = 15`, IL @0x10003000). P/Invokes: `RegOpenKeyEx`, `RegNotifyChangeKeyValue`,
`RegCloseKey` (dnfile `ImplMap`). Note the monitor watches the whole **key** — any change under
it fires the handler.

### Registry Protector — repair algorithm (`Anomaly Detected. Repairing […]`)

1. `OnRegChanged` (IL @0x10004df0): just enables `repairSettingTimer_` — a **1-second debounce**
   (one repair per burst of changes).
2. `RepairRegistryEntry` (IL @0x10004e00): disable timer → `rmon_.Stop()` (avoid self-triggering)
   → `CreateSubKey(subkey)` → log
   **`Anomaly Detected.  Repairing [<key.Name>\<valueName> with <savedValue>]`** (byte[] values
   rendered with `BitConverter.ToString`, i.e. hex) → **`SetValue(valueName, savedValue_,
   savedValueKind_)` unconditionally** (it does not diff current vs expected — any event on the
   key rewrites the value) → `Close()` → `rmon_.Start()`. Exceptions are logged
   `OnRegChanged[<valueName>]: <ex>`.
3. Expected values: `set_Enabled(true)` (IL @0x10004ce0) records `savedValueKind_` from the live
   value; if the ctor's `savedValue_` was null it snapshots the current value as the reference,
   otherwise it **immediately rewrites** the hardcoded expected value (repair-on-enable) and uses
   it as `savedValue_`. Restore source = in-memory constant/snapshot; there are no embedded
   backup copies on disk.

Log format strings (VSWD.dll managed): `"Anomaly Detected.  Repairing ["` @0x1000d8ee,
`"OnRegChanged["` @0x1000d93a, `" with "`, `"]"`.

### Registry Protector — ACL machinery (present, but unused by default wiring)

`set_Enabled`'s empty-`valueName` branch calls `UnProtectSubkey` → `ProtectSubkey`
(IL @0x10004f30/0x10004fac): with `ProcessPrivileges.PrivilegeEnabler` enabling
`{SeTakeOwnershipPrivilege, SeBackupPrivilege, SeRestorePrivilege}` (enum (29, 2, 22); blob at
`VSWD.dll` VA `0x10002160`), it:
`TakeOwnership(subkey, currentUser)` (records old owner; `OpenSubKey(…, WriteOwner)`,
`SetOwner`) → `SetRules(subkey, protect)` (IL @0x1000507c) → `TakeOwnership(subkey, oldOwner)`.

`SetRules` adds/removes two `Everyone` ACEs on the subkey:

| ACE | rights (dec = hex) | type |
|---|---|---|
| Allow | `131101 = 0x2001D` = KEY_QUERY_VALUE \| KEY_CREATE_SUB_KEY \| KEY_ENUMERATE_SUB_KEYS \| KEY_NOTIFY \| READ_CONTROL | Allow |
| Deny | `852002 = 0xD0022` = KEY_SET_VALUE \| KEY_CREATE_LINK \| DELETE \| WRITE_DAC \| WRITE_OWNER | Deny |

**However**, all 22 protectors created by `ProtectRegistrySettings` have non-empty value names, so
this subkey-ACL path is not executed in the shipping wiring [INFERENCE: legacy/optional code —
the value-level repair loop is the actual RP].

### Folder Protector

`FolderProtector::Enable` (IL @0x10003f10) = `SetFolderSecurity(folder)` + `MonitorFolder(folder)`;
failures logged `"Fail Enable Folder Protector(<folder>): <ex>"`. `Disable` (IL @0x10003f74) =
`watcher_.EnableRaisingEvents = false`.

`SetFolderSecurity` (IL @0x10003fcc):
1. `FileUtilities.FolderUtilities::TakeOwnership(folder)` (IL @0x10003904): enables
   `SeTakeOwnershipPrivilege` (enum 29), `TraverseTree(dirAct, fileAct)` (IL @0x10003af4) over
   `*.*` recursively setting **owner = current user (LocalSystem)** on every directory and file
   (lambdas @0x10003b98/0x10003bcc); errors `"Failed TO(<folder>) - <ex>"`.
2. Builds a fresh `DirectorySecurity` (protection on) with four `Everyone` rules and applies it
   to the folder:

   | rule | rights (dec = hex) | inheritance | type |
   |---|---|---|---|
   | 1 | `131241 = 0x20089` = FILE_LIST_DIRECTORY \| FILE_READ_EA \| FILE_READ_ATTRIBUTES \| READ_CONTROL | ContainerInherit\|ObjectInherit, NoPropagateInherit | Allow |
   | 2 | `65600 = 0x10040` = DELETE \| DELETE_CHILD | ContainerInherit\|ObjectInherit, NoPropagateInherit | **Deny** |
   | 3 | `0x20089` (same) | folder itself | Allow |
   | 4 | `0x10040` (same) | folder itself | **Deny** |

   then `SetAccessRuleProtection(isProtected=true, preserveInheritance=false)` +
   `Directory.SetAccessControl` — matches the live observation "install dir Everyone DENY delete
   + RX" (`01-dynamic-recon`).
3. `FolderUtilities::ResetFileInheritancePermissions(dir)` (IL @0x100039dc): recursively for
   every file (`*.*`): `FileSecurity.SetAccessRuleProtection(false, false)` + `SetAccessControl`
   — i.e. strip explicit file ACEs and **re-enable ACL inheritance** so files pick up the
   folder's protected rules; recurses into subdirectories; first error per class logged
   `"resetFileInheritancePermissions SAC/GF/GD - <ex>"`.

`MonitorFolder` (IL @0x10004084): `FileSystemWatcher` with `Path = folder`,
`IncludeSubdirectories = true`, **`NotifyFilter = 256 = NotifyFilters.Security`** (ACL changes
only; verified against `System.IO.NotifyFilters` docs) and handlers
`Changed/Created/Deleted → OnChanged`, `Renamed` (no-op @0x100041d5), `Error → OnError` (IL
@0x100041c4, logs `"File Watch Failure"`). `OnChanged` (IL @0x1000414c): disables events →
`SetFolderSecurity(folder)` (full re-lock, steps 1–3 again) → re-enables events; exceptions
logged `OnChanged(<path>): <ex>`.

**Foreign processes/files in the protected folder**: nothing is deleted or terminated. Because
the watcher only reacts to `NotifyFilters.Security`, ordinary file drops do not even trigger the
repair; the protection against deletion is the deny ACE itself (a dropped file inherits
Everyone-deny-delete after the next re-lock; until then it keeps the creator's ACL
[INFERENCE]). Process creation inside the folder is not monitored at all.

### The `disableFileProtection` / `disableRegistryProtection` exports

Managed: `WatchdogService.WatchdogControl::disableFileProtection` IL @0x1000519d —
`new ProtectionService(); UnprotectFolders(folderNames, count)`; `disableRegistryProtection`
IL @0x100051ab — `new ProtectionService(); UnprotectRegistryPaths(paths, count)`.
Native exports (Ghidra `VSWD.dll`): `disableFileProtection` @0x100101ee =
`MOV RAX, [0x10012000]; JMP RAX` and `disableRegistryProtection` @0x100101fa =
`MOV RAX, [0x10012008]; JMP RAX` — 12-byte CLR jump thunks into the managed methods
(`disassemble_bytes 0x100101ee–0x10010204`). Signature per the only caller:
`(BSTR* names, int count)`.

- `UnprotectFolders` (IL @0x100028cc): creates `FolderProtector`s for the given names and calls
  `UnprotectFiles` (IL @0x100027d8): per folder `FolderProtector.Disable()` +
  `FolderUnprotector::UnprotectFolderSecurity(folder)` (IL @0x10003840): take ownership,
  `DirectorySecurity` with `Everyone` **FILE_ALL_ACCESS `2032127 = 0x1F01FF`** allow
  (ContainerInherit|ObjectInherit + NoPropagateInherit, and folder-scope), `SetAccessRuleProtection(true,false)`,
  apply, `ResetFileInheritancePermissions` — **a real, stateless unlock** (Everyone full control
  recursively); logs `"UFS complete for <folder>"` or the accumulated error (`"UFS Fail - …"`).
- `UnprotectRegistryPaths` (IL @0x10002904): builds the 4 standard tuples from
  `paths[0..3]` (Run, StartupApproved\Run, Services\VSWD, Services\VictoryShieldCommService —
  same order as `ProtectRegistrySettings`) and calls `UnprotectRegistry` (IL @0x10002784) which
  sets `Enabled = false` on each protector. Since these protector objects were never enabled,
  `set_Enabled(false)` early-returns — **as compiled this export performs no registry
  modification outside the running service** [INFERENCE: the intended semantics is "disarm the
  live service's protectors", but the implementation constructs fresh objects; the effective
  in-service disable is SCM custom command 243, which calls `UnprotectRegistry`/`UnprotectFiles`
  on the *live* instances]. Callers pass 6 paths (below) but only `paths[0..3]` are consumed.

**Admin toggle semantics (vs-config.exe)**: `FUN_14008e690` @0x14008e690
(`DynamicLib::makeSafely("VSWD.dll")`, log `"load library: "`):
`GetProcAddress("disableFileProtection")` → `fn(&bstr1, 1)` with one path [INFERENCE:
`C:\Program Files\CE` — runtime `std::wstring` at `DAT_14041f1c8`, not recoverable from the
file]; `GetProcAddress("disableRegistryProtection")` → `fn(bstr[6], 6)` with six paths
[INFERENCE: the 4 protected keys + legacy `…\Services\CEWD` + `…\Services\CovenantEyesCommService`].
Entry points: `disableWatchdogProtection` = `FUN_140018d30` @0x140018d30
(`VSConfig\src\main.cpp:259`; logs `"removing watchdog protection"`) and wrapper
`FUN_1402fd1a8` @0x1402fd1a8 (`CALL FUN_14008e690`; returns 0). This runs as part of the
watchdog stop/uninstall path (`ce::watchdog_service::{backdoorStop,uninstall}` strings) so the
installer can delete the protected files afterwards (see `watchdog.md` §11,
`re/findings/02-artifacts/logs.md`).

## Evidence

### Protected registry entries — complete table (22 protectors)

Built by `ProtectionService::ProtectRegistrySettings` IL @0x10002b44 + `Protect*` IL
@0x1000249f–0x100026f8 + `ProtectionService::.cctor` IL @0x10002dc8 (constants). Every row is a
`RegistryProtector(keyPath, valueName, expectedValue, disableWow64Redirection=true)`; each is
`Enabled=true` at startup and restored verbatim (value + kind) on any change under its key.

| # | Key (full path) | Value name | Expected value (type) | Constant / evidence |
|---|---|---|---|---|
| 1 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | `Victory Shield` | `"<BaseDir>VictoryShield.exe"` incl. quotes (REG_SZ) — e.g. `"c:\Program Files\CE\VictoryShield.exe"` | `cePathQuoted`, `.cctor` IL @0x10002dc8; key string VSWD.dll @0x1000dddc |
| 2 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run` | `Victory Shield` | 12-byte REG_BINARY `02 00 00 00 00 00 00 00 00 00 00 00` ("enabled") | `explorerAutostartEnableBlob`, `.cctor` IL @0x10002dc8 (byte[12], first byte 2); key string @0x1000de5f |
| 3 | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSWD` | `Start` | `2` — Automatic (REG_DWORD) | `serviceStart = 2`, `.cctor`; `ProtectCommonServiceSettings` IL @0x100024fc |
| 4 | same key | `Type` | `16` — Win32OwnProcess (REG_DWORD) | `serviceType = 16` |
| 5 | same key | `WOW64` | `332` (0x14C = IMAGE_FILE_MACHINE_I386) (REG_DWORD) | `serviceWow64 = 332` |
| 6 | same key | `ErrorControl` | `1` — Normal (REG_DWORD) | `serviceErrorControl = 1` |
| 7 | same key | `ObjectName` | `LocalSystem` (REG_SZ) | literal in `ProtectCommonServiceSettings` |
| 8 | same key | `FailureActions` | 44-byte REG_BINARY: `ffffffff 00000000 00000000 03000000 14000000 (01000000 e8030000)×3` = ResetPeriod=INFINITE, cActions=3, SC_ACTION_RESTART ×3 @1000 ms | blob `B681D3C8…`, VA `0x10002130` (extracted from `re/samples/00-baseline/VSWD.dll`) |
| 9 | same key | `DependOnService` | `RpcSs`, `SamSs`, `EventLog`, `ProfSvc` (REG_MULTI_SZ) | `wdServiceDependencies`, `.cctor` |
| 10 | same key | `Description` | `VSWD` (REG_SZ) | `ProtectWatchdogService` IL @0x10002654 |
| 11 | same key | `ImagePath` | `c:\Program Files\CE\VSWD.exe` (REG_SZ) | literal, same method |
| 12 | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VSWD\Security` | `Security` | 208-byte REG_BINARY self-relative SD (owner/group S-1-5-18; SYSTEM `0x2001FD` + Administrators `0x000F01FF` full; Authenticated Users/S-1-5-6/S-1-5-4 `0x0002009D` query-class; one SYSTEM_AUDIT ACE on S-1-1-0) | blob `4F1CCAE7…`, VA `0x10002060`; tuple built as `key + "\Security"` in `ProtectCommonServiceSettings` |
| 13 | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VictoryShieldCommService` | `Start` | `2` | as #3 |
| 14 | same key | `Type` | `16` | as #4 |
| 15 | same key | `WOW64` | `332` | as #5 |
| 16 | same key | `ErrorControl` | `1` | as #6 |
| 17 | same key | `ObjectName` | `LocalSystem` | as #7 |
| 18 | same key | `FailureActions` | same 44-byte blob as #8 | as #8 |
| 19 | same key | `DependOnService` | `RpcSs`, `SamSs`, `ProfSvc`, `Afd`, `Tcpip`, `nsi`, `Dhcp`, `Dnscache` (REG_MULTI_SZ) | `commServiceDependencies`, `.cctor` |
| 20 | same key | `Description` | `Communicates between Victory Shield processes and servers.` (REG_SZ) | `ProtectCommService` IL @0x100026f8 |
| 21 | same key | `ImagePath` | `c:\Program Files\CE\VictoryShieldCommService.exe` (REG_SZ) | same method |
| 22 | `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VictoryShieldCommService\Security` | `Security` | same 208-byte SD blob as #12 | as #12 |

(Rows are per value; #3–#12 = 10 protectors for `Services\VSWD`, #13–#22 = 10 for
`Services\VictoryShieldCommService` — plus #1/#2 = **22 value-protectors total**; the list is
exactly `registrySettingsToProtect_`'s tuples: 2 autostart + (7 values + `\Security` value) × 2
services = 22. `registryProtectors_` is created with capacity 2 but holds 22 — the capacity is
just a `List` hint.)

FailureActions decode (evidence: blob bytes above):
`dwResetPeriod = 0xFFFFFFFF` (never reset), `lpRebootMsg = lpCommand = 0`,
`cActions = 3`, action-array offset 0x14, then 3 × `{ Type = 1 (SC_ACTION_RESTART), Delay = 0x3E8
(1000 ms) }` — the SCM-recovery "RESTART ×3 @1 s" policy, written and restored as a value.

### Protected filesystem paths (FP) — complete table

| # | Path | Watcher | ACL applied | Evidence |
|---|---|---|---|---|
| 1 | `C:\Program Files\CE\` — `AppDomain.CurrentDomain.BaseDirectory` of the service | `FileSystemWatcher`, recursive, `NotifyFilter = 256` (Security) | Everyone Allow `0x20089` (read-data/EA/attrs + READ_CONTROL) and Everyone **Deny `0x10040` (DELETE \| DELETE_CHILD)**, applied to the folder and (NoPropagateInherit) first-level children; ACL protected from inheritance; every file re-inherited recursively | `ProtectFolders` IL @0x10002c3c; `SetFolderSecurity` IL @0x10003fcc; `MonitorFolder` IL @0x10004084 |

That is the only path (folderProtectors_ capacity 1, one `FolderProtector`).

### Key excerpts / addresses

- `WatchdogService.RegistryProtector::RepairRegistryEntry` IL @0x10004e00 —
  `"Anomaly Detected.  Repairing ["` (string @0x1000d8ee) + `key.Name + "\" + valueName + " with " +
  savedValue + "]"`, then `SetValue(valueName, savedValue_, savedValueKind_)`.
- `WatchdogService.RegistryProtector::set_Enabled` IL @0x10004ce0 (snapshot/force-rewrite;
  `"Enable Registry Protector("` error log @0x1000d8b8).
- `RegistryUtils.RegistryMonitor::ThreadLoop` IL @0x100034b8 (`RegNotifyChangeKeyValue`
  async + `WaitAny`).
- `WatchdogService.FolderProtector::{Enable,Disable,SetFolderSecurity,MonitorFolder,OnChanged}`
  IL @0x10003f10/0x10003f74/0x10003fcc/0x10004084/0x1000414c;
  `"Fail Enable Folder Protector("` @0x1000d3c0, `"OnChanged("` / `"File Watch Failure"`.
- `FileUtilities.FolderUnprotector::UnprotectFolderSecurity` IL @0x10003840
  (`"UFS Fail - "` / `"UFS complete for "` @0x1000d…); `FolderUtilities::TakeOwnership` IL
  @0x10003904; `ResetFileInheritancePermissions` IL @0x100039dc; `TraverseTree` IL @0x10003af4.
- `WatchdogService.WatchdogControl::disableFileProtection` IL @0x1000519d /
  `disableRegistryProtection` IL @0x100051ab; native exports @0x100101ee / @0x100101fa
  (`disassemble_bytes`: `MOV RAX, [0x10012000]; JMP RAX` / `MOV RAX, [0x10012008]; JMP RAX`).
- Privilege blobs: `(SeTakeOwnershipPrivilege=29, SeBackupPrivilege=2, SeRestorePrivilege=22)`
  at `VSWD.dll` VA `0x10002160` (private implementation data, extracted from
  `re/samples/00-baseline/VSWD.dll`); privilege-name table
  `ProcessPrivileges.Privileges::.cctor` IL @0x100059d8 maps enum → `Se*` names.
- vs-config.exe call sites: `FUN_14008e690` @0x14008e690 (export invoker),
  `FUN_140018d30` @0x140018d30 (`disableWatchdogProtection`),
  strings `VSWD.dll` @0x140398950, `disableFileProtection` @0x1403989a0,
  `disableRegistryProtection` @0x1403989b8.
- `NotifyFilters.Security = 256`: Microsoft docs,
  https://learn.microsoft.com/en-us/dotnet/api/system.io.notifyfilters (2026-09-24).

## Linux-reimplementation notes

- **RP** ≈ an integrity daemon holding expected config values in its own (root-owned) memory and
  restoring them on change events. On Linux the natural mechanism is `inotify` on the config
  file(s) or `fanotify` + rewrite; CE's 1-second debounce is worth copying (change bursts collapse
  to one repair). Do **not** keep the expected state in the watched location.
- **FP** ≈ making the install dir non-deletable by non-root: `chattr +i` on critical binaries, or
  `chmod` root-owned `a-w`/`a-rx` with the directory write-protected; Linux has no direct ACL
  analog of "Everyone deny delete but allow read" (`ext4` immutable flags come closest; a
  periodic re-check loop can mirror the FileSystemWatcher re-lock).
- CE never deletes foreign files found in protected areas and never kills processes — the
  protection is passive (ACL + restore). If LustLess wants stronger guarantees (e.g. removing
  unknown executables from its own directory), document it explicitly — that is a policy CE does
  not implement.
- The admin toggle should be a documented, authenticated control path (CE: SCM custom command 243
  + exported functions called by the config tool). CE's `disableRegistryProtection` export is
  effectively inert outside the service (see above) — don't copy that; make the toggle actually
  operate on the live protector set (CE's command 243 does).
- Timestamps/registry are Windows-isms; the portable core is: watched scope + known-good values +
  event-driven restore + debounced repair + "unprotect" used only for upgrade/uninstall.

## Open questions

- The six path strings passed by `vs-config.exe` to `disableRegistryProtection`
  (`DAT_14041f288/14041f2a8/14041f2c8/14041f268/14041f248/14041f1e8`) are runtime-initialized
  `std::wstring`s not recoverable from the file; the 4+legacy-2 mapping is [INFERENCE].
- Is the `RegistryProtector` subkey-ACL path (`valueName == ""` → `ProtectSubkey`) reachable from
  any other caller (e.g. an older CE generation or another binary referencing `VSWD.dll`)? Within
  these five programs it is unused.
- Exact effect of `NotifyFilter = Security` vs .NET Framework's ReadDirectoryChangesW filter
  mapping on older Windows: [INFERENCE] Created/Deleted events may additionally fire on file
  creation regardless of the filter in some .NET versions — the repair is idempotent either way.
- Whether `OnRenamed`'s no-op is deliberate (renaming an object inside the tree does not re-lock;
  the next security event does).
- Who (besides custom command 243/`OnShutdown`) ever sends `sc control VSWD 243`/`176` in
  production flows — the installer path is inferred from `vs-config.exe` strings only.
