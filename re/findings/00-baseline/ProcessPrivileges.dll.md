# ProcessPrivileges.dll — baseline

## What it does

**Third-party .NET library, not Covenant Eyes-authored code.** "Process Privileges" v1.5.7.0 by **Nick Lowe (2009)** — a C# assembly of `System.Diagnostics.Process` extension methods that query/enable/disable/remove Windows process token privileges (`SeDebugPrivilege`, `SeBackupPrivilege`, …) via Win32 interop. CE bundles and Authenticode-signs this library inside `C:\Program Files\CE\` (signer is Covenant Eyes, Inc.; the copyright remains Nick Lowe's). Original home: CodePlex `processprivileges.codeplex.com` (defunct); community mirror `github.com/ViRb3/ProcessPrivileges` [INFERENCE: permissive-era CodePlex licensing (MS-PL/MIT) is likely but unverified — do NOT copy this code into LustLess; reimplement privilege handling from the OS API docs].

## Mechanism

### Metadata

| Field | Value | Source |
|---|---|---|
| Source path | `C:\Program Files\CE\ProcessPrivileges.dll` (34,240 bytes) | VM file |
| Language | `x86:LE:32:default` (x86, 32-bit!), compiler spec `windows` — Ghidra reports Compiler `cli` (managed CIL assembly with native bootstrap stub) | Ghidra `get_metadata`/`get_program_options` |
| Image base | `0x10000000` | Ghidra `list_open_programs` |
| Format / layout | PE (CLI), SectionAlignment 8192 | Ghidra `get_program_options` |
| Functions | 62 (post-analysis; analysis time 31.5 s) | Ghidra `analysis_status`, `get_program_options` |
| PE TimeDateStamp | `1555959462` → 2019-04-22 18:57:42 UTC (much older than the 2026-07-08 CE build session — the library was built once and reused) | PE header `e_lfanew+8` |
| Authenticode signer | `CN="Covenant Eyes, Inc.", O="Covenant Eyes, Inc.", …` (CE re-signed the third-party DLL) | `Get-AuthenticodeSignature` |
| MD5 / SHA256 | `d0c5ba5e92fcca2d615b8cbcaf06faa1` / `08c88d039da97f245ffa3c34810066a43b895fb2f0483ec519d3ea2e38d646f8` | Ghidra `get_program_options` |
| PDB | `ProcessPrivileges.pdb`, RSDS GUID `afe77a73-8523-4070-bfa3-62c00a907ea4`, age 1 | Ghidra `get_program_options` |
| Version info | FileDescription `Process Privileges`; FileVersion/Assembly Version `1.5.7.0`; InternalName/OriginalFilename `ProcessPrivileges.dll`; LegalCopyright `Copyright © Nick Lowe 2009`; Comments `Implements the functionality necessary to query, enable, disable or remove privileges on a process.` | Ghidra `get_program_options` |

### Imports grouped by DLL

Native PE import table is the .NET bootstrap stub only — 1 import total (Ghidra `list_imports` = 1; `list_external_locations`):

| DLL | Import | IAT address |
|---|---|---|
| **MSCOREE.DLL** | `_CorDllMain` (CLR hosting entry) | `0x000070f8` |

Managed layer (not represented in the native import table; observed in .NET metadata strings of the file copy at `re/samples/00-baseline/ProcessPrivileges.dll`, file offsets): P/Invoke targets **`advapi32.dll`** (offset `0x4bc0`) and **`kernel32.dll`** (offset `0x4bd9`) — i.e., the privilege logic calls `AdjustTokenPrivileges`/`LookupPrivilegeValue`-class APIs through interop. [INFERENCE: exact P/Invoke set not enumerated here; named interop surface is `advapi32` + `kernel32` per metadata strings.]

Category scan of the native import surface: no networking, no crypto, no injection, no service-control, no IOCTL, no GDI, no browser — all such behavior would be in managed/P-Invoke code.

### Exports (Ghidra `list_exports`)

| Export | Address |
|---|---|
| `entry` (CLI entry point stub) | `0x10007116` |

No named native exports; the public surface is the managed API (process privilege extension methods) visible only through .NET metadata.

### Representative strings

Ghidra `list_strings` (native data) — 2 total:

| Address | String | Category |
|---|---|---|
| `0x100070fa` | `_CorDllMain` | import name |
| `0x10007106` | `mscoree.dll` | import DLL name |

.NET metadata strings (UTF-16 literals in CIL metadata heaps — richer than native strings; VAs mapped from the PE section table of `re/samples/00-baseline/ProcessPrivileges.dll`, image base `0x10000000`):

| Address | String | Category |
|---|---|---|
| `0x10005906`–`0x10005f5c` | `SeAssignPrimaryTokenPrivilege`, `SeAuditPrivilege`, `SeBackupPrivilege`, `SeChangeNotifyPrivilege`, `SeCreateGlobalPrivilege`, `SeCreatePagefilePrivilege`, `SeCreatePermanentPrivilege`, `SeCreateSymbolicLinkPrivilege`, `SeCreateTokenPrivilege`, `SeDebugPrivilege` (`0x10005abc`), `SeEnableDelegationPrivilege`, `SeImpersonatePrivilege` (`0x10005b16`), `SeIncreaseBasePriorityPrivilege`, `SeIncreaseQuotaPrivilege`, `SeIncreaseWorkingSetPrivilege`, `SeLoadDriverPrivilege` (`0x10005bf2`), `SeLockMemoryPrivilege`, `SeMachineAccountPrivilege`, `SeManageVolumePrivilege`, `SeProfileSingleProcessPrivilege`, `SeRelabelPrivilege`, `SeRemoteShutdownPrivilege`, `SeRestorePrivilege`, `SeSecurityPrivilege`, `SeShutdownPrivilege`, `SeSyncAgentPrivilege`, `SeSystemEnvironmentPrivilege`, `SeSystemProfilePrivilege`, `SeSystemtimePrivilege`, `SeTakeOwnershipPrivilege`, `SeTcbPrivilege` (`0x10005eb2`), `SeTimeZonePrivilege`, `SeTrustedCredManAccessPrivilege`, `SeUndockPrivilege`, `SeUnsolicitedInputPrivilege` | full privilege-name table (second copy at `0x10006251`+) |
| `0x100069c0` / `0x100069d9` | `advapi32.dll` / `kernel32.dll` | P/Invoke targets |
| `0x1000814c` | `Implements the functionality necessary to query, enable, disable or remove privileges on a process.` | version-resource comment |
| `0x10008260`, `0x100082a8`, `0x1000833e`, `0x10008484` | `Process Privileges`, `1.5.7.0`, ` Nick Lowe 2009`, `1.5.7.0` (Assembly Version) | version resource |

No URLs/IPs, no named pipes, no mutexes, no service names, no registry keys.

## Evidence

- Ghidra MCP (project `CE`, program `ProcessPrivileges.dll`): `get_program_options("Program Information")` (30 options incl. hashes/PDB/version info), `list_imports` (1), `list_external_locations` (1: `MSCOREE.DLL!_CorDllMain` @ `0x000070f8`), `list_exports` (1: `entry` @ `0x10007116`), `list_strings` (2), `analysis_status` (analyzed, 62 functions).
- VM command output (2026-09-24): `ProcessPrivileges.dll | ts=1555959462 | 2019-04-22 18:57:42Z | signer=CN="Covenant Eyes, Inc.", …`
- Local sample copy `re/samples/00-baseline/ProcessPrivileges.dll` (pulled via `scp`, 34,240 B) + `strings -el -t x` output (privilege table, P/Invoke DLL names, version resource) as tabulated.
- Web research (2026-09-24): "Process Privileges" is Nick Lowe's CodePlex-era C# library; mirror `https://github.com/ViRb3/ProcessPrivileges`; used by NTFSSecurity/autorunner. Exact license unverified.
- Checkpoint: `C:\Users\dolphin\ghidra-ckpt\ProcessPrivileges.dll.gzf` (196,460 B) + project `CE:/ProcessPrivileges.dll` (saved).

## Linux-reimplementation notes

This is Windows token-privilege plumbing with **no** accountability semantics. LustLess must not port it (third-party code, unclear license). On Linux the nearest analog is capabilities (`cap_get_proc`/`cap_set_proc` from libcap) — likely unnecessary for LustLess [INFERENCE: the CE client uses this to grant its service/agent components debug/backup rights when manipulating other processes; a plain user-mode Linux agent needs nothing similar].
