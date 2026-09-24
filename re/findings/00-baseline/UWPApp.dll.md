# UWPApp.dll — baseline

## What it does

A **C++/WinRT UWP XAML "island" DLL** hosting the Victory Shield **sign-in UI**: implements WinRT class `UWPApp.SignInControl` (XAML `ms-appx:///SignInControl.xaml` with `RootGrid`, `passwordInput`, "switch users") plus `UWPApp.App` and `UWPApp.XamlMetaDataProvider`. Built on the Microsoft.Toolkit.Win32 `XamlHost` pattern (XAML hosting from Win32), themed image loading (`LoadImageBasedOnTheme`), WinRT crypto (`Windows.Security.Cryptography.CryptographicBuffer`). This is the login/account-switch dialog surface of the CE client.

## Mechanism

### Metadata

| Field | Value | Source |
|---|---|---|
| Source path | `C:\Program Files\CE\UWPApp.dll` (482,240 bytes) | VM file |
| Language | `x86:LE:64:default` (x86-64), Compiler `visualstudio:unknown` (C++/WinRT, RTTI present) | Ghidra `load_program`, `get_program_options` |
| Image base | `0x180000000` | Ghidra `list_open_programs` |
| Functions | 829 (post-analysis; analysis time 99.1 s) | Ghidra `analysis_status`, `get_program_options` |
| PE TimeDateStamp | `1783516863` → 2026-07-08 13:21:03 UTC | PE header `e_lfanew+8` |
| Authenticode signer | `CN="Covenant Eyes, Inc.", O="Covenant Eyes, Inc.", L=Owosso, S=…` | `Get-AuthenticodeSignature` |
| MD5 / SHA256 | `cc7e9ca360cfae147839aae97737f6d7` / `3e12da40df8def21c4eedbe93e207663df420fd932cb83ca2bf5fe632d6b406e` | Ghidra `get_program_options` |
| PDB | `UWPApp.pdb`, RSDS GUID `59a6266a-fb6f-4691-a9b6-a1f5fbe124c2`, age 1 | Ghidra `get_program_options` |
| Version info | CompanyName `Covenant Eyes`; FileDescription/ProductName `Victory Shield`; FileVersion `10.1.44`; InternalName/OriginalFilename `UWPApp.dll` | Ghidra `get_program_options` |
| Toolchain traces | `C++/WinRT version:2.0.240405.15` (`0x180043010`); build paths `D:\actions-runner\_work\w\p\x64\UWPApp\Generated Files\winrt\…` (GitHub Actions runner) | strings |

### Imports grouped by DLL

83 native imports (Ghidra `list_imports` total 83; `list_external_locations` returned 90 rows including ordinal aliases, grouped by library). By DLL:

- **KERNEL32.DLL** (11): `WakeAllConditionVariable`, `SleepConditionVariableSRW`, `AcquireSRWLockExclusive`, `ReleaseSRWLockExclusive`, `InitializeSListHead`, `InterlockedPushEntrySList`/`FlushSList` (API-MS-WIN-CORE-INTERLOCKED), `GetSystemTimeAsFileTime`, `GetCurrentProcessId`, `GetCurrentThreadId`, `QueryPerformanceCounter`, `DisableThreadLibraryCalls`
- **OLEAUT32.DLL** (4, by ordinal): `SysFreeString` (Ordinal_6), `SysStringLen` (Ordinal_7), `GetErrorInfo` (Ordinal_200), `SetErrorInfo` (Ordinal_201) — WinRT/BSTR interop
- **MSVCP140.DLL** (8): `__ExceptionPtr*` family, `_Thrd_yield`
- **VCRUNTIME140.DLL / VCRUNTIME140_1.DLL** (12): `__CxxFrameHandler4`, `__C_specific_handler`, `_CxxThrowException`, `__std_*`, `memcpy`/`memset`/`memcmp`, `_purecall`
- **API-MS-WIN-CRT-{RUNTIME,STRING,HEAP}-L1** (22): `abort`, `_initterm`, `malloc`/`free`, `strlen`/`wcslen`/`wcscmp`, `isalnum`…
- **API-MS-WIN-CORE-WINRT-*** : `RoGetActivationFactory` (`0x00054c38`), `RoGetAgileReference`, `RoOriginateLanguageException`, `RoTransformError`, `RoFailFastWithErrorContext`
- **API-MS-WIN-CORE-COM-L1-1-0/1**: `CoTaskMemAlloc`/`Free`, `CoGetObjectContext`, `CoGetApartmentType`, `CoCreateFreeThreadedMarshaler`, `CoIncrementMTAUsage` (via `combase.dll` string)
- **API-MS-WIN-CORE-{HEAP,STRING,LIBRARYLOADER,ERRORHANDLING,THREADPOOL,SYNCH,UTIL}-*** : `HeapAlloc`/`HeapFree`, `WideCharToMultiByte`, `LoadLibraryExW`, `GetProcAddress`, `FreeLibrary`, `GetLastError`, `TrySubmitThreadpoolCallback`, critical sections, `EncodePointer`

Category scan: **crypto present via WinRT** — `Windows.Security.Cryptography.CryptographicBuffer` type name (`0x180041860`) [INFERENCE: used for sign-in token/nonce handling]. UI: XAML/UIElement surface (hundreds of WinRT type names). No network socket imports, no service control, no injection, no GDI/BitBlt, no browser APIs.

### Exports (Ghidra `list_exports`, 7 entries = 4 named + 3 ordinal aliases)

| Export | Address | Note |
|---|---|---|
| `DllGetActivationFactory` | `0x180016630` | WinRT activation factory (XAML island entry) |
| `VSDesignerCanUnloadNow` | `0x180016640` | module lifetime (name suggests VS XAML-designer template ancestry [INFERENCE]) |
| `VSDesignerDllMain` | `0x180016700` | DLL entry shim |
| `entry` | `0x1800198c0` | PE entry |

### Representative strings (with addresses)

Ghidra `list_strings` (549 total; selected):

| Address | String | Category |
|---|---|---|
| `0x180020c48` | `UWPApp.SignInControl` | WinRT class (the sign-in control) |
| `0x180043108` | `UWPApp.App` | WinRT application class |
| `0x180043540` | `UWPApp.XamlMetaDataProvider` | XAML type metadata |
| `0x180043af0` | `ms-appx:///SignInControl.xaml` | XAML UI definition URI |
| `0x1800419f0` | `RootGrid` | XAML element name |
| `0x180041a28` | `passwordInput` | XAML element name (password box) |
| `0x180041a08` | `switch users` | UI label |
| `0x180041860` | `Windows.Security.Cryptography.CryptographicBuffer` | WinRT crypto API |
| `0x180043d68` | `Windows.Foundation.Uri` | WinRT URI type |
| `0x180042020` | `Windows.Foundation.IAsyncOperation\`1<Windows.UI.Xaml.Media.Imaging.BitmapImage>` | async image loading |
| `0x180043010` | `C++/WinRT version:2.0.240405.15` | toolchain version |
| `0x180020a40` | `D:\actions-runner\__work\w\p\x64\UWPApp\Generated Files\winrt\base.h` | CI build path |
| `0x180043580` | `D:\actions-runner\_work\w\p\x64\UWPApp\Generated Files\module.g.cpp` | CI build path |
| `0x180020aa0` | `combase.dll` | runtime-load target |
| `0x1800548fa` | `KERNEL32.dll` | import DLL name |
| `0x180054d8a` | `OLEAUT32.dll` | import DLL name |

No URLs/IPs, no named pipes, no mutexes, no service names, no registry keys in the string set.

## Evidence

- Ghidra MCP (project `CE`, program `UWPApp.dll`): `get_program_options("Program Information")` (28 options), `list_imports` (total 83), `list_external_locations` (90 rows incl. ordinal aliases), `list_exports` (7), `list_strings` (549 total; 400 fetched) — addresses as tabulated.
- VM command output (2026-09-24): `UWPApp.dll | ts=1783516863 | 2026-07-08 13:21:03Z | signer=CN="Covenant Eyes, Inc.", …`
- Checkpoint: `C:\Users\dolphin\ghidra-ckpt\UWPApp.dll.gzf` (1,680,709 B) + project `CE:/UWPApp.dll` (saved).

## Linux-reimplementation notes

The sign-in UI has no direct Linux analog requirement for LustLess (accountability clients typically authenticate via browser/OIDC or a CLI). [INFERENCE] If a native sign-in surface is wanted, `SignInControl` semantics (password entry + user switching + themed branding) are the spec; note CE performs crypto in the UI layer via WinRT `CryptographicBuffer`. The XamlHost/WinRT machinery is Windows-only and irrelevant to porting.
