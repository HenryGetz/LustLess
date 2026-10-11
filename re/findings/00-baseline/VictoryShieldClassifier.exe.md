# VictoryShieldClassifier.exe — baseline

## What it does

The **Victory Shield Classifier** — the content/URL classification engine (53 MB, MSVC++ with heavy CRT math and the Concurrency Runtime). It queries the local CE SQLite schemas directly (raw SQL strings): **`userdb.install_metadata`** (`unique_device_id`), **`logdb.logins`** (who is logged in right now), **`userdb.telemetry`**. Uses CryptoAPI/BCrypt (including `BCryptOpenAlgorithmProvider` and hash/sign APIs — [INFERENCE] for signed model/config verification), Winsock (mostly ordinal imports), Event Log reporting, and has an interactive `GetSaveFileNameA` dialog ([INFERENCE] diagnostics/model export).

## Mechanism

### Metadata

| Field | Value | Source |
|---|---|---|
| Source path | `C:\Program Files\CE\VictoryShieldClassifier.exe` (52,962,752 bytes) | VM file |
| Language | `x86:LE:64:default` (x86-64, machine `0x8664`), Compiler `visualstudio:unknown` — native C++ (MSVCP140/CONCRT140, CRT math-heavy) | PE header |
| Image base | `0x140000000` | PE header |
| Functions | **47,830** (post-analysis, 2026-09-27) | Ghidra `analysis_status` |
| PE TimeDateStamp | `1783516667` → 2026-07-08 13:17:47 UTC (first binary of the build session) | PE header `e_lfanew+8` |
| Authenticode signer | `CN="Covenant Eyes, Inc.", O="Covenant Eyes, Inc.", L=Owosso, S=…` | `Get-AuthenticodeSignature` |
| MD5 / SHA256 | `8f885384a479010a5a89bfc180a48110` / `fc8dc7d1134457577e387e2b593dd5ca0e63bb7de0a42fee2afe7bb6a6b1b136` | local hash of `re/samples/00-baseline/VictoryShieldClassifier.exe` |
| PDB | `VictoryShieldClassifier.pdb`, RSDS GUID `8d032c5f-ca53-499c-ab58-d9d66c3a2c5c`, age 1 (build path `D:\actions-runner\_work\w\p\x64\build\Classifier\x64-microsoft-windows\…`) | PE debug directory |
| Version info | CompanyName `Covenant Eyes`; FileDescription/ProductName `Victory Shield Classifier` (`0x14336d764`); FileVersion `10.1.44` | strings / version resource |

### Imports grouped by DLL

755 imports across 26 DLLs (PE import table of the local sample, parsed per DLL).

| DLL | # | Notable APIs |
|---|---|---|
| **MSVCP140.dll** | 224 | C++ standard library (math/string/stream) |
| **KERNEL32.dll** | 155 | file mapping (`CreateFileMappingW`, `MapViewOfFile`, `FlushViewOfFile`), file I/O + locking (`LockFileEx`, `SetFileTime`), `CreateProcessA`, `GetExitCodeProcess`, `GetTempFileNameA` |
| **api-ms-win-crt-math-l1-1-0.dll** | 62 | math runtime ([INFERENCE] numeric/scoring workload) |
| **USER32.dll** | 49 | minimal UI (dialog for `GetSaveFileNameA`) |
| **api-ms-win-crt-stdio/runtime/string** | 43/30/22 | CRT |
| **WS2_32.dll** | 27 | Winsock (imported largely by ordinal) |
| **VCRUNTIME140.dll / VCRUNTIME140_1.dll** | 23 / 1 | CRT |
| **ADVAPI32.dll** | 23 | **CryptoAPI**: `CryptAcquireContextW` (IAT `0x143143f78`), `CryptSignHashW` (`0x143143f28`), `CryptCreateHash` (`0x143143f38`), `CryptDecrypt` (`0x143143f40`), `CryptExportKey` (`0x143143f48`), `CryptGenRandom` (`0x143143f18`), `CryptEnumProvidersW`, `CryptGetUserKey`. **Event log**: `ReportEventW` (IAT `0x143143f80`), `RegisterEventSourceW` (`0x143143f88`). **Registry**: `RegCreateKeyExA`/`RegQueryValueExA`/`RegSetValueExA`/`RegEnumKeyExA`/`RegDeleteKeyA` |
| **CONCRT140.dll** | 19 | Concurrency Runtime (parallel work) |
| **GDI32.dll** | 17 | dialog drawing |
| **api-ms-win-crt-{heap,convert,time,filesystem,locale,utility,environment}** | ~41 | CRT |
| **CRYPT32.dll** | 8 | `CertOpenSystemStoreW` (IAT `0x1431440b8`), `CertOpenStore`, `CertFindCertificateInStore`, `CertEnumCertificatesInStore`, `CertDuplicateCertificateContext`, `CertFreeCertificateContext`, `CertGetCertificateContextProperty`, `CertCloseStore` |
| **bcrypt.dll** | 3 | **`BCryptOpenAlgorithmProvider` (IAT `0x143145750`)**, `BCryptCloseAlgorithmProvider`, `BCryptGenRandom` (`0x143145760`) |
| **WTSAPI32.dll** | 3 | `WTSEnumerateSessionsA`, `WTSQuerySessionInformationW`, `WTSFreeMemory` |
| **COMDLG32.dll** | 1 | **`GetSaveFileNameA` (IAT `0x143143fd8`)** — save dialog (diagnostics/model export) |
| SHELL32 (2), ole32 (1) | | support |

Category scan: **crypto — yes (CryptoAPI sign/decrypt + bcrypt providers)**; **networking — yes (Winsock)**; SQL/SQLite — yes (embedded queries, see strings); Event Log — yes; no service-control imports (runs as a helper process), no screenshot capture, no browser APIs.

### Exports

None — the PE has no export table (console/GUI helper).

### Representative strings (with addresses)

UTF-16 strings VA-mapped from `re/samples/00-baseline/VictoryShieldClassifier.exe` (327 total; selected):

| Address | String | Category |
|---|---|---|
| `0x142a119e0` | `SELECT value FROM userdb.install_metadata WHERE key = 'unique_device_id';` | **SQL — device identity table** |
| `0x142a11a80` | `SELECT username FROM logdb.logins WHERE system_user_name = ? AND logout_at IS NULL ORDER BY id DESC LIMIT 1;` | **SQL — login session table** |
| `0x142a12a50` | `SELECT * FROM userdb.telemetry WHERE key in (?);` | **SQL — telemetry table** |
| `0x14314b878` | `\\?\Global\` | global object-namespace prefix (mutex/file paths) |
| `0x142db7940` | `Intel Hardware Cryptographic Service Provider` | CryptoAPI provider name |
| `0x142db5948` | `Service-0x` | log-format fragment |
| `0x142a442f8` / `0x142a44380` | `kernel32.dll` / `ntdll.dll` | runtime-load targets |
| `0x14336d764` | `Victory Shield Classifier` | version-resource description |
| `0x14336d7e8` | `VictoryShieldClassifier.exe` | version resource |

No URLs/IPs, no named pipes, no mutex names beyond the `\\?\Global\` prefix in the string set.

## Evidence

- Ghidra MCP (project `CE`, program `VictoryShieldClassifier.exe`): `analysis_status` (analyzed=true, **47,830 functions**; discovery waves 36,348 → 38,878 → 39,279 → 41,345 → 46,518 → 47,830), `save_program` (saved to project `CE:/VictoryShieldClassifier.exe`).
- Local sample `re/samples/00-baseline/VictoryShieldClassifier.exe` (scp'd, 52,962,752 B): PE import table parsed per DLL (755 imports / 26 DLLs) with IAT addresses; UTF-16 strings (327) VA-mapped; MD5/SHA256 and RSDS PDB record read from the PE.
- VM command output (2026-09-24): `VictoryShieldClassifier.exe | ts=1783516667 | 2026-07-08 13:17:47Z | signer=CN="Covenant Eyes, Inc.", …`

## Linux-reimplementation notes

The SQL strings are the highest-value artifact here: they document the **local state schema** (`userdb`/`logdb` — device id, logged-in user, telemetry) that any accountability client must maintain. For LustLess, an equivalent SQLite (or state file) needs: device identity, current-login tracking, and telemetry counters — and should treat those as sensitive data (the classifier reads them to attribute activity to a user). The classifier's scoring engine itself is opaque Windows ML/native code [INFERENCE]; a Linux port would implement its own classifier (e.g. URL categorization against a local model) and must document its privacy posture.
