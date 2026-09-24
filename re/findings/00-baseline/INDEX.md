# 00-baseline — Ghidra baseline inventory (Victory Shield 10.1.44)

Ghidra project `CE` on the Windows VM (`C:\Users\dolphin\ghidra_projects\CE.gpr`), headless MCP server `GhidraMCP-Headless` on `127.0.0.1:8089`. All 11 binaries imported, auto-analyzed, and left **open** in the project; each also checkpointed as `.gzf` under `C:\Users\dolphin\ghidra-ckpt\`.

## Inventory

| Program | Source path | Image base | Functions | Analysis complete | Authenticode signer | Checkpoint (.gzf) | Baseline doc |
|---|---|---|---|---|---|---|---|
| CEA.sys | `C:\Windows\System32\drivers\CEA.sys` | `0x140000000` | 233 | yes | **CN=Microsoft Windows, O=Microsoft Corporation** — STOCK WINDOWS COMPONENT, not Covenant Eyes | yes | [CEA.sys.md](./CEA.sys.md) |
| ProcessPrivileges.dll | `C:\Program Files\CE\ProcessPrivileges.dll` | `0x10000000` | 62 | yes | CN="Covenant Eyes, Inc." (third-party code inside — Nick Lowe 2009, built 2019) | yes | [ProcessPrivileges.dll.md](./ProcessPrivileges.dll.md) |
| VSWD.exe | `C:\Program Files\CE\VSWD.exe` | `0x00400000` | 110 | yes | CN="Covenant Eyes, Inc." | yes | [VSWD.exe.md](./VSWD.exe.md) |
| VSWD.dll | `C:\Program Files\CE\VSWD.dll` | `0x10000000` | 186 | yes | CN="Covenant Eyes, Inc." | yes | [VSWD.dll.md](./VSWD.dll.md) |
| UWPApp.dll | `C:\Program Files\CE\UWPApp.dll` | `0x180000000` | 829 | yes | CN="Covenant Eyes, Inc." | yes | [UWPApp.dll.md](./UWPApp.dll.md) |
| vs-config.exe | `C:\Program Files\CE\vs-config.exe` | `0x140000000` | 13,287 | yes | CN="Covenant Eyes, Inc." | yes | [vs-config.exe.md](./vs-config.exe.md) |
| RestartVS.exe | `C:\Program Files\CE\RestartVS.exe` | `0x140000000` | 11,543 | yes | CN="Covenant Eyes, Inc." | yes | [RestartVS.exe.md](./RestartVS.exe.md) |
| RestartVSClientOnly.exe | `C:\Program Files\CE\RestartVSClientOnly.exe` | `0x140000000` | PENDING | PENDING | CN="Covenant Eyes, Inc." | PENDING | [RestartVSClientOnly.exe.md](./RestartVSClientOnly.exe.md) |
| VictoryShield.exe | `C:\Program Files\CE\VictoryShield.exe` | PENDING | PENDING | PENDING | CN="Covenant Eyes, Inc." | PENDING | [VictoryShield.exe.md](./VictoryShield.exe.md) |
| VictoryShieldCommService.exe | `C:\Program Files\CE\VictoryShieldCommService.exe` | PENDING | PENDING | PENDING | CN="Covenant Eyes, Inc." | PENDING | [VictoryShieldCommService.exe.md](./VictoryShieldCommService.exe.md) |
| VictoryShieldClassifier.exe | `C:\Program Files\CE\VictoryShieldClassifier.exe` | PENDING | PENDING | PENDING | CN="Covenant Eyes, Inc." | PENDING | [VictoryShieldClassifier.exe.md](./VictoryShieldClassifier.exe.md) |

## Headline findings

- **`CEA.sys` is a stock Windows component** — Microsoft-signed `EventAggregation.sys` (Event Aggregation Kernel Mode Library, version = host OS build 10.0.26100.9444), byte-identical to the WinSxS `microsoft-windows-eventaggregation` copy (independent corroboration: `re/findings/01-dynamic-recon/live-surface.md` §a). **Not Covenant Eyes; do not RE as CE** — the "CEA" acronym is not "Covenant Eyes Agent". Wave-B passes should skip it.
- `ProcessPrivileges.dll` is **third-party code** ("Process Privileges" v1.5.7.0, © Nick Lowe 2009, CodePlex-era; mirror `github.com/ViRb3/ProcessPrivileges`) bundled and re-signed by CE. Do not port it into LustLess (license unverified); reimplement any needed privilege handling from OS API docs.
- The other 9 binaries are Covenant Eyes, Inc. signed; PE TimeDateStamp cluster 2026-07-08 13:17–13:36 UTC (single build session; `ProcessPrivileges.dll` excepted at 2019-04-22).

## Infra notes (session 2026-09-24)

- Ghidra runs headless via scheduled task `GhidraMCP-Headless` → `C:\Users\dolphin\tools\run-headless.ps1` (java `-Xmx4g -XX:+UseG1GC`, jar `ghidra-mcp/target/GhidraMCP-7.0.0.jar`, port 8089). Session fixes applied to that launcher: stdout/stderr now redirect to `C:\Users\dolphin\headless.log` (the task's `-File` invocation previously swallowed `>>`), and heap left at `-Xmx4g`.
- The server is memory-resident; programs persist via the Ghidra project `C:\Users\dolphin\ghidra_projects` (`CE.gpr`/`CE.rep`) created during this session (`create_project` places `.gpr`/`.rep` directly in the given parent dir). Per-program `.gzf` checkpoints in `C:\Users\dolphin\ghidra-ckpt\` (mandatory protocol) — after a JVM crash these restore full analysis state via `import_program` + reopen, verified end-to-end.
- Two JVM crashes occurred (13:05 and 13:52), both **native OutOfMemoryError: G1 virtual-space mmap failure** (machine commit exhaustion, `hs_err_pid797680.log` / `hs_err_pid797268.log`) while several big binaries were being loaded/analyzed concurrently. Mitigation adopted: strictly one program at a time (load → analyze → save → export), `-Xmx4g`, checkpoint after each.
- `import_file` is GUI-only in this bridge; the working headless path is `load_program` (import into open project) + `reanalyze`. `load_program` dedupes by open program name — a pre-project in-memory instance must be `close_program`'d and re-imported to become project-located (`save_program` errors on transient DomainFileProxy otherwise).
