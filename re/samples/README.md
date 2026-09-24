# samples/ — pulled binaries (gitignored)

Pulled 2026-09-24 from the research VM (`DESKTOP-6LK4SCA`):

- `C:\Program Files\CE\{VictoryShieldClassifier,VictoryShieldCommService,VictoryShield,vs-config,RestartVS,RestartVSClientOnly,VSWD}.exe`,
  `C:\Program Files\CE\{UWPApp,VSWD,ProcessPrivileges}.dll`
- `C:\Windows\System32\drivers\CEA.sys`

Note: `CEA.sys` turned out to be a **stock Microsoft file** (Event Aggregation kernel-mode
library, byte-identical to the WinSxS copy — see `findings/01-dynamic-recon/live-surface.md`
§a). Kept only as evidence of the misidentification; it is NOT a Covenant Eyes binary and
was only ever analyzed in Ghidra as the stock Microsoft component it is.

All sizes match the VM listing; hashes verified against the VM's `Get-FileHash -Algorithm SHA256`
output — see `MANIFEST.sha256` (committed). Binaries themselves are NOT committed
(proprietary Covenant Eyes code; research reference only). `data/` and `runtime/` hold
gitignored scratch copies for format/behavior analysis.
