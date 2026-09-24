# Covenant Eyes / Victory Shield — Reverse Engineering Workspace

Reverse-engineering record for Covenant Eyes Windows client **"Victory Shield" v10.1.44**,
produced to support a clean-room Linux accountability client (LustLess). Research notes only —
no Covenant Eyes code is redistributed here.

## Layout

| Path | Contents |
|---|---|
| `PROGRESS.md` | Master progress tracker (orchestrator-owned; do not edit from subagents) |
| `INVENTORY.md` | Complete observed surface: binaries, services, registry, files, network |
| `findings/NN-*/` | Per-subsystem RE writeups, one phase per folder |
| `samples/` | Pulled binaries + `MANIFEST.sha256` (binaries are gitignored) |

## Evidence rules

Every claim in findings MUST cite evidence: Ghidra address/function name, file path,
registry key, log excerpt, or captured command output. Mark inference explicitly as
`[INFERENCE]`. Speculation without evidence does not belong in these docs.

## Environment access

- Windows VM (admin): `ssh dolphin@100.99.219.44 '<powershell>'`
  - Default shell is **PowerShell**: no `&&`, use `;`. Local shell expands `$` — keep remote
    commands in **single quotes** locally (`'... $_.Name ...'`).
  - Add `-o ControlPath=none` for concurrent SSH sessions.
- Ghidra headless MCP runs **on the Windows VM** (bridge `127.0.0.1:8089`).
  - Tools are invoked by writing JSON args to `xd://mcp__win_ghidra_mcp_<tool>`;
    read `xd://mcp__win_ghidra_mcp_<tool>` for the schema first.
  - **Always pass the `program` argument** (multiple programs are open over time).
  - Binaries live at `C:\Program Files\CE\`; programmatic data at `C:\ProgramData\CovenantEyes\`.

## Ghidra mutation policy

Only the intake pass imports/analyzes programs. All RE passes are read-only on Ghidra:
no import, no program switch, no re-analysis, no renames that break shared analysis state
(rename only within your own pass and record old→new in your findings file).

## Conventions

- Findings: Markdown, `findings/<phase>/<topic>.md`. Open with a "What it does" summary,
  then mechanism, then evidence, then Linux-reimplementation notes.
- Do not run linters/formatters/tests; do not commit to git. The orchestrator verifies and commits.
