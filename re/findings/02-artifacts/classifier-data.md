# Classifier data files — `C:\ProgramData\CovenantEyes\Classifier`

## What it does

Per-user working state of the on-device URL/page classifier (`CovenantEyesClassifier.exe`, renamed
`VictoryShieldClassifier.exe` in 10.1.44). The tree holds one small text log per classifier process
(lifetime logs named by PID), plus per-user-SID working directories (`cache\`, `data\`) that receive
encrypted/encoded data blobs: a "next update" marker, a hash-table blob, and two timestamped
subdirectories (`data\client\<epoch-ms>`, `data\pdl\<ISO-ts>`) that look like download/work batches.
The classifier reads its model from `C:\Program Files\CE\data` (the `.dat.enc` files, see
`enc-data.md`) and its per-user `--data`/`--cache` directories from this tree.

All samples copied to `re/samples/data/classifier-logs/`, `re/samples/data/classifier-data/`,
`re/samples/data/classifier-pdl/` (hashes below are of the pulled copies).

## Mechanism

### Launch contract (from the logs)

Every run logs its full command line at startup:

```
"C:\Program Files\CE\CovenantEyesClassifier.exe" --version=10.1.1
  --model="C:\Program Files\CE\data"
  --data=C:\ProgramData\CovenantEyes\Classifier\<SID>\data
  --cache=C:\ProgramData\CovenantEyes\Classifier\<SID>\cache
```

- `--version=10.1.1` is a classifier/model version argument (constant across all 14 logs), not the
  client build.
- `--model` points at the install dir's `data\` folder — i.e. the six encrypted `*.dat.enc` model
  files (see `enc-data.md`).
- `--data` / `--cache` point into the per-SID directories documented below.

### Per-SID directory layout

```
C:\ProgramData\CovenantEyes\Classifier\
├── logs\<PID>.txt                      one file per classifier process (lifetime log)
└── S-1-5-21-2224134039-3417563983-3831536026-1001\     ← user SID (dolphin) [INFERENCE]
    ├── cache\bmdat\nxu.dat             32 B  "next update" marker [INFERENCE]
    ├── cache\ssdat\                    empty here [INFERENCE: "site-score"/"safe-search" data cache]
    ├── data\client\1789880113031\      per-batch dir named by UTC epoch-ms
    │   ├── ht.dat                      41,760 B  hash table of classifications [INFERENCE]
    │   └── re4sHXTJFJHReHXTJFJTR.dat   0 B  token-named placeholder [INFERENCE]
    └── data\pdl\2026-09-20T04-55-17.3281948-0\          per-batch dir named by ISO timestamp
        ├── rr.dat                      0 B  [INFERENCE: "result/report" slot]
        └── su.dat                      160 B  [INFERENCE: "status/update" blob]
```

Role inferences (all `[INFERENCE]`, nothing in the logs names these files):

- `cache\bmdat\nxu.dat` (32 B) — "bmdat" ≈ *bundle data*; the only log line referencing bundle state
  is `bundleManager: onTimeUpdate error - Unable to read nextUpdate file` (below), so `nxu` is most
  plausibly the *nextUpdate* timestamp/commitment the bundle manager expects to find. 32 bytes =
  one AES-256 block or a hash [INFERENCE].
- `cache\ssdat\` — empty on this VM; role unknown [INFERENCE: "site score"/"safe search" cache, or a
  staging dir for a second model-family; name only].
- `data\client\1789880113031\` — the directory name is a UTC epoch-ms timestamp:
  `1789880113031 ms = 2026-09-20T04:55:13.031Z` = local `2026-09-19 23:55:13 -05:00`, exactly the
  mtime of `ht.dat` in it. [INFERENCE] one directory per fetched "client data" batch; `ht.dat`
  (41,760 B, entropy 7.996 — high-entropy blob, name ≈ *hash table*) is the batch payload;
  `re4sHXTJFJHReHXTJFJTR.dat` (0 B, 20-char random-looking base name) is a keyed/token-named file
  created as a placeholder (mtime 23:47:24, 8 min before `ht.dat`) [INFERENCE: download slot or
  lock/lease file].
- `data\pdl\2026-09-20T04-55-17.3281948-0\` — the log tag `pdl-edi` matches the `pdl` directory
  name, so this is where the `pdl-edi` subsystem writes [INFERENCE: "pdl" = *pending download
  list*; the subdirectory name is the ISO-8601 UTC instant `2026-09-20T04:55:17.3281948` with `:`
  replaced by `-` plus a trailing `-0` fragment (offset truncated?); it was created 4.30 s after the
  `data\client` batch above]. `su.dat` (160 B = 10×16 B, entropy 6.75) and `rr.dat` (0 B) are its
  payload slots [INFERENCE].

All non-empty data blobs have sizes that are multiples of 16 (41,760 / 32 / 160) and near-maximal
entropy where large — consistent with block-cipher ciphertext [INFERENCE].

### Classifier log format and taxonomy

Plain UTF-8 text, one line per event:

```
YYYY/MM/DD HH:MM:SS.mmm <SEV> <tag>: <message>
```

- Severity codes observed: `MAR` (mark/normal milestones: command line, starting, terminating),
  `WAR` (warnings), `ERR` (errors).
- Tag taxonomy observed across all 14 logs: `Classifier` (lifecycle, DB attach),
  `pdl-edi` (experiment gating, one-time notes), `bundleManager` (bundle update scheduling).
- Lifecycle per process: `Classifier: Command line: …` → `Classifier v10.1.1 is starting` →
  startup warnings → (optional) `pdl-edi` one-time note seconds later → `Classifier v10.1.1 is
  terminating` (graceful runs only).
- SQLite: at every startup, twice: `WAR Classifier: Could not attach to user database SQLite error:
  26` followed by `WAR Classifier: SQLite database connect error`. Error 26 is SQLite's
  `SQLITE_NOTADB` ("file is not a database"). Non-fatal — the run continues [INFERENCE: the
  classifier ATTACHes the per-user `ce-user-file` DB (separate task's scope) at startup and the file
  is absent/locked/not-yet-created at that moment].
- Experiment flags: `WAR pdl-edi: ONE-TIME NOTE: Experimental chance set to 0, no experiments will
  run for this user.` — emitted once per process, 5–40 s after start. [INFERENCE] a per-user
  experiment-assignment roll ("experimental chance") that came out 0, disabling A/B experiments for
  this user; the "ONE-TIME NOTE" wording implies the flag is persisted so the message repeats once
  per process but not once per session.
- Bundle scheduling: `ERR bundleManager: onTimeUpdate error - Unable to read nextUpdate file (might
  not have been created yet)` (only in PID 5028) — the bundle update timer needs a `nextUpdate`
  file (cf. `nxu.dat` [INFERENCE]).

### Runs observed (PID → window)

Chain of runs on 2026-09-18 shows the classifier being restarted back-to-back (each successor starts
within 0.2 s of its predecessor's "terminating" line) [INFERENCE: supervisor/client restart loop].

| log | first ts | last ts | lines | ends with |
|---|---|---|---|---|
| 5028.txt | 2025-11-10 20:05:14.792 | 20:05:20.360 | 8 | `bundleManager` ERR (no terminating) |
| 8400.txt | 2025-11-10 21:49:36.937 | 21:49:46.777 | 7 | pdl-edi note (no terminating) |
| 8852.txt | 2025-11-10 22:01:36.790 | 22:01:46.882 | 7 | pdl-edi note (no terminating) |
| 5516.txt | 2025-11-24 21:02:29.851 | 21:02:40.255 | 7 | pdl-edi note (no terminating) |
| 8680.txt | 2025-12-08 16:42:24.147 | 16:42:34.283 | 7 | pdl-edi note (no terminating) |
| 3080.txt | 2026-09-18 16:10:53.159 | 19:15:15.899 | 8 | `is terminating` |
| 2216.txt | 2026-09-18 19:15:16.527 | 19:37:20.866 | 8 | `is terminating` |
| 10672.txt | 2026-09-18 19:37:21.075 | 19:42:26.018 | 8 | `is terminating` |
| 11392.txt | 2026-09-18 19:42:26.224 | 19:46:29.518 | 8 | `is terminating` |
| 9308.txt | 2026-09-18 19:46:29.798 | 20:15:58.617 | 8 | `is terminating` |
| 9904.txt | 2026-09-18 20:15:58.781 | 22:23:43.356 | 8 | `is terminating` |
| 2232.txt | 2026-09-18 22:23:43.505 | 22:34:55.876 | 8 | `is terminating` |
| 7416.txt | 2026-09-18 22:34:56.000 | 22:35:17.707 | 7 | pdl-edi note (no terminating) |
| 10252.txt | 2026-09-19 00:34:49.550 | 00:35:00.179 | 7 | pdl-edi note (no terminating) |

No classifier log exists after 2026-09-19 00:35, i.e. none from after the 2026-09-21 upgrade to
10.1.44 (which introduced `VictoryShieldClassifier.exe`, see below).

### Binary name: old `CovenantEyesClassifier.exe` vs current `VictoryShieldClassifier.exe`

**All 14 logs** (2025-11-10 → 2026-09-19) were produced by
`"C:\Program Files\CE\CovenantEyesClassifier.exe" --version=10.1.1`. The rename to
`VictoryShieldClassifier.exe` is documented in the 10.1.44 upgrade log, which kills both old and new
names during the cutover (evidence below). On this VM no run of the new binary has been logged yet:
`Classifier\logs\` is unchanged since 2026-09-19 (verified 2026-09-24 via `dir`), and no classifier
process was running at collection time. So the "current" `VictoryShieldClassifier.exe` behavior
beyond its name is `[INFERENCE]` (same CLI contract, new exe name).

## Evidence

### Full listing — `C:\ProgramData\CovenantEyes\Classifier` (2026-09-24; mtimes local −05:00)

| path (relative to root) | type | size | sha256 | last write |
|---|---|---|---|---|
| `logs\` | dir | — | — | 2026-09-19 00:34 |
| `logs\10252.txt` | file | 874 | `61b2ed9a1faf4c18bfa1a4b4bf8a3c5c5a144677a7731b3914f36d42868ef747` | 2026-09-19 00:35:00 |
| `logs\10672.txt` | file | 949 | `b646f128a8521384aff63ed92d08b6bb88a00d936a71f28b788b2e236567f1fe` | 2026-09-18 19:42:26 |
| `logs\11392.txt` | file | 949 | `4892b62a85b1901194e69b6220393c994ea23c08390f00ba70db1514ce4501f2` | 2026-09-18 19:46:29 |
| `logs\2216.txt` | file | 949 | `683865f819d646de36475bca3eeb5b5ab2942ca605205b5a355e6a7cdb3d7063` | 2026-09-18 19:37:20 |
| `logs\2232.txt` | file | 949 | `584ebae931287b8cab3bcef97518d30bb6009ff54b10e46a0d2e3e44c128661e` | 2026-09-18 22:34:55 |
| `logs\3080.txt` | file | 949 | `b7523bbc5557a809ce9c3c8a1bfaa2793488cf83ef9e3088cdddbdb53329cff1` | 2026-09-18 19:15:15 |
| `logs\5028.txt` | file | 1004 | `26d60448dd92e7cc2598399ec0c3467fec94b839b3c2850cb33cfcc094f46731` | 2025-11-10 20:05:20 |
| `logs\5516.txt` | file | 874 | `db108cc6df00e3f7016cb68085469cee68634f02b65d2eede558c47fffeef610` | 2025-11-24 21:02:40 |
| `logs\7416.txt` | file | 874 | `e3a1edd371f1c30041eaf80a35f68b99e3edfb9ae1a2e5d0721182ed91e2224d` | 2026-09-18 22:35:17 |
| `logs\8400.txt` | file | 874 | `c9fe3e55f14c5023101fc73c544e2aab7aa894ae5eff4eada1a2c2a88e0604b2` | 2025-11-10 21:49:46 |
| `logs\8680.txt` | file | 874 | `e2259e2f69d51712a4146d99d36a9368c92730c6dab6ca80b68d1127b62fe8e5` | 2025-12-08 16:42:34 |
| `logs\8852.txt` | file | 874 | `a2f0c443dad57e3ee9575d8617e9f13c53b625b0c7ba3c5a8c116b720dceb8e7` | 2025-11-10 22:01:46 |
| `logs\9308.txt` | file | 949 | `5c5f352721a16a851d0b65981dfe27f50c008843c14f29a99dc99857afbf07c3` | 2026-09-18 20:15:58 |
| `logs\9904.txt` | file | 949 | `5f94e09963cd51f02edeee31d83aa20fce0a3ec9b395407c4cf77bd2e7db3de0` | 2026-09-18 22:23:43 |
| `S-1-5-21-2224134039-3417563983-3831536026-1001\` | dir | — | — | — |
| `…\cache\bmdat\nxu.dat` | file | 32 | `25dab3c0ca005f767d57ffb2c15a32d44059a8ef6c3093ba53bc269380fe0c7d` | 2026-09-19 21:36:03 |
| `…\cache\ssdat\` | dir | empty | — | — |
| `…\data\client\1789880113031\ht.dat` | file | 41,760 | `05e75f57f7a951c52fad13faa3f411a101c7885ca278abca6cf4bc88a436716f` | 2026-09-19 23:55:13 |
| `…\data\client\1789880113031\re4sHXTJFJHReHXTJFJTR.dat` | file | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 2026-09-19 23:47:24 |
| `…\data\pdl\2026-09-20T04-55-17.3281948-0\` | dir | — | — | — |
| `…\data\pdl\2026-09-20T04-55-17.3281948-0\rr.dat` | file | 0 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 2026-09-19 23:55:17 |
| `…\data\pdl\2026-09-20T04-55-17.3281948-0\su.dat` | file | 160 | `f324efd7bda1150f1803e4c73547298e4a3ff6c677a4dac19f2597d73425edd1` | 2026-09-19 23:55:17 |

The `data\pdl\` directory contains exactly one timestamped subdirectory with exactly these two
files (verified via `Get-ChildItem -Force` on 2026-09-24 and the initial recursive listing).

### Per-file hexdump (first 128 bytes) and entropy

Entropy = Shannon entropy, bits/byte, over the whole file.

`…\cache\bmdat\nxu.dat` — 32 B, entropy 4.8750 (small sample; value is low only because of size):

```
00000000  26 45 14 97 29 24 35 6e 28 ca ba 94 96 1a c3 ba  |&E..)$5n(.......|
00000010  38 4c 2a 01 54 a3 6d 99 2e 4c 19 b6 34 de 55 8f  |8L*.T.m..L..4.U.|
```

`…\data\client\1789880113031\ht.dat` — 41,760 B, entropy 7.9958:

```
00000000  a7 eb 51 e8 1e 57 d9 89 a2 2f 81 9b 09 fa ba 47  |..Q..W.../.....G|
00000010  b6 4b 6e af 27 ef ab 88 05 ef e8 13 36 eb b4 4b  |.Kn.'.......6..K|
00000020  35 af ce ff b5 26 da 72 fd 85 e7 cd dc b5 bd 5e  |5....&.r.......^|
00000030  84 b8 41 9c 11 bf 19 52 72 27 7a 08 c3 ae f0 76  |..A....Rr'z....v|
00000040  fa ab ef 97 6e 15 1b 18 ad 3f 89 b4 90 ef 34 52  |....n....?....4R|
00000050  2c 0d 2a aa c8 7e 2c 73 af 1a 63 29 b9 d4 a9 4d  |,.*..~,s..c)...M|
00000060  56 6d e9 20 9b 5c 9b 56 00 2c 97 ad 11 9a 4a 01  |Vm. .\.V.,....J.|
00000070  04 d1 9c bd ff bd b0 2f 85 63 79 52 2b 9b a9 1a  |......./.cyR+...|
```

`…\data\pdl\2026-09-20T04-55-17.3281948-0\su.dat` — 160 B, entropy 6.7483 (first 128 shown):

```
00000000  cb 96 d5 99 42 a2 83 87 6a 66 86 ca 3a c8 a6 3d  |....B...jf..:..=|
00000010  bc 11 46 a3 ef 71 c9 4f 49 26 bd 91 d1 f7 c3 be  |..F..q.OI&......|
00000020  82 8f 13 28 70 83 5b d8 9f e8 7c 39 52 a3 8c 21  |...(p.[...|9R..!|
00000030  82 a0 59 d7 3a 0b a2 c2 92 8f bc 6e 21 23 d0 f1  |..Y.:......n!#..|
00000040  77 77 c5 ee 8c 75 4e 79 83 b0 9d 63 1f ea 33 ef  |ww...uNy...c..3.|
00000050  47 05 5f 0e 3d 14 d0 8e a2 21 a7 29 a7 3a 1f b8  |G._.=....!.).:..|
00000060  50 ff e1 07 57 e4 f7 f6 18 ea fd f2 55 70 44 fe  |P...W.......UpD.|
00000070  cc 28 b4 07 52 a4 91 81 b7 20 f5 44 45 0f 74 62  |.(..R.... .DE.tb|
```

`re4sHXTJFJHReHXTJFJTR.dat`, `rr.dat` — 0 B (sha256 = empty-file hash), no hexdump.

`logs\*.txt` are ASCII text; representative first-128 hexdump (`logs\5028.txt`) and per-file entropy:

```
00000000  32 30 32 35 2f 31 31 2f 31 30 20 32 30 3a 30 35  |2025/11/10 20:05|
00000010  3a 31 34 2e 37 39 32 20 4d 41 52 20 43 6c 61 73  |:14.792 MAR Clas|
00000020  73 69 66 69 65 72 3a 20 43 6f 6d 6d 61 6e 64 20  |sifier: Command |
00000030  6c 69 6e 65 3a 20 22 43 3a 5c 50 72 6f 67 72 61  |line: "C:\Progra|
00000040  6d 20 46 69 6c 65 73 5c 43 45 5c 43 6f 76 65 6e  |m Files\CE\Coven|
00000050  61 6e 74 45 79 65 73 43 6c 61 73 73 69 66 69 65  |antEyesClassifie|
00000060  72 2e 65 78 65 22 20 2d 2d 76 65 72 73 69 6f 6e  |r.exe" --version|
00000070  3d 31 30 2e 31 2e 31 20 2d 2d 6d 6f 64 65 6c 3d  |=10.1.1 --model=|
```

| log | entropy | log | entropy |
|---|---|---|---|
| 5028.txt | 5.2187 | 8400.txt | 5.2337 |
| 5516.txt | 5.2141 | 8680.txt | 5.2262 |
| 8852.txt | 5.2125 | 10252.txt | 5.2487 |
| 2216.txt | 5.2296 | 2232.txt | 5.2229 |
| 3080.txt | 5.2267 | 7416.txt | 5.2495 |
| 9308.txt | 5.2386 | 9904.txt | 5.2386 |
| 10672.txt | 5.2279 | 11392.txt | 5.2276 |

### Log excerpts

Full content of `logs\5028.txt` (2025-11-10 run; only run with a `bundleManager` error) — this is
also the canonical startup template for all 14 files:

```
2025/11/10 20:05:14.792 MAR Classifier: Command line: "C:\Program Files\CE\CovenantEyesClassifier.exe" --version=10.1.1 --model="C:\Program Files\CE\data" --data=C:\ProgramData\CovenantEyes\Classifier\S-1-5-21-2224134039-3417563983-3831536026-1001\data --cache=C:\ProgramData\CovenantEyes\Classifier\S-1-5-21-2224134039-3417563983-3831536026-1001\cache
2025/11/10 20:05:14.796 MAR Classifier: Classifier v10.1.1 is starting
2025/11/10 20:05:14.882 WAR Classifier: Could not attach to user database SQLite error: 26
2025/11/10 20:05:14.882 WAR Classifier: SQLite database connect error
2025/11/10 20:05:14.883 WAR Classifier: Could not attach to user database SQLite error: 26
2025/11/10 20:05:14.883 WAR Classifier: SQLite database connect error
2025/11/10 20:05:20.355 WAR pdl-edi: ONE-TIME NOTE: Experimental chance set to 0, no experiments will run for this user.
2025/11/10 20:05:20.360 ERR bundleManager: onTimeUpdate error - Unable to read nextUpdate file (might not have been created yet)
```

Graceful-shutdown tail, `logs\3080.txt` (longest run, 16:10:53 → 19:15:15):

```
2026/09/18 16:10:53.159 MAR Classifier: Command line: "C:\Program Files\CE\CovenantEyesClassifier.exe" --version=10.1.1 --model="C:\Program Files\CE\data" --data=…\S-1-5-21-…-1001\data --cache=…\S-1-5-21-…-1001\cache
2026/09/18 16:10:53.168 MAR Classifier: Classifier v10.1.1 is starting
…
2026/09/18 16:10:57.962 WAR pdl-edi: ONE-TIME NOTE: Experimental chance set to 0, no experiments will run for this user.
2026/09/18 19:15:15.899 MAR Classifier: Classifier v10.1.1 is terminating
```

New-binary evidence, `re/samples/data/logs/upgrade-126428.log` (10.1.44 upgrade, lines 172/184) —
the upgrade stops both classifier names:

```
TRAC|09-21 00:22:06.962581|0x0001ef08|findProcessesByExe|Begin finding all processes for VictoryShieldClassifier.exe
…
TRAC|09-21 00:22:07.065301|0x0001ef08|findProcessesByExe|Begin finding all processes for CovenantEyesClassifier.exe
```

### Collection commands (evidence provenance)

```
Get-ChildItem -Recurse -Force -File "C:\ProgramData\CovenantEyes\Classifier" | … FullName|Length|LastWriteTime
scp 'dolphin@100.99.219.44:C:/ProgramData/CovenantEyes/Classifier/…' re/samples/data/…
sha256sum re/samples/data/classifier-logs/* re/samples/data/classifier-data/* re/samples/data/classifier-pdl/*
```

## Linux-reimplementation notes (brief)

- Mirror the CLI contract: `classifier --model=<dir> --data=<per-user dir> --cache=<per-user dir>`,
  log one `<PID>.log` per process with `time, severity, tag, message` lines; emit `starting`,
  a startup command-line dump, and `terminating`.
- Per-user state keyed by user id: `cache/` for small control files (update-schedule marker),
  `data/<batch-id>/` for fetched batches, `data/<work-ts>/` for pending-work batches. Batch ids as
  epoch-ms (sortable, collision-free) work well.
- Keep model data out of the per-user tree (installed read-only, versioned per release); treat
  "user DB unavailable" as a warning and keep classifying offline.
- If A/B experiments are used, persist the assignment per user and log it once ("experimental
  chance" roll), so behavior is explainable in support logs.
