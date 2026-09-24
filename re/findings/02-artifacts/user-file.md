# `ce-user-file` — opaque high-entropy per-user state container

## What it does

`C:\ProgramData\CovenantEyes\VictoryShieldv010.001.044\ce-user-file` (12,288 B) and its
pre-upgrade sibling `C:\ProgramData\CovenantEyes\PreviousConfiguration\ce-user-file`
(86,016 B) are **fully opaque, uniformly high-entropy blobs** — no magic, no strings, no
repeated blocks, no trivial encoding. Byte statistics match **strong encryption (or
encryption of already-compressed data)** with per-file randomization: the two files share
no common prefix and no 8-byte chunk, so any header/IV/nonce is unique per file.
`[INFERENCE]` The name and lifecycle indicate a per-user account/config state container
(CE session state, filter/config data, or cached per-user policy) written by the client at
install/upgrade time: the current 12,288 B file was written once (2026-09-21 00:22:40,
install) and never since; the older 86,016 B file was moved to `PreviousConfiguration\`
during the 2026-09-21 upgrade (`InstallMode=upgrade` in the registry), preserving its
original mtime (2026-09-19 23:55:21).

Sample locations: `re/samples/data/ce-user-file` (12,288 B) and
`re/samples/data/ce-user-file.previous` (86,016 B).

## Mechanism

### Block structure

| file | size | 4 KiB blocks | interpretation |
|---|---|---|---|
| `ce-user-file` (current) | 12,288 B | 3 × 4096 | exactly 3 × 4 KiB |
| `ce-user-file.previous` | 86,016 B | 21 × 4096 | exactly 21 × 4 KiB |

Both sizes are exact multiples of 4096 (and of 16). `[INFERENCE]` The 4 KiB granularity
mirrors the SQLite page size used by `ce-file` and NTFS allocation granularity — the
container is likely grown/allocated in whole pages (e.g. one encrypted page per 4 KiB of
plaintext, or a page-aligned encrypted store). 12,288 = 3 × 4096 confirms the "3 blocks"
hypothesis; there is no separate visible header block (block 0 is as random as the rest).

### Entropy / encoding quick checks (all negative for structure)

Per-4 KiB-block Shannon entropy — uniformly ~7.95 bits/byte (finite-sample ceiling for
random 4 KiB data is ≈7.95–7.96; plaintext/compressed data would show variance between
blocks; structured data would drop well below 7):

```
ce-user-file (12288 B):
  block 0 (0x00000-0x00fff): entropy=7.959, zeros=20/4096, distinct=256
  block 1 (0x01000-0x01fff): entropy=7.959, zeros=9/4096,  distinct=256
  block 2 (0x02000-0x02fff): entropy=7.953, zeros=19/4096, distinct=256
ce-user-file.previous (86016 B):
  block 0..20: entropy=7.947–7.960, zeros=8–24/4096, distinct=256   (all 21 blocks)
```

Further checks (python; commands in Evidence):

- **Byte histogram vs. uniform:** chi-square 271 (current) / 255 (previous) on df=255 —
  both consistent with a uniform (random-looking) byte distribution.
- **ECB-style block repetition:** 0 duplicate 16 B blocks in either file (768 and 5,376
  blocks checked); all 4 KiB blocks distinct. Naive ECB on structured plaintext would
  typically leak repeats. `[INFERENCE]` weak evidence only — dedup could also fail simply
  because pages differ.
- **Fixed-position structure:** 0 byte positions identical across all blocks in either
  file — no aligned header/counter/flag per page.
- **Single-byte XOR:** no key 0x01–0xFF makes `SQLite format 3` appear anywhere; the best
  single-byte-XOR printable ratio is 0.38–0.39 (random baseline ≈ 0.37) — no monoalphabetic
  obfuscation.
- **Compression at offset 0:** zlib (wbits 15/−15/47) and bzip2 do not decompress at
  offset 0 in either file.
- **Known container magics:** neither file starts with `LUKS`, `VERA`, `TRUE`, DPAPI
  blob prefix, gzip/zlib/bz2, or SQLite.
- **Printable strings ≥6 chars:** only chance-level runs (e.g. `V[i$3e`, `EY90c#`) at
  ~1 expected per 100 random bytes — no embedded text.

### Header comparison (the two files)

First 256 B of each are entirely different: **0 common prefix bytes**, **0 shared 8-byte
chunks** across the files, and the bytewise XOR of the two headers is itself uniform
(e.g. first 32 B: `7c6cb5e086998837cbbb4422b058d97719130907ea5b00a1219b8d80d04806ea`).
`[INFERENCE]` There is no fixed cleartext header (no version field, no key id visible in
the clear); if a header exists it is covered by the encryption or is itself a random
nonce/IV. Per-file randomization (fresh IV/key per write) is the simplest explanation.

### Hypothesis on format and contents `[INFERENCE]`

Most likely: an **encrypted container of per-user state** — e.g. AES-CBC/CTR/ChaCha with a
per-file IV/nonce (possibly DPAPI-protected key material, given the Windows target) over a
page-aligned record structure. The jump from 86,016 B (previous config) to 12,288 B
(current) suggests the container holds data that got much smaller — e.g. per-user policy/
filter lists cached at provision time (big when a full filter configuration was fetched,
small when only a stub/default was). The per-page granularity would allow partial rewrites
without re-encrypting the whole file. Alternative hypothesis: it is a compressed-then-
encrypted archive (compression would explain the size drop); the zero structure makes
these indistinguishable without the key or the writer's code.

## Evidence

### Header hexdumps (first 256 B)

`xxd -l 256 re/samples/data/ce-user-file`:
```
00000000: c378 7330 7e6e 84cc 2bb9 647d 129d 1e68  .xs0~n..+.d}...h
00000010: 921c 9488 a935 0cbf 0083 9719 07b4 1df7  .....5..........
00000020: a461 20e8 61a1 2800 1960 5808 0911 752b  .a .a.(..`X...u+
00000030: 1a33 61db e4e3 255b a5a3 bf06 f501 aa31  .3a...%[.......1
00000040: 7182 8a19 a028 35eb 2ee8 2a0e ce1a ca91  q....(5...*.....
00000050: ee57 3142 5701 23b2 4a34 a70e 6ae0 4af4  .W1BW.#.J4..j.J.
00000060: 5b0a 62a9 23cd 21ee 4f10 a8b9 b82c 361a  [.b.#.!.O....,6.
00000070: a4f8 afda d5cf 84f9 679c 0064 5a63 77a2  ........g..dZcw.
00000080: 69cd e37f 073d c753 5eb3 a858 6fef 9bc9  i....=.S^..Xo...
00000090: e4cb 233b b29b c5d0 fee3 b86f 11a4 0be5  ..#;.......o....
000000a0: acae 25ee 86c2 3f36 b815 b102 6556 d69f  ..%...?6....eV..
000000b0: 0a68 c2ae 8010 f57b edf7 0eb8 52c5 74e5  .h.....{....R.t.
000000c0: 5b17 bfd6 1be1 8e18 849f e3b8 4611 238a  [...........F.#.
000000d0: cfcc 1465 58c8 643f 0282 eb14 47b8 3f7b  ...eX.d?....G.?{
000000e0: e602 027e 5b88 ead9 d39a 5365 f5fe b711  ...~[.....Se....
000000f0: 34f3 b370 a7ba a868 7323 4ad8 fee9 dc8f  4..p...hs#J.....
```

`xxd -l 256 re/samples/data/ce-user-file.previous`:
```
00000000: bf14 c6d0 f8f7 0cfb e002 205f a2c5 c71f  .......... _....
00000010: 8b0f 9d8f 436e 0c1e 2118 1a99 d7fc 1b1d  ....Cn..!.......
00000020: ab97 6a6f 5cfc 9cf3 641a d069 c16a f3e5  ..jo\...d..i.j..
00000030: 8293 f307 2f8a 0735 2324 51e6 f120 e2b3  ..../..5#$Q.. ..
00000040: 147b d8a9 5134 506a 70a6 dd31 2e53 b382  .{..Q4Pjp..1.S..
00000050: 8356 5b69 2433 658c af45 b79c 79de b1a2  .V[i$3e..E..y...
00000060: 9f9c c4fc bc7a f277 aaf9 5b32 b62b 8d61  .....z.w..[2.+.a
00000070: 107d d8e6 9855 0fb0 09e9 27a0 de76 db0b  .}...U....'..v..
00000080: 58f2 2490 d405 8fab 705b e063 eeeb 5a20  X.$.....p[.c..Z 
00000090: f1aa b8bf c110 0e49 46d1 9881 3305 6638  .......IF...3.f8
000000a0: 5d1e e57f e437 022f 2f2c 8723 d5ad 4342  ]....7.//,.#..CB
000000b0: 9177 e645 5939 3063 231e a93d ade6 34fc  .w.EY90c#..=..4.
000000c0: 4f50 8513 7a7c 1a7c 36f0 3262 b80a 5569  OP..z|.|6.2b..Ui
000000d0: eedf a2e0 58cd f48f 3485 1d3c 8043 18ea  ....X...4..<.C..
000000e0: e933 221a c159 f191 9260 a8a2 9161 4a16  .3"..Y...`...aJ.
000000f0: 5b5a b125 01f3 97b9 5683 828d c625 0023  [Z.%....V....%.#
```

### Per-4 KiB-block entropy (python one-liner output)

```
--- re/samples/data/ce-user-file (12288 B) ---
block 0 (0x00000-0x00fff): entropy=7.959 bits/byte, zeros=20/4096, distinct=256
block 1 (0x01000-0x01fff): entropy=7.959 bits/byte, zeros=9/4096, distinct=256
block 2 (0x02000-0x02fff): entropy=7.953 bits/byte, zeros=19/4096, distinct=256
--- re/samples/data/ce-user-file.previous (86016 B) ---
block 0  (0x00000-0x00fff): entropy=7.954, zeros=15/4096
block 1  (0x01000-0x01fff): entropy=7.951, zeros=13/4096
block 2  (0x02000-0x02fff): entropy=7.960, zeros=23/4096
block 3  (0x03000-0x03fff): entropy=7.951, zeros=18/4096
block 4  (0x04000-0x04fff): entropy=7.960, zeros=21/4096
block 5  (0x05000-0x05fff): entropy=7.952, zeros=22/4096
block 6  (0x06000-0x06fff): entropy=7.951, zeros=23/4096
block 7  (0x07000-0x07fff): entropy=7.958, zeros=18/4096
block 8  (0x08000-0x08fff): entropy=7.947, zeros=13/4096
block 9  (0x09000-0x09fff): entropy=7.956, zeros=8/4096
block 10 (0x0a000-0x0afff): entropy=7.956, zeros=15/4096
block 11 (0x0b000-0x0bfff): entropy=7.957, zeros=20/4096
block 12 (0x0c000-0x0cfff): entropy=7.956, zeros=17/4096
block 13 (0x0d000-0x0dfff): entropy=7.957, zeros=17/4096
block 14 (0x0e000-0x0efff): entropy=7.960, zeros=19/4096
block 15 (0x0f000-0x0ffff): entropy=7.956, zeros=14/4096
block 16 (0x10000-0x10fff): entropy=7.955, zeros=18/4096
block 17 (0x11000-0x11fff): entropy=7.957, zeros=16/4096
block 18 (0x12000-0x12fff): entropy=7.956, zeros=24/4096
block 19 (0x13000-0x13fff): entropy=7.952, zeros=17/4096
block 20 (0x14000-0x14fff): entropy=7.952, zeros=19/4096
```

### XOR / encoding / structure checks (python output)

```
=== ce-user-file (12288 B, 3 x 4KB) ===
  last 32B: 6484116329cd959b58eb3e311bb2ecbb1ef12e8c69919a655e7d599816f16e0b
  16B blocks: 768, duplicates: 0
  4KB blocks all distinct: True
  no single-byte XOR reveals SQLite magic
  best single-byte XOR 0xca printable ratio (block0): 0.39
  byte-histogram chi-square vs uniform: 271 (df=255, uniform-critical~293)
=== ce-user-file.previous (86016 B, 21 x 4KB) ===
  last 32B: 45c83f1be8f525066b6a0f958f35caadac678763a959805500582db75ab2f4da
  16B blocks: 5376, duplicates: 0
  4KB blocks all distinct: True
  no single-byte XOR reveals SQLite magic
  best single-byte XOR 0x14 printable ratio (block0): 0.38
  byte-histogram chi-square vs uniform: 255 (df=255, uniform-critical~293)

common prefix bytes: 0
shared 8B chunks (8B-aligned): 0
header XOR (first 64B) hex: 7c6cb5e086998837cbbb4422b058d97719130907ea5b00a1219b8d80d04806ea0ff64a873d5db4f37d7a8861c87b86ce98a092dccb69226e8687eee004214882
magic sniff done (no hits = neither file starts with a known container magic)
ce-user-file zlib/bz2: no decompression at offset 0
previous zlib/bz2: no decompression at offset 0

byte positions identical across all blocks: 0   (both files)
printable strings >=6 chars: 20 (current), 137 (previous) — all chance-level fragments
```

### File timestamps (remote `Get-ChildItem`, 2026-09-24)

```
...\PreviousConfiguration\ce-user-file                    | 86016 B | created 2026-09-21 00:22:39 | written 2026-09-19 23:55:21
...\VictoryShieldv010.001.044\ce-user-file                | 12288 B | created 2026-09-21 00:22:39 | written 2026-09-21 00:22:40
```
The previous file's `LastWriteTime` (2026-09-19 23:55:21) predates its
`PreviousConfiguration` creation (2026-09-21 00:22:39) — the upgrade copied/moved the old
file with its mtime intact, and wrote the new small file one second later. Registry
context (`HKLM\SOFTWARE\Covenant Eyes\Victory Shield`, `InstallMode=upgrade`) corroborates
an in-place upgrade on 2026-09-21.

## Linux-reimplementation notes

- Whatever the payload is, the *container* properties worth copying are simple: page-
  aligned (4 KiB) encrypted blocks, per-file random IV/nonce, no cleartext header, sizes
  that are exact multiples of the page. libsodium `secretbox`/`crypto_stream` per page
  with a random per-page nonce, or LUKS-style whole-file encryption keyed via the OS
  keystore (DPAPI analogue: kernel keyring), both satisfy the observed statistics.
- Keep the upgrade behavior: preserve the old container under a `PreviousConfiguration/`
  equivalent instead of deleting, so a rollback can restore per-user state.

## Open questions

1. What is the actual format — whole-file cipher, per-4 KiB-page cipher, or a compressed
   archive wrapped in encryption? (Blocked without the key or the writer's code; runtime
   write-tracing via the Ghidra/debugger tasks may reveal block writes and key handling.)
2. Who holds the key? DPAPI (per-user or machine scope), embedded key, or server-derived?
   `[INFERENCE]` DPAPI is likely on Windows but unproven.
3. Why did the container shrink 86,016 → 12,288 B across the upgrade — different content
   (filter list vs. stub), different plaintext, or a format change?
4. Is `ce-user-file` per Windows user or per CE account? (Single file per install directory
   suggests per-install, but the name says "user".)
5. Do the 4 KiB pages carry per-page authentication (GCM tag) or is integrity checked at
   the whole-file level? Tail bytes show no obvious padding/tag structure.
6. What writes it, and when — only at install/upgrade (mtimes suggest yes on this VM), or
   also on account sign-in/configuration changes on an actively-used machine?
