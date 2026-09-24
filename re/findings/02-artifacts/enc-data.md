# Encrypted data files — `C:\Program Files\CE\data\*.dat.enc`

## What it does

The six `*.dat.enc` files in the install directory are the **classifier model/data set** shipped
with the client. They are loaded by the classifier process via `--model="C:\Program Files\CE\data"`
(evidence in `classifier-data.md`) and are treated as "Classifier Model Data" by the installer,
which destroys and re-ships the whole directory on upgrade (evidence below). The `.dat.enc`
extension plus uniform high entropy (≥ 7.87 bits/byte over each whole file) show the payloads are
encrypted at rest; no plaintext magic survives anywhere in the files.

Copies: `re/samples/data/enc/` (hashes below are of the pulled copies).

## Mechanism

### Naming pattern

Every file is `<20 lowercase hex chars>-<suffix>.dat.enc`:

```
805b3533c9a731909930-b3.dat.enc
83b568cc34e776439494-b1.dat.enc
d8b85cbaabaf6c1e7b15-b2.dat.enc
a076283f3318c8ea4de0-sw.dat.enc
cea3215e9378de852a41-j1.dat.enc
f160caa8342747d04d8f-mn.dat.enc
```

- Prefix = 20 hex chars = 80 bits. The upgrade log (below) shows that between 10.1.1 and 10.1.44
  the `b1`, `b2`, `b3`, `sw` names stayed byte-identical while `j1` and `mn` got new prefixes:

  | suffix | 10.1.1 name (destroyed at upgrade) | 10.1.44 name (installed now) |
  |---|---|---|
  | b1 | `83b568cc34e776439494-b1.dat.enc` | `83b568cc34e776439494-b1.dat.enc` (same) |
  | b2 | `d8b85cbaabaf6c1e7b15-b2.dat.enc` | `d8b85cbaabaf6c1e7b15-b2.dat.enc` (same) |
  | b3 | `805b3533c9a731909930-b3.dat.enc` | `805b3533c9a731909930-b3.dat.enc` (same) |
  | sw | `a076283f3318c8ea4de0-sw.dat.enc` | `a076283f3318c8ea4de0-sw.dat.enc` (same) |
  | j1 | `b9336e70cd39551c7c77-j1.dat.enc` | `cea3215e9378de852a41-j1.dat.enc` (changed) |
  | mn | `436af58cc0e58764322e-mn.dat.enc` | `f160caa8342747d04d8f-mn.dat.enc` (changed) |

  [INFERENCE] the 20-hex prefix is a content-derived id (e.g. truncated hash of the plaintext or of
  the shipped payload) and the suffix is the stable role of the artifact: files whose payload did
  not change between releases keep their id; changed payloads get new ids. An alternative reading —
  random per-build ids — fits less well because four of six names were reused verbatim.
- Suffix set across both releases is exactly `{b1, b2, b3, j1, mn, sw}` — a closed taxonomy of six
  model/data components.

### Size correlation

| file | size (B) | size mod 16 | sha256 | entropy (whole file) |
|---|---|---|---|---|
| `83b568cc34e776439494-b1.dat.enc` | 2,323,104 | 0 | `d3df6ce3ef1374a96b15880764a1b71b8a266f2c99dd2eb4fb51fdc7317a8179` | 7.9999 |
| `d8b85cbaabaf6c1e7b15-b2.dat.enc` | 2,323,104 | 0 | `80877f5a52a2ac153d015cebf4ff37dc24596470a7eca5b1b59c9b8eaab2c2ca` | 7.9999 |
| `805b3533c9a731909930-b3.dat.enc` | 2,323,104 | 0 | `0b91634c5b8680f99aa400163e601740262809530baa255e11a4545e1a4899a7` | 7.9999 |
| `a076283f3318c8ea4de0-sw.dat.enc` | 901,200 | 0 | `28f77d31afe11ce2eca7f8bbd8099893bbf34d932f42947d4bbd154eb8dba1c7` | 7.9998 |
| `cea3215e9378de852a41-j1.dat.enc` | 187,248 | 0 | `da5caa4d27772c06eafee35a8a1638dbd69b7366dfddfb1fbb50310468eef9b1` | 7.9991 |
| `f160caa8342747d04d8f-mn.dat.enc` | 1,248 | 0 | `cad1afbe9815779331d8922acf5a0bb9b32e4568c382250202f8cbd35ab856dc` | 7.8787 |

- The three `bN` files are exactly the same size (2,323,104 B = 567.16 KiB) — same-size shards of one
  structure [INFERENCE].
- Every size is a multiple of the 16-byte AES block size (2,323,104 = 145,194 × 16;
  901,200 = 56,325 × 16; 187,248 = 11,703 × 16; 1,248 = 78 × 16). Padding of a whole-file cipher is
  therefore invisible [INFERENCE: block cipher in a block-aligned mode or length-preserving stream
  construction].
- No compression containers: scanning each file for zlib (`78 9C`, `78 01`), gzip (`1F 8B`), bz2,
  xz, zstd, `PK\x03\x04`, `SQLite format 3`, `MZ` magics finds only chance-level hits at scattered
  offsets (e.g. `MZ` at b1 offset 93,634 ≈ random 2-byte collision at n/65536); nothing at offset 0
  and no consistent alignment. Entropy ~8.0 everywhere ⇒ raw ciphertext, not compressed plaintext
  (compressed data would sit at ≈ 7.x with visible framing).

### Headers and structure

First 128 bytes of each file (full hexdump in `re/samples/data/entropy-report.txt`):

`-b1` / `-b2` / `-b3` share **byte-identical** first bytes:

```
00000000  d4 3e 57 47 92 4b f7 2b 96 c5 8d 89 29 19 17 e2  |.>WG.K.+....)...|
00000010  d0 1e 91 ee d6 47 77 b7 f2 73 06 97 b8 17 fe 1e  |.....Gw..s......|
00000020  ea c0 d4 5e 7b db f1 c1 11 46 58 e2 08 5f 70 0a  |...^{....FX.._p.|
00000030  73 49 f1 1b 38 9d 43 47 13 8e ee eb 46 fe f6 f5  |sI..8.CG....F...|
```

`-sw`:

```
00000000  e4 b4 9f a2 4d c9 ab 50 f3 bb c4 7f 55 0e 73 8c  |....M..P....U.s.|
00000010  d6 73 23 64 3d 56 1a e1 bc 4c ec 44 cc 2c f1 f0  |.s#d=V...L.D.,..|
```

`-j1`:

```
00000000  68 8b b2 9d 4d 83 0c 5d c9 c1 d1 e3 ab fe 3d 6c  |h...M..]......=l|
00000010  f2 10 66 01 ab 97 88 40 34 46 d1 be c2 68 90 49  |..f....@4F...h.I|
```

`-mn`:

```
00000000  69 5c cd 73 29 33 e0 8a 1e 06 e4 eb 1a 4d 29 89  |i\.s)3.......M).|
00000010  fc 0d 33 6c 19 99 48 6a 3c f6 f5 d5 ac 8e fb 73  |..3l..Hj<......s|
```

Pairwise common-prefix lengths across the six files:

| pair | identical leading bytes |
|---|---|
| b1 vs b2 | **9,584** |
| b1 vs b3 | **9,584** |
| b2 vs b3 | **9,584** |
| any bN vs sw / j1 / mn | 0 |
| sw vs j1 / mn, j1 vs mn | 0 |

So the three `bN` files consist of a 9,584-byte (599 × 16 B) identical prefix and then diverge
completely (byte-equality rate after the boundary ≈ 0.79 % ≈ chance). Boundary bytes of b1/b2
around the split:

```
; b1 at 0x2550..0x259f
00002550  75 a2 1a fd 85 48 51 d6 18 d3 fc a6 ae 7a 76 be
00002560  dd 4c a2 c2 04 5a ff bc 54 af fe 1c b8 05 e6 4c   ← identical in b2 to 0x256f
00002570  5e f0 95 ef 90 04 bf f6 8c 7d d1 d9 ba 77 01 e6   ← b2 diverges from 0x2570
00002580  77 c2 2e 6d ac 3b a0 d4 e1 b3 3b 35 2a fb c9 7f
00002590  25 df cd 33 32 84 fe 32 59 f3 27 b2 21 15 2d a8
; b2 at 0x2560..0x258f (diverges at 0x2570 = 9584)
00002560  dd 4c a2 c2 04 5a ff bc 54 af fe 1c b8 05 e6 4c
00002570  1d e0 2a 79 a9 9e 76 dc 6e 9f ce 82 b6 51 e9 ae
```

[INFERENCE] the shared 9,584-byte prefix is an identical plaintext header/index in all three shards
that is encrypted deterministically (identical ciphertext ⇒ same key + ECB or fixed-IV CBC over
identical input), while the per-shard bodies differ. No duplicated 16-byte blocks exist within any
file (0 duplicates out of 145,194 in the b-files), so the bodies are high-entropy even at block
level — [INFERENCE] either ECB over compressed/encrypted-looking data, or a chained/stream mode.

### How they are keyed and loaded — evidence + [INFERENCE]

Evidence (not inference):

1. Classifier startup line: `--model="C:\Program Files\CE\data"` (all 14 classifier logs,
   `classifier-data.md`), i.e. this exact directory is the classifier's model directory.
2. The installer calls the directory contents "Classifier Model Data" and deletes each `*.dat.enc`
   by name during upgrade, then removes the empty directory
   (`re/samples/data/logs/upgrade-126428.log:306-427`):

```
TRAC|09-21 00:22:31.562149|0x0001ef08|RemoveClassifierModelData|Begin
INFO|09-21 00:22:31.565965|0x0001ef08|destroyDirectory|destroying directory: C:\Program Files\CE\data
INFO|09-21 00:22:31.567996|0x0001ef08|destroyFile|destroying file: C:\Program Files\CE\data\d8b85cbaabaf6c1e7b15-b2.dat.enc
INFO|09-21 00:22:31.567996|0x0001ef08|destroyFile|destroying file: C:\Program Files\CE\data\b9336e70cd39551c7c77-j1.dat.enc
INFO|09-21 00:22:31.570029|0x0001ef08|destroyFile|destroying file: C:\Program Files\CE\data\a076283f3318c8ea4de0-sw.dat.enc
INFO|09-21 00:22:31.572062|0x0001ef08|destroyFile|destroying file: C:\Program Files\CE\data\83b568cc34e776439494-b1.dat.enc
INFO|09-21 00:22:31.572062|0x0001ef08|destroyFile|destroying file: C:\Program Files\CE\data\805b3533c9a731909930-b3.dat.enc
INFO|09-21 00:22:31.574092|0x0001ef08|destroyFile|destroying file: C:\Program Files\CE\data\436af58cc0e58764322e-mn.dat.enc
INFO|09-21 00:22:31.576128|0x0001ef08|destroyEmptyDirectory|destroying empty directory: C:\Program Files\CE\data
TRAC|09-21 00:22:31.576128|0x0001ef08|RemoveClassifierModelData|Done
```

   The 10.1.44 installer then re-creates `C:\Program Files\CE\data\` with the six current files
   (present on disk since the 2026-09-21 upgrade).

[INFERENCE] — keying/loading:

- The classifier binary decrypts the blobs in-process at startup. No key material lives beside the
  files (the directory contains only the six `.dat.enc`), so the key is either embedded in
  `CovenantEyesClassifier.exe`/`VictoryShieldClassifier.exe` or derived (e.g. from the 20-hex file
  id) — nothing in the collected artifacts distinguishes these.
- The suffix taxonomy is a role classifier. Most plausible readings, all `[INFERENCE]`:
  `b1..b3` = three equal shards of the main model/table ("b" ≈ *bundle* / *bucket* / *blocklist*;
  identical 9,584 B header ⇒ shared record index or schema block); `sw` = *stop-words*/word-feature
  table (901,200 B); `j1` = *json-ish* auxiliary mapping (187,248 B); `mn` = a tiny
  *manifest/menu/mnemonic* artifact (1,248 B ≈ 78 AES blocks — small enough to be a manifest or a
  wrapped key/config). No artifact in logs or names confirms these expansions.
- Because `j1`/`mn` were refreshed between 10.1.1 and 10.1.44 while `b1..b3`/`sw` were not,
  [INFERENCE] the shards hold a long-lived base model and `j1`/`mn` hold version-sensitive data
  (e.g. config, category map, or model metadata).

## Evidence

- File listing and hashes: table above; sizes verified with `Get-ChildItem "C:\Program Files\CE\data"`
  and `dir` on 2026-09-24 (both show exactly these six files).
- Hexdumps/entropy/prefix analysis: computed on the pulled copies
  (`re/samples/data/entropy-report.txt`, sha256 table above).
- Old-name/new-name mapping: `RemoveClassifierModelData` block, `upgrade-126428.log:306-427`
  (quoted above).
- Model-directory linkage: classifier command line (`classifier-data.md`, `logs\5028.txt:1`).

## Linux-reimplementation notes (brief)

- Ship model data as content-addressed artifacts (`<id>-<role>.enc`) outside the per-user state, and
  have the classifier take `--model/--data/--cache` explicitly; id = hash of payload makes updates
  and rollback trivial and lets the installer delete exactly the obsolete set.
- Encrypt models at rest only if the threat model needs it; if you do, prefer an AEAD with a
  per-file nonce so identical plaintext prefixes do not leak as identical ciphertext (the three
  b-shards leak exactly that here). Keep a small plaintext manifest (like `mn` appears to be) for
  versions/roles so tooling can verify completeness without keys.
- Log the loaded file ids at classifier startup — the CE logs never name the model files, which made
  this mapping an inference exercise.
