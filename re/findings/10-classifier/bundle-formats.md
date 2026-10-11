# Classifier data-bundle formats and keying — `*.dat.enc` + bundleManager/pdl-edi

Scope: the encrypted model/data artifacts in `C:\Program Files\CE\data` (six `<id>-<role>.dat.enc`
files), the classifier's per-user control files (`nxu.dat`, `ht.dat`, `su.dat`, `rr.dat`,
`re4*.dat`, the `bmdat`/`ssdat` cache dirs), and the `bundleManager`/`pdl-edi` machinery that
locates, validates and replaces them. This document **closes** `re/findings/91-linux-mapping.md`
§2 Open item 1(b): every one of the six `*.dat.enc` roles is now decrypted and identified, the
at-rest encryption scheme is fully recovered and empirically verified against the pulled samples,
and the bundle manifest format is recovered verbatim. It supersedes the `[INFERENCE]` role
taxonomy and keying section of `re/findings/02-artifacts/enc-data.md` (file hashes/naming there
remain valid); it complements `re/findings/10-classifier/classifier-internals-classifier.md`
(message vocabulary, JS-bundle architecture), which covers the parts of the flow that are not
about bundle bytes.

Method: `xxd`/Python/`openssl` on the local samples (`re/samples/data/enc/*.dat.enc`,
`re/samples/data/classifier-data/`, `re/samples/data/classifier-pdl/`) plus read-only Ghidra
tracing of `VictoryShieldClassifier.exe` (image base `0x140000000`; all `FUN_*` addresses below
are functions in that program unless stated). Per the clean-room scope guard, model *contents*
(weights, JS source) are identified by header/structure only and are not reproduced; only the
container/manifest formats and keying are documented. No recovered blob is written anywhere
except analysis notes in this file.

---

## 1. The at-rest encryption layer (`CECrypto`)

Every artifact in this document — the six model-dir files **and** the per-user `nxu/ht/su` files —
is a raw AES-CBC ciphertext with PKCS#7 padding, no IV prefix, no MAC, no compression. Two key
contexts exist ("crypto contexts" 0 and 1), both with **static keys derived from literals embedded
in the binary**. Both derivations were reconstructed from code and then *empirically verified*:
decrypting the pulled artifacts with the recovered parameters yields valid plaintext
(PKCS#7-valid in every case, structured JSON/text from byte 0).

### 1.1 Cipher objects and padding

| component | address | evidence |
|---|---|---|
| `CECrypto::CipherAes256` ctor (context 0, key length field `0x20`) | `FUN_141996bc0` | vtable assignment `*param_1 = CECrypto::CipherAes256::vftable`; two CBC members keyed via `FUN_14199c890(member, key, 0x20, iv, ivlen)` |
| `CECrypto::CipherAes128` ctor (context 1, key length field `0x10`) | `FUN_141996b10` | same shape, `CECrypto::CipherAes128::vftable` |
| crypto-context selector (`0`→AES-256 factory `FUN_141995930`, `1`→AES-128 factory `FUN_141995bc0`; anything else throws `"Invalid crypto context selected"` `0x142a21a20`) | `FUN_1418b7410` | decompilation |
| PKCS#7 pad + encrypt (pads to 16 B, throws `"Buffer not large enough to store PKCS padding"`) | `FUN_1418b72b0` | decompilation; sole caller `FUN_1418bfc30` (JS-bound encrypt API, 4 args incl. context) |
| decrypt + PKCS#7 strip (last byte must be `< 0x11`, else `"PKCS 7 pad data not found"`) | `FUN_1418b70e0` | decompilation |
| decrypting streambuf ctor (wraps an `ifstream` with a context cipher) | `FUN_141993a80` | callers below |

Mode = **CBC** (not ECB/CTR/GCM): CryptoPP RTTI contains exactly `CBC_Encryption`/`CBC_Decryption`
(Rijndael) and no other mode; alignment errors are reported per whole buffer
(`"encrypt/decrypt buffer length not AES block-size aligned"`, `0x142a3d2d8`/`0x142a3d310`,
catch helper `FUN_14199a7f0`). The fixed-IV CBC conclusion is independently forced by the data:
the three `bN` shards share a byte-identical 9,584-byte ciphertext prefix
(`re/findings/02-artifacts/enc-data.md`), which only a deterministic (key, IV) pair can produce.

### 1.2 Context 0 (AES-256-CBC) — model-dir `*.dat.enc` artifacts

Key material factory `FUN_141995930`:

- **IV** = 16 ASCII bytes, hardcoded as four stack immediates in `FUN_141995930`
  (`local_28..local_1c` = `0x4d7a5776, 0x746e4236, 0x57383157, 0x71776734`, little-endian) →
  `IV0 = "vWzM6BntW18W4gwq"`.
- **Key** = `SHA-256(XOR-0x50(assembled_string))`, 32 bytes, assembled by `FUN_141994dd0` from an
  embedded pool of 32-char random-ASCII strings (literals at `.rdata` `0x142a3b160`–`0x142a3b560`,
  e.g. `"MtTaIRpMewyc9aH9b6cZXpuDciwX0XoF"` at `0x142a3b160`). The assembly is a fixed
  concatenation of 15 slots (13 distinct pool strings, two repeated; order recovered from the
  `FUN_14182ae40`/`FUN_141824f50`/`FUN_141824e70` append chain inside `FUN_141994dd0`), then
  per-byte `XOR 0x50` (`FUN_141994d30`, `*(byte) ^= 0x50` loop), then SHA-256
  (`FUN_141994b10` → `FUN_1419994f0`, CryptoPP hash pipeline).
- Verified result: `KEY0 = ed537645f9ccc3d62d301de93da132a501b587daaed9258ccfd49c073acf42e6`.

### 1.3 Context 1 (AES-128-CBC) — per-user message/control files (`nxu/ht/su` verified; `hr` by code path; `ss/pc/cs` [INFERENCE: same writers])

Key material factories `FUN_141995dc0` (key source) / `FUN_141995fe0` (IV source); each hashes a
29-byte literal with SHA-256 at first use (once-init globals `DAT_1431b2718` / `DAT_1431b2740`,
storer `FUN_141995d10` → `FUN_141994ae0` → `FUN_141994b10` = SHA-256):

- key source literal = `"lobal test environment set-up"` (29 B, loaded from VA `0x142a3b581`;
  note the leading `G` of the adjacent `rdata` string `"Global test environment set-up"`
  `0x142a3b580` is *not* included — verified in the disassembly of `FUN_141995dc0`,
  `movups 0x142a3b581`).
- IV source literal = `"eferred vector width half = 0"` (29 B, VA `0x142a3b5a2`; adjacent
  `"Preferred vector width half = 0"` at `0x142a3b5a0`).
- `FUN_141995bc0` then slices the digests (`lea 0x4(%rdi),%rdx` / `lea 0x3(%rsi),%r8` at
  `0x141995c35`/`0x141995c39`) into the AES-128 ctor:
  - `KEY1 = SHA-256("lobal test environment set-up")[4:20]` = `acea ca87 b1a3 11c5 5c35 125c 3ff9 f2cf`
  - `IV1  = SHA-256("eferred vector width half = 0")[3:19]` = `36ee 4da5 1009 febf 8be7 7797 1275 3c18`

### 1.4 Verification (all pulled samples decrypt cleanly)

| artifact | context | cipher size | PKCS#7 pad | plaintext size | plaintext head (recovered) |
|---|---|---|---|---|---|
| `f160caa8342747d04d8f-mn.dat.enc` | 0 | 1,248 | 8 | 1,240 | `{"schemaVersion":"1.0.0","bundleVersion":"1.12.3","files":[…` |
| `83b568cc…-b1.dat.enc` (and b2/b3) | 0 | 2,323,104 | 16 | 2,323,088 | `ensem_3cls-6.1.2,157.0,143.0,135.0,84.32674546073743,…` |
| `a076283f…-sw.dat.enc` | 0 | 901,200 | 15 | 901,185 | `Snowball NLP 2.0\nrbf\nsomewhere\nme\n…` |
| `cea3215e…-j1.dat.enc` | 0 | 187,248 | 16 | 187,232 | `var exports = {};\n\nObject.defineProperty(exports…` |
| `cache\bmdat\nxu.dat` | 1 | 32 | 3 | 29 | `{"nextUpdate_sec":1789896962}` |
| `data\pdl\…\su.dat` | 1 | 160 | 6 | 154 | `{"$schema":"./suggestion_schema.json","importantRequest":…` |
| `data\client\1789880113031\ht.dat` | 1 | 41,760 | 3 | 41,757 | `{"schemaVersion":"2.1.0","method":"POST","requestFriendlyName":"Feed Batch Upload",…` |

Every size is a multiple of 16 with a valid PKCS#7 tail — the "all sizes ≡ 0 (mod 16), entropy ≥
7.87" observation in `enc-data.md` is now explained completely: whole-file AES-CBC+PKCS#7.

### 1.5 Which code path uses which context

| path | context | address |
|---|---|---|
| JS-bundle loader: reads `<bundleDir>\j1.dat.enc` → plaintext fed to duktape under virtual name `bundleArtifacts/pdl_js.js` (`0x142a16798`) | **0** | `FUN_1418579e0` → AES-256 string-reader `FUN_141859ab0` → `FUN_141993a80` |
| generic file-read-to-string with decrypt flag (`readFileToString(path, flag)`); `flag=1` used e.g. by `BundleManager::onNewFileDownload` (`FUN_141897610`) to read the `hr.dat` response message | **1** | `FUN_141992350` (`flag==0` → plain ifstream; `flag==1` → `FUN_141993ee0`) |
| manifest/body parse from a decrypted stream (consumes `files`/`download_link`/`sha512_hash` keys `0x142a210e8`/`0x142a210f0`/`0x142a21100`) | **1** | `FUN_1418b0440` ← `FUN_1418af170` (bundleManager) |
| JS-exposed `bw.DecryptFile(path, ctx)` (returns `bw.DecryptFile`-tagged object; ctx comes from JS) | selectable | `FUN_141913d30` → `FUN_1418b6060` |
| JS-exposed `decryptBuf(ctx, buf, len)` / encrypt counterpart | selectable | `FUN_1418bf960` / `FUN_1418bfc30` |
| JS-exposed `bw.fs.*` filesystem namespace — 13 boost::filesystem-backed free functions (`absolute`, `canonical`, `create_directories`, `current_path`, `directory_listing`, `exists`, `file_size`, `is_directory`, `is_regular_file`, `last_write_time`, `remove_all`, `rename`, `touch`; registration names `dt_freefunc_bw_fs_*`), plus the `bw.File` fstream class (`open/read/write/seekg/tellg/seekp/tellp/flush/close/is_open`) | n/a | balingbuddy bindings; `boost::filesystem::create_directories` string present |
| `ce::FileUtils::imreadEncrypted(path, flags) → cv::Mat` (fileUtils.cpp lines `0xa1/0xa3/0xa5` catch helpers `FUN_142840530`/`FUN_142840730`/`FUN_142840930`; `CryptoException` on bad decrypt) | bounded — body not fully traced; last examined address `FUN_142840c10` (the `"Could not decrypt file "` handler, string `0x142a3aae8`) | — |

[INFERENCE, strong: the six model-dir files are all context-0. The manifest proves the bundle is
`{b1,b2,b3,sw,j1}` + the manifest itself (`mn`); `j1` decrypts with context 0 (verified), the
context-0 factory exists only in the classifier binary, and the JS bundle receives the remaining
reads through `bw.DecryptFile(ctx=0)` — the C++ side has no other model-dir reader.]
Context 1 is shared with the client: `VictoryShield.exe` contains the same two derivation literals
(`"Global test environment set-up"`, `"Preferred vector width half = 0"`) and the same CryptoPP
CBC RTTI, but none of the context-0 pool strings, `mn.dat.enc`/`j1.dat.enc` literals — the client
can read/write the encrypted *message* files but knows nothing about the model dir. Matches the
`RemoveClassifierModelData`-on-upgrade behavior (`enc-data.md`): the installer can destroy and
re-ship the model dir without client involvement.

A QA switch exists: `Pdl.Engine.isSkipEncryptFiles` (`0x142a19248`, read in `FUN_14186fe40`) —
[INFERENCE] bypasses file encryption for testing; never observed enabled in captured runs.

### 1.6 Security assessment (for the clean-room design)

The scheme is obfuscation, not protection: both keys are static, fully recoverable from the
binary (this analysis took a few hours), the IVs are fixed (leaking the 9,584-byte equal-prefix
across `bN` shards noted in `enc-data.md`), and there is no integrity/MAC layer — a tampered
ciphertext decrypts silently (bundle integrity is handled separately at the manifest level, §4).
`re/findings/13-service-ipc/service-ipc.md` §5 reaches the same verdict for the SQLCipher key;
LustLess should not repeat the pattern (see §7).

---

## 2. The six `<id>-<role>.dat.enc` artifacts — role taxonomy (all roles proven)

### 2.1 The 20-hex content id = first 80 bits of the file's SHA-512 — **PROVEN**

`mn.dat.enc` decrypts to the **bundle manifest**:

```json
{"schemaVersion":"1.0.0","bundleVersion":"1.12.3","files":[
 {"download_link":"https://www.covenanteyes.com/files/pdl/805b3533c9a731909930-b3.dat.enc",
  "sha512_hash":"805b3533c9a73190993085b0146db85800669999e708e8645eed4d87b0715e4a1fd61ba6b27a5ec8358df391dcf25b37c171b2597f2d70b81e3481ef25311c53"},
 {"download_link":"…/d8b85cbaabaf6c1e7b15-b2.dat.enc","sha512_hash":"d8b85cbaabaf6c1e7b151d973…"},
 {"download_link":"…/83b568cc34e776439494-b1.dat.enc","sha512_hash":"83b568cc34e77643949439e3…"},
 {"download_link":"…/a076283f3318c8ea4de0-sw.dat.enc","sha512_hash":"a076283f3318c8ea4de0…"},
 {"download_link":"…/cea3215e9378de852a41-j1.dat.enc","sha512_hash":"cea3215e9378de852a41…"}]}
```

(full plaintext recovered; 1,240 B; shown trimmed). Manifest JSON keys map to parsed fields in the
binary: `bundleVersion` `0x142a210d8`, `files` `0x142a210e8`, `download_link` `0x142a210f0`,
`sha512_hash` `0x142a21100` (consumed in `FUN_1418b0440`); `computeFileHexidecimalSHA512Hash`
(`FUN_14199a1e0`, CryptoPP `SHA512` `FileSource`) provides the hash, wrapper `FUN_141994b50`,
called from bundle-verification code `FUN_1418a9a20`.

For each of the five listed files, `sha512_hash` equals the SHA-512 **of the shipped `.dat.enc`
file** on disk (recomputed locally, all five match), and the filename's 20-hex id equals the
first 20 hex chars of that hash. `mn.dat.enc` is not listed in its own manifest, but its name
follows the same rule (`sha512(mn.dat.enc)[:20] = f160caa8342747d04d8f` ✓). This closes the
`[INFERENCE]` in `enc-data.md` §"Naming pattern": **id = SHA-512(encrypted file)[0:80 bits],
role suffix = stable artifact role, manifest = the authority for the download set.**

### 2.2 Role table

| role | cipher size | plaintext size | identified as | confidence |
|---|---|---|---|---|
| `b1`,`b2`,`b3` | 2,323,104 B each | 2,323,088 | **the scoring model** — three shards of the `ensem_3cls-6.1.2` multi-class ensemble (custom CSV-like text: line 1 = `ensem_3cls-6.1.2,<floats>`, then 8,164 further `\n`-separated records) | **proven** (decrypted header) |
| `sw` | 901,200 B | 901,185 | **word/feature data** — header `Snowball NLP 2.0` + `rbf`, 8 stopword lines, then ~901 KB binary word-lexicon structures | **proven** for header; binary tail opaque (deliberately not analyzed) |
| `j1` | 187,248 B | 187,232 | **the hot-updatable JavaScript bundle** (webpack/babel-compiled TypeScript, `var exports = {};` head) loaded as `bundleArtifacts/pdl_js.js` | **proven** (loader code + plaintext head) |
| `mn` | 1,248 B | 1,240 | **the bundle manifest** (JSON, §2.1) — the "default manifest" (`FUN_1418a7ac0` throws `"Cannot find default manifest file"` `0x142a1f338` if `mn.dat.enc`, `PTR_s_mn_dat_enc_14314b2d8`, is absent from the model dir) | **proven** |

So "which role is the scoring model": `b1+b2+b3` together (an ensemble — the header literal
`ensem_3cls` = *ensemble, 3 classes*; per-file line 1 begins `ensem_3cls-6.1.2,157.0,143.0,135.0,…`).
`j1` is the executable logic (scoring/upload orchestration), `sw` its lexical resource, `mn` the
bundle's own index. The suffix is therefore a closed role vocabulary:
`{b-model-shard ×3, stopword/word data, JS bundle, manifest}`. `j1`/`mn` refreshed between
10.1.1 and 10.1.44 (`enc-data.md` naming table) is consistent: script + manifest churn faster than
the base model. The `mn`/`j1` filename literals exist in the C++ (`mn.dat.enc` at
`PTR_s_mn_dat_enc_14314b2d8`, used by `FUN_141897610`/`FUN_1418a7ac0`; `j1.dat.enc` global
`DAT_14314b120` initialized in `FUN_14181bfe0`); `b1/b2/b3/sw` have **no** C++ literals — the
bundle (JS) enumerates them from the manifest, which is why only the two C++-referenced names
appear in the string table.

### 2.3 Per-artifact format tables

**`b1`/`b2`/`b3` (scoring model shards)** — ciphertext 2,323,104 B, context-0 AES-256-CBC,
PKCS#7 (pad byte 0x10). Plaintext (2,323,088 B) is newline-delimited text:

| offset (plaintext) | field | value/evidence |
|---|---|---|
| 0 | model id line (88 B, ends `\n`) | `ensem_3cls-6.1.2,157.0,143.0,135.0,84.32674546073743,84.4511…` (hex: decrypted via `openssl enc -aes-256-cbc -d -nopad -K KEY0 -IV "vWzM6BntW18W4gwq"`) |
| 0–9,585 | **byte-identical across all three shards** (plaintext common prefix = 9,586 B; the ciphertext common prefix 9,584 B = 599 AES blocks from `enc-data.md`) | shared header/metadata section |
| >9,586 | diverges completely (byte-equality ≈ chance) | per-shard payload (contents deliberately not examined — CE model data, out of clean-room scope) |
| whole | 8,165 `\n`-separated records | line-length profile starts `[88, 21, 2, 8, 4, 25, 19, 13, 22, 18, …]` |

Related: the binary also embeds `readNetFromEncryptedONNX` (`0x142a21aa8`, catch helper
`FUN_1418b7540`) and OpenCV-DNN — [INFERENCE] some model families ship as encrypted ONNX; the
10.1.44 bundle manifest lists no ONNX file, so either unused here or supplied via the JS bundle.
Bounded at `FUN_1418b7540`.

**`sw` (word/feature data)** — ciphertext 901,200 B, context-0. Plaintext 901,185 B:

| offset | field | evidence |
|---|---|---|
| 0 | magic line | `Snowball NLP 2.0` |
| 17 | format marker line | `rbf` |
| 21–~120 | 8 stop-word lines | `somewhere`,`me`,`mine`,`what`,`now`,`however`,`re`,`be` |
| ~120–end | binary structures (max `\n`-run 7,091 B) | hexdump tail shows packed 4-byte LE values, e.g. `0f 00 00 cb 2e 00 00 0d…` — [INFERENCE] radix/trie lexicon ("rbf") over the Snowball stopword/vocabulary set |

The consumer is the duktape-exposed `bw.BinarySnowball` class (`dt_method_bw_BinarySnowball_classify`
method strings; `bw` = the balingbuddy namespace that also hosts `bw.DecryptFile`/`bw.File`) —
the class name, the file name `sw`, and the `Snowball NLP 2.0` header align [INFERENCE, strong].

**`j1` (JS bundle)** — ciphertext 187,248 B, context-0. Plaintext 187,232 B of JavaScript
(`var exports = {};` head; compiled from TypeScript — `"TS"` appears in the channel log strings,
`classifier-internals-classifier.md` §C-3). Loaded at startup by `FUN_1418579e0`, which joins
the bundle folder with the global `j1.dat.enc` name (`FUN_141895b00(…, &DAT_14314b120)`),
decrypts via `FUN_141859ab0` (context 0), and hands the source to
`loadScriptContext` (`FUN_1418b47e0`) under the virtual path `bundleArtifacts/pdl_js.js`.
Contents not examined (CE code; covered by the classifier-internals pass's JS-bundle open item).

**`mn` (manifest)** — format in §2.1. Fields: `schemaVersion` (string, `"1.0.0"`),
`bundleVersion` (string, `"1.12.3"` — the value surfaced to the client via `cs.dat` as
`versions.bundle`, `classifier-internals-classifier.md` §C-2; fallback hardcoded `"0.1.0"` in
`generateUpdateCheckRequest` `FUN_1418948e0`, log `"Unexpected: cannot get current bundle
version, will use hardcoded default"` `0x142a1d920`), `files[]` of
`{download_link, sha512_hash}` (128-hex SHA-512 of the encrypted file; download host
`www.covenanteyes.com/files/pdl/`).

---

## 3. Per-user artifacts (`--data` / `--cache` trees)

All three non-empty captured files are context-1 AES-128-CBC+PKCS#7 (§1.4) — i.e. **the message
and control files are encrypted at rest with the same scheme**, which is why
`re/samples/data/entropy-report.txt` shows entropy ~7.99 for `ht.dat`/"4.88" for the tiny `nxu.dat`.
The 0-byte marker files (`rr.dat`, and by extension `pp.dat`/`dd.dat`) are exempt (created via
`ce::FileUtils::createEmptyFile`).

| file | location | cipher→plain | format (all fields recovered) |
|---|---|---|---|
| `nxu.dat` | `cache\bmdat\` | 32→29 B | `{"nextUpdate_sec":1789896962}` — JSON, one key `nextUpdate_sec` (`0x142a1fda8`) = absolute **epoch seconds** of the next bundle update check. 1789896962 = 2026-09-20T09:36:02Z; file mtime 2026-09-20T02:36:03Z ⇒ scheduled **+25,199 s (≈7 h)** after write [INFERENCE: bundle check period 25,200 s]. Readers/writers `pdl_edi::bm_priv::BundleFileManager::set/getNextUpdateTimePoint` (sigs `0x142a20000`/`0x142a1fe80`); corruption paths: `"Corrupt nextUpdate file"` `0x142a1fdb8`, the observed log `"Unable to read nextUpdate file (might not have been created yet)"` |
| `ht.dat` | `data\client\<epoch-ms>\` | 41,760→41,757 B | **score-batch upload request descriptor** (the file the classifier's `BundleManager`/JS writes as a classifier→client message; schema 2.1.0 — this closes open item 4 of `classifier-internals-classifier.md`: the captured high-entropy `ht.dat` is this JSON, encrypted at rest, not a raw HTTP body). Keys: `schemaVersion:"2.1.0"`, `method:"POST"`, `requestFriendlyName:"Feed Batch Upload"`, `authStrategy:"CE_BASIC"`, `urlSafeUsername`, `url:"https://eyesonapi.cvnt.net/images"`, `requestBody{userName, device{device_model,device_name,device_uuid,name,platform}, images[{app, datetime_created, local_utc_offset, evaluationData(list), splicedResult(float), label, baseBlurredImage, image_sha1_hash, pHashImageHash, scoringModel, tags(list)}], stats{analyzedItemsCount(int)}}`, `requestHeaders[{name,value}]`. String values `"str"`/`"dict"`/`"list"` are **template placeholders** filled at send time by the JS bundle [INFERENCE, strong: template shape + sibling's `ht.dat` request-writer analysis]. This is the classifier→backend score channel (`eyesonapi.cvnt.net`), consistent with `upload-protocol.md` §6's negative (no scores in the comm-service uploader). Writer: the classifier C++ has exactly **two** `ht.dat` writers by name (`generateUpdateCheckRequest` `FUN_1418948e0` and `generateFileDownloadRequest` `FUN_141893de0` — exhaustive xrefs to `PTR_s_ht_dat` `0x14314b5e0`); the third, "Feed Batch Upload", has no C++ writer, and the JS bundle has full filesystem capability — `bw.File` fstream (`open/read/write/seekp/tellp/flush/close` method strings) plus the `bw.fs.*` namespace (`bw.fs.create_directories` et al., §1.5) — so [INFERENCE, strong] the bundle itself creates the epoch-ms outbox folder via `bw.fs.create_directories` and writes this descriptor; this also explains the observed JS-written folder containing `ht.dat` **without** `rr.dat` (`ce::FileUtils::createResponseFolder` `FUN_141991470` — which creates the folder *and* the `rr.dat` marker via the `FUN_141991880` funnel — has exactly one caller, so the JS path bypasses both) |
| `su.dat` | `data\pdl\<ISO-ts>\` | 160→154 B | client→classifier **suggestion** message: `{"$schema":"./suggestion_schema.json","importantRequest":"createScreenAccountabilityReportBatchASAP","schemaVersion":"1.0.0","urlSafeUsername":"kckt0717"}` — consumed by `SuggestionProcessor` (`importantRequest` key, `classifier-internals-classifier.md` §C-2). The captured value is the "flush the score batch now" request [INFERENCE: name] |
| `rr.dat` | `data\pdl\<ISO-ts>\` | 0 B | ready marker (state machine `rr→pp→dd`, `classifier-internals-classifier.md` §a) |
| `re4sHXTJFJHReHXTJFJTR.dat` | `data\client\<epoch-ms>\` | 0 B | `re4*` **retention/claim marker**: a folder containing a `re4<token>.dat` file is exempt from the client's transaction-folder GC (`PdlEdi::cleanFolders` `FUN_1402d7820`, glob `re4*.dat` — `classifier-internals-classifier.md` §C-4). No proven writer in either binary's C++ [INFERENCE: client HttpRequestProcessor or JS bundle]. Not a "work batch" |
| `cache\bmdat\` | `--cache` root | — | bundle state dir (holds `nxu.dat`); `bmdat` joined in `FUN_1418569b0` from the literal `0x142a3b010` |
| `cache\ssdat\` (empty), `tmdat`, `exdat`, `vfdat` | `--cache` root | — | sibling cache namespaces, literals `0x142a3b000`–`0x142a3b020` (`exdat`,`vfdat`,`bmdat`,`ssdat`,`tmdat`); only `bmdat` observed; semantics of the other four **opaque** (no log or code anchor beyond the names) |

---

## 4. bundleManager / pdl-edi bundle mechanics

The classifier keeps **two bundle generations** and promotes atomically, with a built-in fallback
to the shipped (model-dir) bundle. Component names are proven (RTTI/signature strings):
`pdl_edi::BundleManager` (BundleManager.cpp), `pdl_edi::bm_priv::BundleFileManager`
(BundleFileManager.cpp), `pdl_edi::ManifestCache` (ManifestCache.cpp).

### 4.1 Locate / load

- `BundleFileManager` tracks three paths: `defaultBundleFileFolder_`, `bundleFileFolder_`,
  `defaultManifestPath_` (log `"BundleFileManager folders/files: <a>,<b>,<c>"` `0x142a1f500`).
  [INFERENCE: default = the `--model` install dir (`mn`/`j1`/`b*`/`sw`), active = an updated copy
  under the cache tree; not further traced.]
- Default manifest discovery: scan the model dir for the file whose name contains `mn.dat.enc`;
  absent ⇒ throw `"Cannot find default manifest file"` (`FUN_1418a7ac0`, literal
  `PTR_s_mn_dat_enc_14314b2d8`).
  `getActiveManifestFilePath` (sig strings `0x142a1f7f0`/`0x142a1f810`); parse via
  `getManifestFromFile` (`0x142a21040`, error `"getManifestFromFile - Unable to parse manifest
  file"` `0x142a20fd0`), cached by `ManifestCache::getManifest` (sig `0x142a211a0`).
  Multiple manifest-shaped files in a folder are deduplicated with removal of the extras
  (`"Unexpected! Multiple files match active/updating manifest file extension. Using the first
  one, removing the rest."` `0x142a1f710`/`0x142a1f890`).
- JS bundle: `<bundleFolder>\j1.dat.enc` → decrypt(ctx 0) → duktape (§1.5).

### 4.2 Update cycle

1. **Schedule.** `BundleManager::onTimeUpdate` (sig `0x142a1e050`) fires on a timer; reads
   `bmdat\nxu.dat` for `nextUpdate_sec`; missing file ⇒ the observed
   `ERR bundleManager: onTimeUpdate error - Unable to read nextUpdate file (might not have been
   created yet)`; on success logs `"onTimeUpdate: generated update check request"` `0x142a1e170`
   and `"onTimeUpdate: set next update timepoint to next update period."` `0x142a1e330` (≈7 h per
   §3). A QA hook `setNextUpdateTimeForQA` exists (sig `0x142a1df30`).
2. **Update check.** `generateUpdateCheckRequest(path, PdlManifest, bool)` (sig `0x142a1d890`,
   line `0x55`) writes the classifier→client request descriptor `ht.dat` (request friendly name
   `"Version update check"` `0x142a1d238`; endpoint `https://api.cvnt.net/v1/desktop_client_update`
   family per `classifier-internals-classifier.md` §C-2). The client executes the HTTP and drops
   the response back as an `hr.dat` message; `BundleManager::onNewFileDownload(folder)`
   (`FUN_141897610`, line `0x14f`) reads `hr.dat` **decrypted with context 1**
   (`FUN_141992350(…,1)`) and parses the response.
3. **Manifest acceptance.** Short-circuits: `"Download request is for the current active bundle,
   nothing to do"` `0x142a1e8b0`; `"Download request is for the default bundle, demote the active
   manifest to use default instead"` `0x142a1e7f0`; `"Already have the manifest we're supposed to
   download, skip download and use manifest directly"` `0x142a1e950`. Otherwise the manifest is
   saved as *updating*: `saveNewUpdatingManifest(path)` (sig `0x142a1fa90`; errors
   `"saveNewUpdatingManifest - could not parse filename: "` `0x142a1fb40` — filenames are the
   `<20hex>-<role>.dat.enc` form, §2.1).
4. **File download.** `generateFileDownloadRequest(path, url, filename)` (sig `0x142a1dae0`,
   line `0x65`, log `"Generating file download request for <url> to <filename>"`,
   friendly name `"Download PDL bundle file"` `0x142a1d250`) emits one `ht.dat` per missing
   file; the raw downloaded bytes land under the descriptor's `responseRawOutputFilename`
   (`"onNewFileDownload: file responseRawOutputFilename is missing"` `0x142a1eda0`, line
   `0x167`); `.dat.rm`/`rm.dat` literals (`0x142a17fe8`/`0x142a17ff0`) are the download-to-temp
   rename residue [INFERENCE]. The special filename `mn.dat.enc` is checked first in
   `onNewFileDownload` (`FUN_141897610`, compare against `PTR_s_mn_dat_enc_14314b2d8`).
5. **Integrity.** Downloaded files are hashed with `computeFileHexidecimalSHA512Hash`
   (`FUN_14199a1e0`, caller chain `FUN_1418a9a20` → `FUN_141994b50`) and compared against the
   manifest's `sha512_hash` [INFERENCE on the exact compare site — bounded at `FUN_1418a9a20`;
   the hash/manifest-key plumbing on both sides is proven]. Whole-bundle validation is
   `performBundleIntegrityValidation` (sig `0x142a1f220`); failure ⇒
   `revertToDefaultBundle` (sig `0x142a1f160`) with telemetry
   `pdl_bundle_integrity_fail_demote_to_default` `0x142a16c10`.
6. **Promotion.** `checkForUpdatingManifestPromotion(cb)` (sig `0x142a204c0`): requires the
   updating manifest and all its files present — `"No Updating manifest file, cannot promote to
   Active."` `0x142a20428` / `"One or more files missing from Updating manifest, cannot promote to
   Active."` `0x142a20600`; then `"Promoting manifest A to active"`/`"Promoting manifest B to
   active"` (`0x142a20730`/`0x142a20778`) — A/B naming ⇒ the two generations alternate slots;
   the old active is removed (`"Removing originalActiveManifestFilePath: "` `0x142a207c0`).
   Inverse: `demoteActiveManifest(bool)` (sig `0x142a20910`), `"Demoting manifest A/B to
   updating"` `0x142a20b40`/`0x142a20b88`; demoting past the last good state logs
   `"Unexpected! A call to demote the active manifest required deleting the updating manifest
   too."` `0x142a20a80`.
7. **JS-layer demotion.** If `jsHook_manageBundles` fails, the engine reverts the script layer:
   `"PDL-EDI: Reverting to the default JavaScript bundle after jsHook_manageBundles failure"`
   `0x142a16090`, and batch state is invalidated: `"PDL-EDI: Purging batch files due to potential
   incompatability with the default bundle"` `0x142a15fd0`; script reload failures demote with
   `"loadScriptContext - could not load, demote to default bundle and try again"` `0x142a16940`
   (telemetry `pdl_bundle_integrity_fail_demote_to_default`).

### 4.3 Relation to the installer (`RemoveClassifierModelData`)

The installer's upgrade step (`enc-data.md` evidence block) destroys `C:\Program Files\CE\data`
and re-ships it with the six current files. Nothing else in the system owns those bytes: the
client has no model-dir strings (§1.5), and the classifier recreates/uses whatever the manifest
names. So the model dir = the *shipped default bundle generation*; runtime updates live in the
per-user cache and are discarded on demotion/upgrade. The 20-hex ids let the server ship a diff
(manifest lists only current files; ids unchanged ⇒ content unchanged), and the installer's
per-name deletion matches the manifest-name set exactly.

---

## 5. Provable vs. opaque (summary)

**Proven** (code + verified decryption): AES-CBC+PKCS#7 scheme, both contexts incl. exact
key/IV derivations; content-id = SHA-512[:20] scheme; all six roles (`b*`=model, `sw`=word data,
`j1`=JS bundle, `mn`=manifest); manifest JSON schema; `nxu`/`ht`/`su` plaintext formats; update
cycle functions and log strings; promotion/demotion/fallback state machine; SHA-512 integrity
plumbing; installer tie-in.

**Opaque / bounded**: `sw` binary-tail structure (identified header only); `bN` per-shard payload
layout (deliberately not examined — CE model data); `j1` JS internals (separate pass);
`imreadEncrypted` body (bounded: catch helpers cluster at
`FUN_1428404e0`–`FUN_1428411xx`, last address `FUN_142840c10`); the exact SHA-512 compare instruction (bounded at `FUN_1418a9a20`); the four
unused cache namespaces (`ssdat/tmdat/exdat/vfdat`); the `re4*.dat` writer (no C++ literal in
either binary).

---

## 6. Evidence

- Local: `re/samples/data/enc/*.dat.enc`, `re/samples/data/classifier-data/{ht.dat,nxu.dat,
  re4sHXTJFJHReHXTJFJTR.dat}`, `re/samples/data/classifier-pdl/{rr.dat,su.dat}`,
  `re/samples/data/entropy-report.txt`; decryption performed with
  `openssl enc -aes-{128,256}-cbc -d -nopad` under the derived keys (recipes §1.2/§1.3);
  SHA-512 of the five shipped `.dat.enc` recomputed locally and matched to the manifest.
- Code: Ghidra program `VictoryShieldClassifier.exe` — `FUN_141996bc0`/`FUN_141996b10` (cipher
  ctors), `FUN_1418b7410` (context selector), `FUN_141995930`/`FUN_141994dd0`/`FUN_141994d30`/
  `FUN_141994b10` (ctx-0 key), `FUN_141995bc0`/`FUN_141995dc0`/`FUN_141995fe0`/`FUN_141995d10`
  (ctx-1 key), `FUN_1418b72b0`/`FUN_1418b70e0` (pad/unpad), `FUN_1418579e0`/`FUN_141859ab0`
  (j1 loader), `FUN_141992350`/`FUN_141993ee0`/`FUN_141993be0` (ctx-1 readers), `FUN_141913d30`/
  `FUN_1418bf960`/`FUN_1418bfc30` (JS crypto APIs), `FUN_141897610`/`FUN_1418a7ac0`/
  `FUN_1418b0440`/`FUN_1418af170`/`FUN_1418a9a20`/`FUN_14199a1e0` (bundle flow), catch helpers
  `FUN_142840530`/`FUN_142840730`/`FUN_142840930`/`FUN_142840c10`; disassembly spot-checks at
  `0x141995c35`/`0x141995c39` (ctx-1 slices), `0x141995f4e`/`0x14199616e` (literal loads),
  `0x14199545b`–`0x1419956a8` (ctx-0 assembly chain).
- Cross-binary: `VictoryShield.exe` contains the ctx-1 literals + CryptoPP CBC RTTI but none of
  the ctx-0 material or model-dir filenames (local `strings -a | grep -cF`, results §1.5).

## 7. Linux mapping implications (analysis only — answers `91-linux-mapping.md` §2 Open item 1(b))

1. **Keying verdict: do not port CE's at-rest crypto.** Both keys are static literals derivable
   from the binary (§1), fixed IVs leak content equality (the 9,584-byte `bN` prefix), and there
   is no MAC. For LustLess: ship model artifacts plaintext inside a root-owned
   `/usr/share/lustless/bundle/` (0755/0644 is fine — the model is not a secret), or if the
   threat model demands at-rest protection use per-file random-nonce AEAD (age/minisign-style)
   with keys from the OS keystore (91 §5's key-management decision), never embedded constants.
2. **Bundle container: adopt CE's shape, concretized.** 91 §2's "content-addressed `<id>-<role>`
   artifacts + plaintext manifest" is now fully specified by a working implementation: manifest
   `{schemaVersion, bundleVersion, files:[{download_link, sha512_hash}]}`, `id = sha512[:20]`,
   roles `{model shards…, script, worddata, manifest}`, download-then-hash-then-promote with
   active/updating A/B slots and demote-to-default on integrity failure (§4). Port the state
   machine (it is crash-safe and small); the "default bundle = the installed one, updates =
   per-user cache" split maps directly onto `/usr/share` vs `/var/lib/lustless`.
3. **Hot-updatable script layer is real and load-bearing** (91 §2's open question): `j1` is a
   compiled-TS duktape bundle that owns scoring orchestration, upload construction (the
   `eyesonapi` score channel, §3 `ht.dat`) and even bundle management (`jsHook_manageBundles`),
   with a C++-enforced fallback when it fails. Decision input for 91: porting it means shipping
   an embedded JS engine + integrity-pinned script updates; declining it means reimplementing
   `processBatches`/upload in native code. Either way keep the *manifest-mediated* update and
   demote-to-default behavior.
4. **Update cadence + schedule marker**: `cache/bmdat/nxu.dat` = single-key JSON with an
   absolute epoch-seconds deadline, written after each check (~7 h) — concretizes 91 §2's
   "`nxu.dat`-style update-schedule marker" exactly; a plain JSON file in the state dir is the
   Linux equivalent.
5. **Message files need no crypto on Linux**: CE encrypts `ht/su/pc/hr/ss` with the shared
   context-1 key purely as obfuscation; a 0700 per-user spool with plaintext JSON (91 §1's
   design) is strictly better (debuggable, no shared-key problem).
6. **Score-channel contract now known** (feeds 91 Open item 4): score batches go to
   `https://eyesonapi.cvnt.net/images` (CE_BASIC auth, per-user), body =
   `{userName, device{…}, images[{app, evaluationData, splicedResult, label, image_sha1_hash,
   pHashImageHash, scoringModel, tags}], stats{analyzedItemsCount}}` — metadata + scores, with
   image fields (`baseBlurredImage`) template placeholders. This is the exact shape LustLess's
   consent-gated "flagged-window/score evidence" record type (91 Open item 4) can adopt or
   deliberately drop.
7. **`su.dat` maps to a "flush uploads ASAP" suggestion message** — one-line JSON with a schema
   ref + `importantRequest` enum + `urlSafeUsername`; trivially portable over the §1 spool.
