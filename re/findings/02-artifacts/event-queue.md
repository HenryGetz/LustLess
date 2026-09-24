# `ce_user_event_message_queue` — fixed-slot IPC message queue (currently empty)

## What it does

`C:\ProgramData\CovenantEyes\VictoryShieldv010.001.044\ce_user_event_message_queue`
(2,896 B = 0xB50) is a small, **fixed-size binary file holding a preallocated
message-queue structure**: a 256-byte superblock (4 header qwords + a 10-entry slot
directory) followed by 10 fixed 264-byte message records (8-byte length + 256-byte
payload). Every record is zero at capture time — the queue is allocated but **empty**.
`[INFERENCE]` The name and shape indicate a memory-mapped hand-off queue for "user event"
messages (login/logout/user-switch/session events) between the Victory Shield service and
its per-user session components; it is created once at startup and never rewritten while
idle (file timestamps: created 2026-09-21 00:22:45, last written 2026-09-21 00:22:45).

Sample location: `re/samples/data/ce_user_event_message_queue` (byte-identical pull).

## Mechanism

### Framing / layout (derived from the constant fields)

The whole file is zeros except 4 header qwords and 10 slot-directory qwords — so the
structure can be read straight off the still-initialized skeleton:

| offset | value | `[INFERENCE]` meaning |
|---|---|---|
| 0x00 | 2 | format version, or number of attached endpoints/refcount |
| 0x08 | 88 (0x58) | size of the leading header block (0x00–0x57), or offset of a head/tail cursor at 0x58 (currently 0) |
| 0x10 | 10 | slot capacity (matches the 10 slot-directory entries) |
| 0x18 | 256 (0x100) | max message payload size in bytes |
| 0x20–0x5F | 0 | reserved / cursor padding |
| 0x60 + 8·i | 0x50 + i·0x108 (i = 0…9) | slot directory: byte offset of message record *i* |
| 0xB0–0xFF | 0 | reserved to the end of the 256-byte superblock |
| 0x100–0xB4F | 0 | 10 message records, 264 B each |

Key arithmetic (facts):

- Slot values: `0x50, 0x158, 0x260, 0x368, 0x470, 0x578, 0x680, 0x788, 0x890, 0x998` —
  uniform stride **0x108 = 264**.
- 264 = **8 + 256**: one 8-byte prefix (length or state) + one 256-byte payload, and 256 is
  exactly the header field at 0x18. `[INFERENCE]` Each record is `u64 length; u8 payload[256]`.
- File size decomposes exactly: 2896 = 256 (superblock) + 10 × 264 (records). With slot
  offsets read **relative to 0xB0** (immediately after the slot directory, where the 0x50
  first offset equals the 80-byte directory's own size), the records tile
  `0x100 … 0xB4F` and end precisely at EOF. `[INFERENCE]` favored tiling. The alternative
  reading (slot values = absolute file offsets, records at `0x50 … 0xA9F`) leaves 176
  trailing bytes unexplained, so it is less likely.

All record bytes are zero → zero-length/unused messages: **queue depth 0 of 10**.

### Queueing mechanism `[INFERENCE]`

Fixed-size file + offset directory + fixed-capacity slots is the classic shape of a
memory-mapped producer/consumer queue (`CreateFileMapping`/`MapViewOfFile`, mapped by the
service and by each client component): writers grab a free slot, fill its 256-byte payload,
set the 8-byte length, and signal an event/semaphore; readers pop and zero the length.
A 10-deep queue of ≤256-byte messages is consistent with low-rate **control/session
messages** (e.g. "user X logged in at T"), not with streamed activity data (which goes to
`ce-file`'s SQLite tables — see `local-db.md`). No trailing strings, no inline payloads,
no magic — the file is a pure struct image.

Alternative hypothesis, kept for the record: the file could instead be a serialized
fixed-record store whose messages are written only when events occur (same layout, no
ring semantics); with the queue empty, ring vs. append-log cannot be distinguished from
this capture alone.

## Evidence

### Full hexdump of nonzero regions (`xxd re/samples/data/ce_user_event_message_queue`)

The complete file is 2,896 bytes; all bytes outside `0x00–0x19` and `0x60–0xa9` are `0x00`
(verified programmatically — "nonzero spans" listing below). Head of the file:

```
00000000: 0200 0000 0000 0000 5800 0000 0000 0000  ........X.......
00000010: 0a00 0000 0000 0000 0001 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 5000 0000 0000 0000 5801 0000 0000 0000  P.......X.......
00000070: 6002 0000 0000 0000 6803 0000 0000 0000  `.......h.......
00000080: 7004 0000 0000 0000 7805 0000 0000 0000  p.......x.......
00000090: 8006 0000 0000 0000 8807 0000 0000 0000  ................
000000a0: 9008 0000 0000 0000 9809 0000 0000 0000  ................
000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

(From 0x00b0 through 0x0b4f — the remaining 2,736 bytes — every byte is `00`; tail-32
hexdump confirms the file ends in zeros.)

### Nonzero-span analysis (python, full file)

```
size: 2896 0xb50
nonzero spans: [('0x0','0x0'), ('0x8','0x8'), ('0x10','0x10'), ('0x19','0x19'),
                ('0x60','0x60'), ('0x68','0x69'), ('0x70','0x71'), ('0x78','0x79'),
                ('0x80','0x81'), ('0x88','0x89'), ('0x90','0x91'),
                ('0x98','0x99'), ('0xa0','0xa1'), ('0xa8','0xa9')]
qword@0x000 = 2 (0x2)
qword@0x008 = 88 (0x58)
qword@0x010 = 10 (0xa)
qword@0x018 = 256 (0x100)
slots@0x60: ['0x50', '0x158', '0x260', '0x368', '0x470', '0x578', '0x680', '0x788', '0x890', '0x998']
deltas: ['0x108' x 9]
tail 32: 0000…0000
```

### Printable strings

`strings -a -t x -n 3 re/samples/data/ce_user_event_message_queue` → **no output** (exit 0).
The file contains no printable run of ≥3 characters anywhere — consistent with a
zero-filled struct image (no trailing strings, no embedded names).

### File timestamps (remote `Get-ChildItem`, 2026-09-24)

```
...\VictoryShieldv010.001.044\ce_user_event_message_queue | 2896 B | created 2026-09-21 00:22:45 | written 2026-09-21 00:22:45
```

## Linux-reimplementation notes

- If an IPC queue is needed between a system service and per-session helpers, prefer a
  Unix domain socket or `eventfd`+shared memory ring; CE's file shows the minimal fixed
  alternative: preallocated slots (10 × 256 B messages) + offset directory + length prefix,
  no dynamic allocation on the write path.
- A queue file that is zero-filled at rest doubles as its own "empty" state — no separate
  metadata file needed; capacity/record-size constants live in the superblock so both
  sides can validate layout after upgrades.

## Open questions

1. Exact record format: is the 8-byte prefix a payload length, a (type, length) pair, or a
   slot-state word? (Unobservable while every record is zero.)
2. What does `qword@0x00 = 2` denote — format version, attached-process count, or queue
   generation? What is `qword@0x08 = 88` exactly (header size vs. cursor offset at 0x58)?
3. Which processes map/produce/consume this file? (Expected: `VictoryShieldCommService.exe`
   and a per-user/session component; needs handle tracing or binary RE — out of scope here.)
4. Ring semantics vs. append-log: is there a head/tail cursor (perhaps the zero qwords at
   0x20/0x58), and is the slot directory rewritten on enqueue?
5. What messages actually flow ("user event" in the name suggests session events —
   do they duplicate `logins`/`switch_users` rows in `ce-file`, or are they transport for
   them)?
6. Why 256 B payload / 10 slots — is the payload JSON, a protobuf, or a packed struct?
