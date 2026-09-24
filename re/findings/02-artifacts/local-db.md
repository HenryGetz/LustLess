# `ce-file` — local SQLite3 activity/reporting database

## What it does

`C:\ProgramData\CovenantEyes\VictoryShieldv010.001.044\ce-file` (835,584 B) is a plain,
unencrypted **SQLite 3 database** (magic `SQLite format 3`, page size 4096, 204 pages,
journal mode WAL but no `-wal`/`-shm` sidecar present at capture time). It is the client's
local system-of-record for accountability-relevant events — DNS lookups, app-blocking
"circumvention" interruptions, logins/logouts, fast-user-switching — plus a telemetry
rollup table (`metrics`) and one install-metadata key. Every event table carries the same
`(status, status_changed_at, created_at)` triple, i.e. rows live through a sync lifecycle
and are presumably marked `sent` after upload to the Covenant Eyes backend.

Sample location: `re/samples/data/ce-file` (byte-identical pull, 2026-09-24).

## Mechanism

### Storage facts

- File header confirms SQLite3, page size 4096, write version 2 / read version 2 (WAL),
  `user_version 0`, 204 pages, freelist 0.
- `PRAGMA journal_mode` returns `wal`. No `ce-file-wal` / `ce-file-shm` files existed at
  capture (directory listing below), so the DB is cleanly checkpointed when idle.
- `install_metadata.db_created_at = 2026-09-21T05:22:39Z`; the file's creation timestamp on
  disk is 2026-09-21 00:22:40 local (UTC−5), consistent — the DB is created fresh by the
  current install (`InstallMode=upgrade` preserved the old config instead of this DB).

### Tables (full schema verbatim in Evidence)

| table | columns | rows @ capture |
|---|---|---|
| `install_metadata` | key, value | 1 |
| `logins` | id, username, system_user_id, system_user_name, timestamp, login_at, logout_at, status, status_changed_at, created_at | 0 |
| `metrics` | id, username, metric_name, bucket_id, tags, fields, utc_timestamp, bucket_size, bucket_current, status, status_changed_at, created_at | 194 |
| `circumventions` | id, username, interruption_type, app_name, app_window_title, device_id, timestamp, timezone_offset, status, status_changed_at, created_at | 0 |
| `switch_users` | id, username, switch_user_from, switch_user_to, timestamp, timezone_offset, device_name, device_id, status, status_changed_at, created_at | 0 |
| `dns_activity` | id, username, domain, process_id, process_name, datetime_created, ip, resolution_type, connection_type, resolution_datacenter, resolution_time_ms, status, status_changed_at, created_at | 0 |
| `sqlite_sequence` | name, seq | 1 (metrics → 194) |

Two partial indexes exist for the sync/upload path:
`circumventions_matching (username, status, interruption_type)` and
`dns_activity_matching (username, status, process_name, datetime_created)` — note both lead
with `(username, status, …)`, i.e. "find this user's rows in this sync state" is the
hot query. `[INFERENCE]` The index shape is direct evidence of a pick-up-where-you-left-off
uploader scanning by `status`.

### Per-table detail

**`install_metadata`** — key/value store; single row `db_created_at → 2026-09-21T05:22:39Z`.
`[INFERENCE]` Written once by `VictoryShieldCommService.exe` at DB creation.

**`logins`** — CE-account session tracking: `login_at`/`logout_at` plus a `system_user_*`
pair mapping the OS account to the CE account. Columns `status`/`status_changed_at`/`created_at`
follow the shared sync-lifecycle pattern. Empty at capture (0 rows). `[INFERENCE]` Writer is
the comm service's session watcher (evidence: table shape + the parallel `switch_users`
table); no binary RE proof yet.

**`switch_users`** — records Windows fast user-switching transitions (`switch_user_from` →
`switch_user_to`, `device_name`, `device_id`, `timezone_offset`). Empty at capture.
`[INFERENCE]` Fed by the session-change notifications the service already receives (see
live recon findings); row shape matches an "event" uploader identical to `logins`.

**`dns_activity`** — one row per DNS resolution observed by the client: `domain`, `process_id`,
`process_name`, `ip`, `resolution_type`, `connection_type`, `resolution_datacenter`,
`resolution_time_ms`. Empty at capture (no browsing activity on the VM). `[INFERENCE]`
Writer is the DNS-proxy path (registry `DnsProxyDisable` and the DNS tables exist precisely
because the client observes resolutions); rows are the raw material for the "browsing
history" half of accountability reporting.

**`circumventions`** — "interruption" events: `interruption_type`, `app_name`,
`app_window_title`, `device_id`, `timestamp`, `timezone_offset`. Empty at capture.
`[INFERENCE]` Writer is the screen/window-monitoring component ("Victory Shield" blocking
UI); `app_window_title` can't come from anywhere else. These are the events that alert
an accountability partner about attempted circumvention.

**`metrics`** — telemetry rollups, 194 rows, all `username = <redacted>` (a single
sentinel-like token on this VM; `COUNT(DISTINCT username)=1`). Time range
`2026-09-21T05:22:44Z … 2026-09-24T17:31:30Z` (192 distinct bucket timestamps).
Metric names: `client_api_success` ×191, `client_network` ×2, `client_startup` ×1.
Bucketing: `bucket_size = 3600` (1 h), `status` ∈ {`sent` (192), `collecting` (2)}.
- `bucket_id` holds a JSON array of indexed dimension tags (`client_component=service`,
  `client_version=10.1.44`, `device_cpu=Intel64`, `device_manufacturer=QEMU`,
  `os_name=Windows`, `os_version=11.0`, `host_name=api.cvnt.net`,
  `http_response_code=200`, `ce_cluster=slc_1b`, `mac_address`, …).
- `tags` holds a parallel JSON array with explicit aggregation semantics
  (`"aggregation": "INCIDENTAL" | "INDEXED" | "CARDINAL"`).
- `fields` holds the measured value, e.g. `[{"name":"startup_count","operation":4,"value":1}]`.

`[INFERENCE]` `metrics` is a client-side time-bucketed metrics buffer (1-hour buckets,
`bucket_current` counts seconds accumulated in the open bucket: 3600 = complete, 0 = just
opened) uploaded to Covenant Eyes' telemetry ingest (`api.cvnt.net`, cluster `slc_1b`) and
then flipped `collecting → sent`. The row shape (indexed tags + cardinal/incidental tags +
operation-coded fields) is a generic metrics pipeline, not accountability data per se —
but it shares the DB with the event tables, so one SQLite file backs both "report what the
user did" and "report how the client itself is doing".

### Relation to accountability reporting

The four event tables are exactly the data an accountability report needs: **who**
(`username`), **when** (`timestamp`/`datetime_created`, `timezone_offset`), **what**
(domain, app+window title, login/logout, user switch), and **how it ended** (`status`).
The uniform `status`/`status_changed_at`/`created_at` triple plus `(username, status, …)`
indexes implies an outbox pattern: events are inserted locally as they happen, then a
uploader marks them `sent` after the backend acknowledges. `[INFERENCE]` Until RE proves the
writer/uploader functions in `VictoryShieldCommService.exe`, treat the exact status values
for the empty tables as unknown; `metrics` demonstrably uses `collecting`/`sent`.

For LustLess: this schema is a reasonable starting point — one local SQLite file, event
tables keyed by (username, status), a separate metrics namespace, and an upload-then-mark
lifecycle that tolerates offline operation.

## Evidence

### Full schema (verbatim, `sqlite3 re/samples/data/ce-file '.schema'`)

```sql
CREATE TABLE install_metadata (key TEXT  COLLATE NOCASE,value TEXT,PRIMARY KEY(key));
CREATE TABLE logins (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT KEY COLLATE NOCASE,system_user_id TEXT KEY,system_user_name TEXT,timestamp TEXT,login_at TEXT,logout_at TEXT,status TEXT KEY,status_changed_at TEXT,created_at TEXT);
CREATE TABLE sqlite_sequence(name,seq);
CREATE TABLE metrics (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT COLLATE NOCASE,metric_name TEXT KEY,bucket_id TEXT KEY COLLATE NOCASE,tags TEXT,fields TEXT,utc_timestamp TEXT KEY,bucket_size INTEGER,bucket_current INTEGER,status TEXT,status_changed_at TEXT,created_at TEXT);
CREATE TABLE circumventions (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT COLLATE NOCASE,interruption_type TEXT,app_name TEXT,app_window_title TEXT,device_id TEXT,timestamp TEXT KEY,timezone_offset TEXT,status TEXT,status_changed_at TEXT,created_at TEXT);
CREATE INDEX circumventions_matching ON circumventions (username, status, interruption_type);
CREATE TABLE switch_users (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT KEY COLLATE NOCASE,switch_user_from TEXT,switch_user_to TEXT,timestamp TEXT,timezone_offset TEXT,device_name TEXT,device_id TEXT,status TEXT,status_changed_at TEXT,created_at TEXT);
CREATE TABLE dns_activity (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT COLLATE NOCASE,domain TEXT,process_id TEXT,process_name TEXT KEY,datetime_created TEXT KEY,ip TEXT,resolution_type TEXT,connection_type TEXT,resolution_datacenter TEXT,resolution_time_ms TEXT,status TEXT,status_changed_at TEXT,created_at TEXT);
CREATE INDEX dns_activity_matching ON dns_activity (username, status, process_name, datetime_created);
```

Note the odd `TEXT KEY` column constraints (non-standard but legal SQLite — no effect);
the real keys are the `PRIMARY KEY`/index declarations.

### Row counts (`SELECT COUNT(*)` per table)

```
circumventions: 0
dns_activity: 0
install_metadata: 1
logins: 0
metrics: 194
sqlite_sequence: 1
switch_users: 0
```

### Sample rows (usernames redacted; structure preserved)

`install_metadata`:
```
key              | value
db_created_at    | 2026-09-21T05:22:39Z
```

`sqlite_sequence`:
```
name    | seq
metrics | 194
```

`metrics` (columns compressed to fit; `bucket_id`/`tags` are long JSON arrays):
```
id=1 | <user> | client_startup     | 2026-09-21T05:22:44Z | 3600 | 3600 | sent | 2026-09-21 06:28:50 | 2026-09-21 05:23:45
id=2 | <user> | client_api_success | 2026-09-21T05:22:45Z | 3600 | 3600 | sent | 2026-09-21 06:28:50 | 2026-09-21 05:23:45
id=3 | <user> | client_network     | 2026-09-21T05:22:45Z | 3600 | 3600 | sent | 2026-09-21 06:28:50 | 2026-09-21 05:23:45
```

`metrics.bucket_id` (row 1, excerpt — JSON tag array):
```json
[{"indexed":true,"name":"client_component","value":"service"},
 {"indexed":true,"name":"client_version","value":"10.1.44"},
 {"indexed":true,"name":"device_cpu","value":"Intel64"},
 {"indexed":false,"name":"device_id","value":"undefined"},
 {"indexed":true,"name":"device_manufacturer","value":"QEMU"},
 {"indexed":false,"name":"device_model","value":"Standard PC (Q35 + ICH9, 2009)"},
 {"indexed":false,"name":"mac_address","value":"<redacted-mac>"},
 {"indexed":true,"name":"os_name","value":"Windows"},
 {"indexed":true,"name":"os_version","value":"11.0"},
 {"indexed":true,"name":"startup_type","value":"normal"},
 {"indexed":false,"name":"user_id","value":"undefined"}]
```

`metrics.tags` (row 2, excerpt — aggregation annotations):
```json
[{"aggregation":"INCIDENTAL","name":"bucket_size","value":"3600"},
 {"aggregation":"INDEXED","name":"ce_cluster","value":"slc_1b"},
 {"aggregation":"INDEXED","name":"client_component","value":"service"},
 {"aggregation":"INDEXED","name":"client_version","value":"10.1.44"}, ...]
```

`metrics.fields` (row with a measured value):
```json
[{"name":"startup_count","operation":4,"value":1}]
```

Metric/status distribution:
```
client_api_success | 191
client_network     | 2
client_startup     | 1
status: collecting | 2    (bucket_current=0)
status: sent       | 192  (bucket_current=3600)
```

### File header (`xxd -l 100 re/samples/data/ce-file`)

```
00000000: 5351 4c69 7465 2066 6f72 6d61 7420 3300  SQLite format 3.
00000010: 1000 0202 0040 2020 0000 00c3 0000 00cc  .....@  ........
00000020: 0000 0000 0000 0000 0000 0008 0000 0004  ................
00000030: 0000 0000 0000 0000 0000 0001 0000 0000  ................
```
(0x10: page size 0x1000 = 4096; 0x12–0x13: write/read version 2 = WAL; 0x1c–0x1f: database size in pages = 0xcc = 204; 0x24: freelist count = 0.)

`PRAGMA` output:
```
page_size: 4096
page_count: 204
freelist_count: 0
user_version: 0
journal_mode: wal
```

### File timestamps (remote `Get-ChildItem`, 2026-09-24)

```
...\VictoryShieldv010.001.044\ce-file | 835584 B | created 2026-09-21 00:22:40 | written 2026-09-24 12:31:34
```
Last write 12:31:34 local = 17:31:34 UTC matches `MAX(metrics.utc_timestamp) =
2026-09-24T17:31:30Z` — the service flushes metrics rows within seconds of collecting them.

## Linux-reimplementation notes

- Reuse the schema shape: per-event tables with a shared `(status, status_changed_at,
  created_at)` outbox triple and `(username, status, …)` indexes; a single SQLite file in
  a per-install versioned directory.
- Time-bucket metrics (3600 s) with `bucket_current` counting accumulation into the open
  bucket; store dimension tags as JSON with aggregation annotations instead of one column
  per dimension.
- Keep telemetry (`metrics`) separate from accountability events in the same DB — reports
  and self-diagnostics have different retention/upload needs.
- Timestamps: store event time as ISO-8601 UTC (`…Z`) plus a separate `timezone_offset`
  string for local-time rendering, as CE does.

## Open questions

1. Which process/functions write each table? (Expected: `VictoryShieldCommService.exe`;
   unproven — no binary RE in this task.) The exact `INSERT` statements and the status
   state machine for `logins`/`dns_activity`/`circumventions`/`switch_users` are unknown
   (those tables were empty at capture).
2. What status values do the event tables use before upload? (`metrics` uses
   `collecting`/`sent`; event tables may use `pending`/`sent`/etc.)
3. Is the username column ever a real CE account name, or always the sentinel-like token
   seen here (`COUNT(DISTINCT username)=1` on this VM)?
4. What are `metrics.fields` `operation` codes? (`operation: 4` seen on `startup_count`;
   sum/min/max/count semantics `[INFERENCE]`.)
5. Retention/pruning policy: `freelist_count=0` and 204 pages suggest rows are deleted after
   upload or after a TTL, but the pruning SQL is unobserved.
6. Is `ce-file` renamed/recreated per version (`VictoryShieldv010.001.044` directory), i.e.
   does an upgrade migrate rows or start fresh? (This DB was created 2026-09-21 at install.)
