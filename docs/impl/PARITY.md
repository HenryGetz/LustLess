# PARITY — LustLess vs the Covenant Eyes Windows client

What "parity" means here: every **observable** behavior of the Windows client
(`VictoryShield` 10.1.44, documented in `re/findings/`) is either implemented
with the same user-visible effect, or deliberately deviated from with the
decision recorded in `re/findings/91-linux-mapping.md` § "Decision summary".
CE's surface is pure user mode (`re/findings/01-dynamic-recon/live-surface.md`
§a–§f) — the kernel driver `CEA.sys` has no Linux counterpart to port.

Status column: **✓** implemented and exercised, **✓*** implemented with a
documented deviation, **✗** gap (work named).

| # | Subsystem | Status | Evidence (code / test / run) |
|---|---|---|---|
| 1 | Screen capture + screenstate pipeline | ✓* | **Both** backends ship (v0.1.10): X11 MIT-SHM and the Wayland portal + PipeWire backend. The PipeWire side runs on our own version-tolerant bindings (`capture/src/pipewire_sys.rs`, dlopen — no link dependency, no libpipewire headers at build time) with our own SPA pod codec (`capture/src/pipewire_pod.rs`); all 24 pod constants print identically on 22.04 and 24.04, all 25 dlsym'd symbols resolve against the real 1.0.5 library (`load_resolves_the_system_library_when_pipewire_is_installed`), the release build needs neither `libpipewire-0.3-dev` nor `libclang-dev`, and no shipped binary carries a `libpipewire`/`libspa` `DT_NEEDED`. The FFI contract is exercised end to end against a stub `libpipewire-0.3.so.0` built from the real headers (`tests/pipewire_sys_fake.rs`: registry vtable, `restricted` via the real `spa_dict`, format-pod negotiation, padded-stride frame extraction, buffer queueing). *Deviation*: **no capture has ever been observed end-to-end**, on either backend — the portal grant is unverified (gap 0) and the one live run never cleared the daemon's logind session gate (gap 1). Both backends share the verified file-transaction handoff, ready marker, jittered cadence and the CE retry ladder (`capture/src/{spool,manifest,scheduler}.rs`, tests `jitter_stays_within_uniform_bounds`, `retry_ladder_matches_ce_table`); tamper rows for removed/renamed transactions ✓ |
| 2 | Classifier (on-device ML) | ✓ | Real CE bundle decrypts, loads and **scores** — verified end to end on a synthetic 640×480 transaction: `{"app":"firefox","score":0.0,"flagged":false,"scored_windows":1}` with `threshold 0.467` from the calibration artifact and all six artifacts (`b1/b2/b3-scorer`, `sw-labels`, `mn`) loaded; `doNotScore` windows skipped (`classifier/src/consumer.rs`) |
| 3 | DNS/URL filtering | ✓* | Forwarder on 127.0.0.2 with dual resolution, RPZ-style synthetic blocks, block page, browser DoH-lockdown policies; *deviation*: shipped upstream is a CleanBrowsing-family endpoint (open item 5 — redistribution terms) |
| 4 | Local IPC + dashboard | ✓* | Unix socket + `SO_PEERCRED` replaces CE's unauthenticated TCP 48867; the 1-byte code + payload vocabulary is kept; token-authenticated dashboard (401 anonymous, verified) |
| 5 | State stores | ✓* | `ce-file` outbox shape and `queued→sending→sent` kept in SQLite; per-user settings DB is SQLCipher with an OS-held key (CE hardcoded the key — deliberately not copied) |
| 6 | Upload protocol | ✓ | 7 routes, batch claim/reaper, server throttle, clock anchor, 5 record types, **no images/scores ever** (stricter than CE: scores stay local); uploads stall on a 401 instead of re-authenticating — see gaps |
| 7 | Watchdog / persistence / anti-tamper | ✓* | systemd `Restart=always` + `StartLimitIntervalSec=0` (a crash loop keeps DNS alive), logind-gated sessions, per-uid crash budget with CE's ≤3 escalation; *deviation*: no hidden `disable*Protection` exports — one audited polkit action |
| 8 | UI | ✓ | GTK/AppIndicator tray with CE's menu vocabulary, notifications, dashboard in the browser; verified visually on Zorin OS 17.3 Lite (sign-in window, tray icon, menu entry) |
| 9 | Updater | ✓* | JSON feed with `now|later|none` + `critical`, 24 h cadence, ed25519-verified payloads; *deviation*: installs the verified `.deb` rather than using a signed apt repo |
| 10 | Crash reporting + diagnostics | ✓* | Automatic pipeline (`crates/lustlessd/src/crash.rs`, v0.1.8): crash detection via the clean-shutdown marker, `crash_type` from the panic/fatal-signal hooks, CE's log-group attachments under CE's caps, the `ClientCrashesAt/Since` counter pair, the `client_crashes` telemetry row, and CE's `client_crash{crash_type,count}` metric cleared after reporting; hooks `--crashatonce=true` / `crash_test_hook="force"`. *Deviation (stricter)*: the activity databases are never attached — `state-summary.json` replaces CE's `debugDB.zip` |
| 11 | Packaging (Zorin OS) | ✓ | One staging tree → deb/rpm/arch/apk, lifecycle helper, hicolor icons, .desktop entries, polkit policy, browser policies; live-VM verified on Zorin Lite (and five other distros in `TEST-MATRIX.md`) |

## Remaining gaps, ranked

0. **The portal grant is unverified on real hardware.** Even once gap 1 is
   cleared, this remains. The *shipping* half is closed (v0.1.10): the backend is
   in every build, the
   `pipewire` crate is gone in favour of our own dlopen'd bindings, the build
   needs no pipewire headers and links no libpipewire, and the FFI contract is
   proven against a stub library built from the real 0.3.48 headers plus the
   real 1.0.5 library on a dev host. What is **not** yet observed is a real
   compositor granting ScreenCast and handing us a frame. That work is blocked
   on the *testbeds*, not the code: both VM images ship
   `WaylandEnable=false` in `/etc/gdm3/custom.conf` (so GDM never offers or
   starts a Wayland session — the login screen shows no session chooser), and
   once that is undone the daemon-side path can be exercised; the harness for
   it is staged (`target/serve-cap.sh`: install → offline sign-in → wait for a
   tick → dump the spool, manifest and daemon log). Evidence collected from the
   half-completed live run is already valuable and is recorded in
   `TEST-MATRIX.md` (the daemon resolving the *session's* kind, the classifier
   loading all six CE artifacts, the logind `Display` gap that the X11 path hit
   first).
1. **Screen capture has never produced a screenstate on a real desktop.** In the
   one live installation that reached a running daemon with a signed-in policy and
   a ready classifier (Ubuntu 24.04, 0.1.10), every tick logged
   `Skip capturing Screenstate (session inactive)` while `loginctl` reported the
   session `Active=yes`. The daemon's own registry (`sessions.rs::gate`) returns
   `SessionInactive` when it holds no *active* entry for the uid, so either its
   per-session property reads did not populate `active`/`uid` as expected or it
   never learned about the session at all; the separate `session_gate` in
   `scheduler.rs` has the same failure shape. This was **not** introduced by
   v0.1.10 (the gate is older), but v0.1.10's session-environment work touches
   exactly that watcher, so it needs re-checking with the fix. Until it is fixed,
   screen accountability does nothing on a real machine — this is the most
   important open item in this file, ahead of gap 0.
2. ~~Crash-reporting pipeline~~ — **closed in v0.1.8** (`crates/lustlessd/src/crash.rs`
   with its nine tests, verified end to end: forced SIGABRT → `last-reason=SIGNAL`
   → next start reports `client_crash{crash_type=SIGNAL,count=1}`, the
   `client_crashes=SIGNAL:1` telemetry row, attachments with no database content,
   and CE's counter pair cleared after reporting). Not yet attached to the
   upload channel as a *file*: the recovered protocol has no attachment route
   (CE used BugSplat), so the bundle stays local and is reported by
   `lustlessctl collect-debug`.
3. **Upload auth recovery.** A rotated/expired device token stalls uploads
   (`crates/lustless-net/src/uploader.rs` drops the cached token on 401 with
   no re-auth path) although the device key/secret are stored
   (`lustless-core/src/settings.rs`) and `/v1/auth/signin` is implemented.
4. **`disable_silent_upgrade` grace flag has no producer** — the updater reads
   `SILENT_UPGRADE_GRACE_FILE` (`crates/lustless-net/src/updater.rs`) but
   nothing writes it, so an admin who sets the flag suppresses critical
   updates indefinitely instead of for the CE-documented day.
5. **`org.lustless.disable-protection` has no consumer** — the polkit action
   ships in `packaging/polkit/org.lustless.policy` but only break-glass is
   wired (`crates/lustlessd/src/ipc.rs`), so the documented tamper/uninstall
   action cannot actually be invoked.
6. **Crash test hooks** (`crashatonce`, `ForceCrash*`) absent — CE's support
   affordance for verifying crash handling.
7. **Screensaver gate** is skipped when the session bus is unavailable (the
   daemon runs as a system service); the logind *lock* signal is the gate that
   does apply.
8. **Open policy items** (not code): the shipped DoH endpoint's redistribution
   terms (item 5) and Wayland portal permission persistence on GNOME (item 3,
   now that the backend ships — needs a live GNOME/Wayland session).

## Hardening round (v0.1.9)

Two reviews beyond the subsystem mapping — the **local attack surface** (the
user is the adversary) and **error paths** — found and closed:

| Finding | Impact | Fix |
|---|---|---|
| Dashboard token uid validated then discarded | any local uid could sign the owner out, lower the filter level, or allow-list `*` | ownership enforced per mutation + regression test |
| `0x4c` unguarded | any uid forces a sign-out (filter stops with `fail_closed_when_signed_out = false`) | session-scoped like `0x66` |
| `0x61`/`0x43`/`0x4d`/`0x54`/`0x67` connection-scoped | global state leak + token minting + outbox flushes for any uid | session-scoped |
| break-glass audit line lacked the promised tag | audit trail did not match the policy file | tagged effect line with uid+reason, denials distinguished |
| agent token file fell back to `/tmp` | symlink capture of the session token | `XDG_RUNTIME_DIR`/`~/.local/state`, symlinks refused |
| DNS failure was a log line | **filtering off while the daemon looked healthy** | `Outage` + notification, startup validation, fatal on a broken config |
| classifier fail-closed exit counted as clean | 5 s respawn loop forever, no budget/metric/escalation | only status 0 is clean; spawn failures budgeted |
| 4xx batches used `drop_invalid` | queue starved forever by poison rows | delete the claimed rows (test) |
| block CNAME owned by the block host | **block page unreachable** (stub resolvers NODATA) | RFC 1034 owner = queried name (test) |
| no singleton guard | two daemons sharing the outbox/spool/ledger + false crash report | `flock` on `<state_dir>/lustlessd.pid` |
| spool orphans only cleaned by the classifier | unbounded disk growth | daemon-side sweep |
| DoH timeout paid during a known outage | per-query latency during outages | filter path skipped on outage |

Still open after this round: the download path buffers update payloads without a
size cap before signature verification (`uploader.rs` response handling), and
the `client_crashes` telemetry/`crash_type` split could carry more CE tags.

## How this was audited

Two read-only passes over `re/findings/91-linux-mapping.md` rows 1–5 and 6–11:
for each subsystem, the Windows behavior (cited from `re/findings/`), the
Linux files/symbols that implement it, the missing/partial pieces with
evidence, and the test coverage. The classifier and Wayland findings were then
re-verified by running them:

```sh
# real CE model, end to end (synthetic transaction + real bundle)
./target/debug/lustless-classifier --model=crates/lustless-classifier/models \
  --data=<spool with pdl/<ts>/{im0.png,manifest.json,ready}> \
  --cache=/tmp/cl-cache --version=parity-test < /dev/null
# → {"type":"result", …, "windows":[{"app":"firefox","score":0.0,…}],"scored_windows":1}
```
