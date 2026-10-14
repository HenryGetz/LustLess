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
| 1 | Screen capture + screenstate pipeline | ✗ | X11 MIT-SHM (`capture/src/x11.rs`) ships and works; the Wayland portal + PipeWire backend (`capture/src/wayland.rs`, `wayland-portal` feature) is implemented but **not shipped** — see gap 0. Both backends share the verified file-transaction handoff, ready marker, jittered cadence and the CE retry ladder file-transaction handoff, ready marker, jittered cadence and the CE retry ladder (`capture/src/{spool,manifest,scheduler}.rs`, tests `jitter_stays_within_uniform_bounds`, `retry_ladder_matches_ce_table`); tamper rows for removed/renamed transactions ✓ |
| 2 | Classifier (on-device ML) | ✓ | Real CE bundle decrypts, loads and **scores** — verified end to end on a synthetic 640×480 transaction: `{"app":"firefox","score":0.0,"flagged":false,"scored_windows":1}` with `threshold 0.467` from the calibration artifact and all six artifacts (`b1/b2/b3-scorer`, `sw-labels`, `mn`) loaded; `doNotScore` windows skipped (`classifier/src/consumer.rs`) |
| 3 | DNS/URL filtering | ✓* | Forwarder on 127.0.0.2 with dual resolution, RPZ-style synthetic blocks, block page, browser DoH-lockdown policies; *deviation*: shipped upstream is a CleanBrowsing-family endpoint (open item 5 — redistribution terms) |
| 4 | Local IPC + dashboard | ✓* | Unix socket + `SO_PEERCRED` replaces CE's unauthenticated TCP 48867; the 1-byte code + payload vocabulary is kept; token-authenticated dashboard (401 anonymous, verified) |
| 5 | State stores | ✓* | `ce-file` outbox shape and `queued→sending→sent` kept in SQLite; per-user settings DB is SQLCipher with an OS-held key (CE hardcoded the key — deliberately not copied) |
| 6 | Upload protocol | ✓ | 7 routes, batch claim/reaper, server throttle, clock anchor, 5 record types, **no images/scores ever** (stricter than CE: scores stay local); uploads stall on a 401 instead of re-authenticating — see gaps |
| 7 | Watchdog / persistence / anti-tamper | ✓* | systemd `Restart=always` + `StartLimitIntervalSec=0` (a crash loop keeps DNS alive), logind-gated sessions, per-uid crash budget with CE's ≤3 escalation; *deviation*: no hidden `disable*Protection` exports — one audited polkit action |
| 8 | UI | ✓ | GTK/AppIndicator tray with CE's menu vocabulary, notifications, dashboard in the browser; verified visually on Zorin OS 17.3 Lite (sign-in window, tray icon, menu entry) |
| 9 | Updater | ✓* | JSON feed with `now|later|none` + `critical`, 24 h cadence, ed25519-verified payloads; *deviation*: installs the verified `.deb` rather than using a signed apt repo |
| 10 | Crash reporting + diagnostics | ✗ | `lustlessctl collect-debug` bundles and per-uid crash counters exist; there is **no automatic crash collection/report pipeline** (no minidump/coredump capture, no crash route, no `crash_type`) — CE uploads three zips and a `client_crash{crash_type}` metric |
| 11 | Packaging (Zorin OS) | ✓ | One staging tree → deb/rpm/arch/apk, lifecycle helper, hicolor icons, .desktop entries, polkit policy, browser policies; live-VM verified on Zorin Lite (and five other distros in `TEST-MATRIX.md`) |

## Remaining gaps, ranked

0. **Wayland capture is not in the shipped binaries.** `packaging/build-binaries.sh`
   builds `--no-default-features` for every format, so a Wayland session
   (GNOME: Zorin Core, Ubuntu, Fedora) gets X11/XWayland root capture and a
   logged warning — most of the screen is missed. Turning the feature on is
   *not* a flag flip: the `pipewire` crate's `spa_sys` bindings reference
   libspa symbols/fields newer than the 22.04 (Zorin 17) baseline — the build
   fails, and a binary linked against a newer libspa would fail to load on the
   target. Work: version-tolerant PipeWire access (dlopen the ~15 spa entry
   points used, or a crate pin matching 0.3.48), then a live GNOME/Wayland
   verification of the portal grant and frame extraction.
1. **Crash-reporting pipeline** (§10 above). Work: coredump/minidump
   collection, a crash record type + route in `crates/lustless-net/src/uploader.rs`,
   a report builder wired to `CrashStore` (`crates/lustlessd/src/classifier.rs`),
   and `crash_type` on the existing `client_crash` metric.
2. **Upload auth recovery.** A rotated/expired device token stalls uploads
   (`crates/lustless-net/src/uploader.rs` drops the cached token on 401 with
   no re-auth path) although the device key/secret are stored
   (`lustless-core/src/settings.rs`) and `/v1/auth/signin` is implemented.
3. **`disable_silent_upgrade` grace flag has no producer** — the updater reads
   `SILENT_UPGRADE_GRACE_FILE` (`crates/lustless-net/src/updater.rs`) but
   nothing writes it, so an admin who sets the flag suppresses critical
   updates indefinitely instead of for the CE-documented day.
4. **`org.lustless.disable-protection` has no consumer** — the polkit action
   ships in `packaging/polkit/org.lustless.policy` but only break-glass is
   wired (`crates/lustlessd/src/ipc.rs`), so the documented tamper/uninstall
   action cannot actually be invoked.
5. **Crash test hooks** (`crashatonce`, `ForceCrash*`) absent — CE's support
   affordance for verifying crash handling.
6. **Screensaver gate** is skipped when the session bus is unavailable (the
   daemon runs as a system service); the logind *lock* signal is the gate that
   does apply.
7. **Open policy items** (not code): the shipped DoH endpoint's redistribution
   terms (item 5) and Wayland portal permission persistence on GNOME (item 3,
   now that the backend ships — needs a live GNOME/Wayland session).

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
