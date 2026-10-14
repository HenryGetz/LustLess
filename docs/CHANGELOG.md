# Changelog

## v0.1.11 — screen accountability actually captures and scores

v0.1.10 shipped the Wayland backend but **screen capture did not work at all** on
a real machine, on either backend. Three bugs, all found by running the daemon
on a real X11 desktop rather than a VM, plus one that made a working capture
score nothing:

- **Sessions discovered after startup were silently dropped.** logind's `User`
  property is the struct `(uo)`; the watcher read it as a bare `u32`, so the read
  always failed and `watch_session` returned early. Sessions present at daemon
  start come from `ListSessions` (which already carries the uid) and were fine —
  but every session created *after* that arrives via the `SessionNew` signal and
  needs the property. On a normal boot the daemon starts before anyone logs in,
  so **every** session was dropped and capture skipped every tick as "session
  inactive" forever. Fixed by reading the struct, with a regression test that
  reads the property off real logind and pins the old shape as failing.
- **An ssh session could shadow the desktop.** Session selection ranked by
  liveness only, so on any machine the operator was also ssh'd into, the tty
  session won and the capture path then refused it as a text session. Selection
  now prefers a local graphical session (x11/wayland, not remote) first.
- **The gate and the backend could disagree.** `gate()` allowed a tick if *any*
  session for the uid was active+unlocked, while the backend captured the
  session selection picked. Both now judge the same session.
- **A capture with no window list was never scored.** When the X11 backend could
  not read `_NET_CLIENT_LIST` it wrote `apps: []` and only logged a warning
  claiming a full-frame fallback that did not exist. The classifier scores the
  apps in the manifest, so every capture was analyzed as zero windows — the
  daemon looked perfectly healthy while doing nothing. It now synthesizes one
  full-frame entry per monitor, as the Wayland backend always has.
- Capture failure is no longer silent: "no session tracked for a signed-in uid"
  is a warning naming the defect, not an indistinguishable "session inactive".

Verified on a real X11 session (`Display=:0`, `Type=x11`, alongside five ssh
sessions for the same uid): `session env applied (uid 1000, type X11, display
Some(":0"))` → `backend selected (X11)` → a real 1280×800 capture with 3069
distinct colours, written as a complete spool transaction (PNG + manifest +
`ready`), consumed by the classifier, and scored:
`{"analyzed_count":1,"top_score":0.06666}`. The `client_screenshot` metric row
in the daemon's ledger corroborates the write.

## v0.1.10 — Wayland capture ships (version-tolerant PipeWire bindings)

Screen capture on a Wayland session (GNOME: Zorin Core, Ubuntu, Fedora) now uses
the compositor's ScreenCast portal instead of falling back to X11/XWayland root
capture. The backend existed since v0.1.7 but could not ship, and the reason was
structural rather than a flag: the `pipewire` crate cannot build against the
Zorin 17 / Ubuntu 22.04 baseline. Its `libspa` bindings need symbols and struct
fields that do not exist in libspa 0.3.48 (`spa_meta_first`,
`spa_meta_region_is_valid`, `spa_video_info_raw.flags`), and
`struct spa_video_info_raw` *changed layout* between 0.3.48 and current PipeWire
(`flags` inserted after `format`, `modifier` widened), so no single linked build
could be correct on both 0.3.48 and 1.0.x — and one `.deb` has to cover both.

- **Our own version-tolerant PipeWire bindings** replace the crate
  (`crates/lustless-capture/src/pipewire_sys.rs`): `libpipewire-0.3.so.0` is
  `dlopen`ed and the 25 entry points that exist in 0.3.48 *and* 1.0.x are
  resolved at runtime. The two calls we need that are header macros
  (`pw_core_get_registry`, `pw_registry_add_listener`) are reached through the
  real `spa_interface` vtable — its layout and the `pw_core_methods` member
  order were verified identical across 0.3.48, 1.0.5 and master. Event tables
  carry trailing padding and the 0.3.x version so a newer library's copy stays
  inside our allocation. **No spa struct ever crosses the boundary**: only
  byte-level SPA pods do, which is what makes one build correct on both
  baselines. Consequences: the release build needs neither `libpipewire-0.3-dev`
  nor `libclang-dev`, no shipped binary has a `libpipewire`/`libspa`
  `DT_NEEDED`, and the packages declare PipeWire as a weak dependency
  (`Recommends`/`optdepends`) — absent PipeWire degrades to the X11 path
  instead of failing to install.
- **Our own SPA pod codec** (`pipewire_pod.rs`) replaces the crate's
  `PodSerializer`/`VideoInfoRaw`: it builds the EnumFormat we negotiate and
  parses the format the compositor picks, with every constant read from the
  real headers and independently probed on 22.04 and 24.04 (all 24 print
  identically).
- **Backend fixes found while porting**: the stream no longer asks for
  `PW_STREAM_FLAG_DRIVER` (wrong for a capture stream, and a way to get no
  frames); frame extraction honours `chunk.offset`/`chunk.size`/`chunk.stride`
  instead of assuming a packed stride, rejects DMA-BUF buffers with a log
  instead of reading them, and **queues buffers back** (the old code leaked
  every one); the PipeWire thread builds the whole graph itself instead of
  taking a command channel.
- **Portal permission persistence.** The ScreenCast restore token is stored per
  user (`<state_dir>/<uid>/portal-restore-token`, 0600) and sent back with
  `PersistMode`, so the compositor re-uses the grant instead of re-prompting on
  every login. The portal session is opened on the *session* bus explicitly
  (`Screencast::with_connection`), which is what a root system service needs.
- **The daemon now chooses its backend from the logind session**, not from its
  own environment. A system service has no session environment, so
  `XDG_SESSION_TYPE` was always absent: an X11 desktop would have picked the
  Wayland backend, and the X11 backend could not see `$DISPLAY` at all.
  `sessions.rs` reads the session's `Type`/`Display`/`Remote`/`Leader` and
  derives the environment (`DISPLAY`, `XAUTHORITY`, `XDG_RUNTIME_DIR`,
  `DBUS_SESSION_BUS_ADDRESS`); text and remote sessions are never captured.
- **X11 capture can connect now.** A live run showed the daemon resolving the
  session correctly and then failing with `$DISPLAY variable not set`, because
  logind's per-session `Display` property is empty on real machines (verified on
  Ubuntu 24.04 and Zorin 17.3). DISPLAY/XAUTHORITY are recovered from the
  session leader's `/proc/<pid>/environ`, then from a bounded walk of its
  descendants, then from the ordered `XAUTHORITY` file probe — and only then
  does an X11 session fall back to `:0`.
  *Not fixed by this*: in the same live run the daemon never got past its logind
  gate (`Skip capturing Screenstate (session inactive)` on every tick) even
  though `loginctl` reported `Active=yes` for that session — so **no screenstate
  has ever been observed to be captured on a real desktop**, on either backend.
  See gap 0 in `docs/impl/PARITY.md`.

Verification: 350 workspace tests pass and `clippy -D warnings` is clean; the
FFI layer is covered by an integration test that compiles a stub
`libpipewire-0.3.so.0` from the real headers and drives the wrappers end to end
(registry vtable, pod negotiation, padded-stride extraction, buffer queueing),
plus a test that resolves the real system library when one is installed. The
build was verified in the `ubuntu:22.04` container *without* any PipeWire
headers, and the resulting release binaries were checked for the absence of a
`libpipewire` link dependency. Live VM evidence collected so far (daemon
session resolution, classifier artifact loading) is in `docs/impl/TEST-MATRIX.md`;
the remaining live step — a real compositor granting ScreenCast — is gap 0 in
`docs/impl/PARITY.md`.

## v0.1.9 — hardening: local tamper, fail-open DNS, poisoned queues

Two focused reviews (local attack surface, error paths) were run against the
shipped code; this release fixes what they found. In an accountability client
the person using the machine is the adversary, so the tamper findings matter as
much as crashes.

### Local tamper (any unprivileged user, previously)

- **Dashboard tokens are enforced, not just validated.** `auth` checked the
  token's uid and then discarded it, so any local user could fetch a token over
  the 0666 IPC socket (`0x61`) and drive the signed-in session: sign it out,
  lower the filter level to the weakest, or add an allow-override for `*`.
  Mutating routes now require the token's uid to own the session (403
  otherwise), with a regression test.
- **`0x4c USER_LOGOUT` is session-scoped.** It had no ownership check, so any
  local uid could force a sign-out — and with
  `fail_closed_when_signed_out = false`, stop the filter.
- **`0x61`/`0x43`/`0x4d`/`0x54`/`0x67` are session-scoped.** They leaked the
  signed-in username, filter level/health and outbox path to any uid, minted a
  dashboard token for the caller, and let any uid trigger diagnostics, outbox
  flushes and a feed fetch.
- **Break-glass audit** carries the promised tag on the effect line
  (`org.lustless.break-glass uid=… reason=…`), and the polkit check line
  distinguishes granted from denied.
- **Agent token file** no longer falls back to world-writable `/tmp` (a local
  attacker could pre-create the directory as a symlink and capture the session
  token): `XDG_RUNTIME_DIR` or `~/.local/state`, and a symlinked directory is
  refused.

### Fail-open and queue defects

- **DNS could silently stop filtering while the daemon looked healthy.** A
  forwarder that failed to build (bad `dns.listen`/`doh_url`) or bind (port in
  use) just logged and returned. It is now marked `Outage` and reported to the
  user, `dns.listen`/port values are validated at startup, and an unparsable
  config **refuses to start** instead of silently running with defaults.
- **A fail-closed classifier exit was treated as clean.** It prints `bye` and
  returns 1, so the supervisor skipped the crash budget, the `client_crash`
  metric and the escalation, and respawned the child every 5 s forever with
  screen accountability off. Only a zero exit status is clean now, and spawn
  failures count against the same budget.
- **Rejected (4xx) batches poisoned the queue forever.** The uploader called
  `drop_invalid`, whose predicate only matches *locally* invalid rows, so
  nothing was deleted: the batch stayed `sending`, was reaped, re-claimed
  oldest-first and starved everything behind it. Deterministic rejections now
  delete exactly the claimed rows (with a regression test), and the support-log
  ring is restored on rejection instead of being silently lost.
- **Block pages never loaded.** The synthesized CNAME was owned by
  `blocked.lustless.local` instead of the queried name, so a real stub resolver
  found no chain from the question and returned NODATA. The answer is now
  RFC 1034-shaped (owner = queried name, target = block host).
- **DNS outage no longer pays the DoH timeout per query** (the filter path is
  skipped while the health machine says outage).
- **A second daemon could run.** Two instances shared the outbox, the spool and
  the crash ledger, and the second reported a false crash. `lustlessd` now
  holds an exclusive `flock` on `<state_dir>/lustlessd.pid` and refuses to
  start.
- **Spool hygiene from the daemon**: orphaned transactions are swept on a slow
  cadence (the classifier only did it at its own startup, so a SIGKILLed daemon
  leaked folders — and disk — forever).
- **Shutdown aborts** tasks that overrun their deadline instead of detaching
  them, and the staged update payload is deleted after install.

Verified: the singleton guard (second start exits 1 with a clear message), the
config validation and parse-failure refusal, and the new regression tests
(dashboard ownership, rejected-batch deletion, config validation).
Workspace suite: **313 passed, 0 failed**.

## v0.1.8 — crash-reporting pipeline (CE parity, minus the databases)

The biggest remaining parity gap (`docs/impl/PARITY.md` gap 1) is closed:
`crates/lustlessd/src/crash.rs` implements CE's crash flow with Linux
mechanisms and the same observable behavior.

- **Detection**: a clean-shutdown marker under `<state_dir>/crash/`. A missing
  marker at startup means the previous run died — systemd's `Restart=always` is
  CE's restart helper, so the report is produced by the next start (CE's
  timing). A first-ever start reports nothing (CE's counters start clean).
- **Type**: a panic hook plus fatal-signal handlers (SIGSEGV/SIGABRT/SIGBUS/
  SIGILL/SIGFPE) write the reason, so the metric's `crash_type` is
  `PANIC`/`SIGNAL` where CE hardcodes `GENERIC`; the handlers re-raise so the
  exit status stays a signal.
- **Attachments**: CE's log groups under CE's caps (5 MB per file, 19 MB
  total). `state-summary.json` replaces CE's `debugDB.zip` — LustLess never
  attaches the activity databases (`91-linux-mapping.md` §10, deliberately
  stricter than CE).
- **Counters + metric**: CE's `ClientCrashesAt`/`ClientCrashesSince` pair in
  `install_metadata` (reset window = CE's `0x165a0bc00` ms), the
  `client_crashes` telemetry row, and CE's
  `client_crash{crash_type=…,count=…}` metrics event, cleared after reporting.
- **Test hooks**: `--crashatonce=true` (CE's command-line switch) and
  `[daemon] crash_test_hook = "force"` (CE's `ForceCrashClient` setting).
- Verified end to end: forced SIGABRT → `last-reason=SIGNAL` → next start logs
  `previous run crashed (SIGNAL, 1 in window)`, writes the attachments, emits
  the metric row with `crash_type=SIGNAL`, inserts `client_crashes=SIGNAL:1`,
  clears the counter; a clean run reports nothing (no false positives).
- Package/CLI version `0.1.8`; installer release-pinned to `v0.1.8`.

## v0.1.7 — Wayland capture actually ships; spool survives resource limits

Parity work driven by `docs/impl/PARITY.md` (a subsystem-by-subsystem audit
against the Windows client, with the remaining gaps named and ranked).

- **Wayland capture: the gap is now understood exactly, not papered over.**
  Shipped builds compile out `wayland-portal`, so on a Wayland session (GNOME —
  Zorin Core, Ubuntu, Fedora) capture falls back to X11/XWayland root. Enabling
  it in the build does **not** work on this baseline: the `pipewire` crate's
  `spa_sys` bindings need a libspa newer than Ubuntu 22.04 / Zorin 17 ships
  (0.3.48) — the build fails (`spa_meta_first`, `spa_video_info_raw.flags`) and
  a binary linked against a newer libspa would not load on the target at all.
  Closing it needs version-tolerant (dlopen) PipeWire bindings or a crate pin
  matching 0.3.48; recorded as gap #1 in `docs/impl/PARITY.md`.
- **The spool consumer survives a missing inotify instance.** When the
  per-user inotify instance limit is exhausted, `SpoolWatcher::open` failed and
  the classifier exited (`spool consumer init failed … Too many open files`).
  It now falls back to polling with identical semantics — new ready folders
  only, and renames still classified as `Renamed` via the folder inode — so
  capture/scoring keeps working in containers and on machines with low limits.
- Verified with the **real CE model bundle**: decrypt → load (threshold 0.467
  from the calibration artifact) → score a 640×480 capture →
  `{"app":"firefox","score":0.0,"flagged":false,"scored_windows":1}`.
- `docs/impl/PARITY.md`: status of all eleven subsystems with evidence, plus
  the ranked remaining gaps (crash-reporting pipeline, upload re-auth,
  silent-upgrade grace flag, the unused `disable-protection` action).
- Package/CLI version `0.1.7`; installer release-pinned to `v0.1.7`.

## v0.1.6 — branded sign-in window, verified on Zorin OS Lite

- **The sign-in window shows the CE shield**: the real artwork (88×94, from
  the Windows build — the same image the dashboard embeds) beside the product
  name and an “Accountability — sign in to continue” subtitle, with the window
  icon set as well. It is shipped as
  `/usr/share/lustless/lustless-mark.png` by every format; the dialog renders
  without it if the file is missing.
- `StartupWMClass=lustless-agent` in both `.desktop` entries, so Xfce's window
  list/taskbar and the Zorin/Whisker menu use the CE icon for the running
  window.
- polkit prompts (`org.lustless.break-glass`,
  `org.lustless.disable-protection`) carry the CE shield as their icon.
- Package/CLI version `0.1.6`; installer release-pinned to `v0.1.6`.

Verified on a real **Zorin OS 17.3 Lite** live VM (`docs/impl/TEST-MATRIX.md`
§ “Zorin OS 17.3 Lite”): apt install with no missing dependencies, resolver
stack detected, daemon enabled, the branded sign-in window opening by itself,
the shield in the Xfce notification area, and the menu entry with the shield
icon — screenshots in `target/testbed/zorin-lite-*.png`.

## v0.1.5 — DNS that stays alive (and answers instantly when signed out)

Fail-closed is about *filtering decisions*, not about taking the machine off
the network. Three changes:

- **The installer no longer points system DNS at a filter that is not
  answering.** `lustless-maintainer` probes 127.0.0.2:53 (`dig`/`nslookup`,
  else a listening-socket check) and, when nothing answers, leaves
  `/etc/resolv.conf` alone and says what to do. Previously a machine where the
  daemon could not start (no systemd, crash loop, container) lost *all* name
  resolution — no package manager, no updates, and nothing on screen saying
  why.
- **The daemon is never left dead**: `Restart=always` with
  `StartLimitIntervalSec=0` (was 3 restarts per 10 s, after which systemd gave
  up and left the box without a resolver), OpenRC `respawn_max=0`. The unit
  also re-asserts the DNS redirect on every start
  (`ExecStartPost=… dns-redirect`), so a machine installed while the filter
  was broken becomes filtered as soon as it runs — and the command is a no-op
  when the redirect is already in place.
- **Blocked answers are instant.** Signed-out lookups took ~2 s because
  per-query process attribution (a SOCK_DIAG netlink dump with a 2 s I/O
  timeout) ran *before* the fail-closed shortcut, and that dump never answers
  in restricted environments. The fail-closed branch now returns before
  attribution, and a netlink failure opens a 30 s circuit breaker instead of
  re-paying the timeout on every query. Measured in a container: 2055 ms →
  4–20 ms per query, verdict unchanged (`blocked.lustless.local` →
  127.0.0.2).
- Package/CLI version `0.1.5`; installer release-pinned to `v0.1.5`.

## v0.1.4 — the agent's main loop actually runs

**v0.1.3 shipped a broken agent: its GTK main loop returned the moment it
started.** Everything that needs the loop was dead — the tray menu items
(including “Sign in…”), the status/notification updates, and the automatic
sign-in window v0.1.3 promised. The process only stayed alive on its worker
thread, so it looked installed but did nothing. Fixed:

- **`gio`'s hold guard was dropped immediately.** `app.hold()` returns an
  RAII guard (`#[must_use]`) that releases the application on drop; called as
  a bare statement it was released a line later, and a windowless
  `GtkApplication` whose use count hits zero returns from `run()` right after
  activation. The guard now lives in the agent's context for the process
  lifetime.
- **argv handling**: the program name is kept in the argument list passed to
  `run_with_args` (an empty slice leaves GApplication with argc 0, which also
  returns immediately), with the agent's own `--show`/`--signin` flags
  filtered out first.
- The sign-in dialog's default button pointed at a temporary `gtk::Button`
  that was dropped immediately (GTK critical, no default response); it now
  uses `set_default_response(ResponseType::Ok)`.
- `lustless-maintainer` wrote `user_resolvers = ["a", "b]` — the closing quote
  was appended after the last *space* instead of the last element, so the
  daemon discarded the **whole** configuration file and silently fell back to
  defaults. The list is now quoted per element.
- Package/CLI version `0.1.4`; installer release-pinned to `v0.1.4`.
- `install.sh` opens a read-only filesystem for the SteamOS `pacman` branch
  (`steamos-readonly disable` → `pacman -U` → `steamos-readonly enable`,
  restored on failure too). The installer script was refreshed in place on the
  v0.1.4 release — the four packages are byte-identical to what v0.1.4 shipped.
- Installer branches exercised per family at this version (`docs/impl/TEST-MATRIX.md`):
  apt (Ubuntu 24.04), dnf (Fedora), pacman (Arch), apk (Alpine) — plus
  rpm-ostree and the SteamOS read-only sequence against stubs, since neither
  can run for real in a container.

Verified on a clean container: fresh install via the public one-liner, then a
plain agent start maps a window titled “Sign in to LustLess”.

## v0.1.3 — install → sign-in window, original icons everywhere

- **The installer ends on the login window.** A signed-out agent presents the
  sign-in dialog two seconds after it starts, and the installer starts that
  agent — so on a fresh machine `curl … | sudo bash` goes install → window →
  sign in with no tray, no menu hunting. Same at every graphical login while
  signed out (the autostart entry starts the same agent).
- `lustless-agent --show` (menu entry, re-activation of a running agent)
  presents the window on demand; an in-flight guard stops two dialogs
  stacking while still letting a later click reopen it.
- **Icons match the original client**: the CE shield is installed at every
  size the desktop asks for (`hicolor` 16/24/32/48/256, plus the existing
  pixmap) instead of a scaled 256, the sign-in window now carries the shield
  as its window icon, and the dashboard has a favicon (same mark). The tray
  icon was already the real 32 px mark.
- Package/CLI version `0.1.3`; the installer is release-pinned to `v0.1.3`.

## v0.1.2 — sign-in surface, one-liner installer, honest version numbers

### Install

- **Copy-paste one-liner**, release-pinned and verified unauthenticated on
  Ubuntu 24.04 and Alpine 3.24:
  `curl -fsSL https://github.com/HenryGetz/LustLess/releases/latest/download/install.sh | sudo bash`
  (plus `wget …| sudo bash`, `…| sudo sh`, and the raw-`main` variant).
  `install.sh` is published as a release asset; the README leads with it and
  the per-distro package table moved to "Other ways to install".
- `install.sh` no longer aborts on `set -o pipefail`-less shells, downloads
  into a world-readable temp dir (apt's `_apt` sandbox user could not read
  the 0700 one — it warned "Download is performed unsandboxed as root"),
  installs with Recommends (the Xfce tray host `xfce4-indicator-plugin`),
  and starts the per-user tray agent for the invoking user right away.

### Fixed

- **Application-menu launcher** shipped by every format
  (`/usr/share/applications/lustless-agent.desktop`,
  `Exec=lustless-agent --show`): opens the sign-in dialog when signed out and
  the dashboard when signed in. Previously the package shipped only the
  hidden (`NoDisplay=true`) autostart entry, so there was nothing in the
  application menu and no sign-in path on a desktop without an SNI host.
  `lustless-agent --show` / re-activation of a running agent presents that
  surface; `--signin` is an alias.
- Maintainer helper tolerates a bind-mounted `/etc/resolv.conf` (containers,
  WSL): removal fails `EBUSY` there, which previously aborted the whole
  `configure` step. Its configure message now says the agent starts at login
  and that the installer already enabled it, instead of telling every user to
  run `systemctl --user …` right after the installer had done so.
- **Versions are real again**: package version `0.1.2` (was clobbered in
  place under `0.1.0`, which made upgrades print "Unpacking 0.1.0 over
  0.1.0" and left no way to tell builds apart). Release tag, package
  version, and `lustless --version` (workspace `CARGO_PKG_VERSION`) now
  agree.
- Two test defects that made the suite red for reasons unrelated to the code
  under test: the spool startup-cleanup test hardcoded folder names while
  cleanup derives age from the transaction timestamp *in the name* (it passed
  only on the day the fixture dates were written), and the install-record test
  pinned `client.version` to the literal `0.1.0`. Both now derive their
  fixtures (clock-relative name / sentinel version), so a version or date
  change can no longer masquerade as a bug.

## v0.1.1 — multi-distro packaging + live-VM verification matrix

First release shipping all four package formats and verified against seven
desktop distros (plus the original Zorin/Xubuntu/Ubuntu/Lubuntu matrix).

### Packaging

- **One glibc 2.35 build → four formats**: `.deb` (Debian 13, Ubuntu 22.04+,
  Zorin 17, Linux Mint), `.rpm` (Fedora Workstation, Bazzite via
  `rpm-ostree install`), `pkg.tar.zst` (Arch, SteamOS), `.apk` (Alpine, musl
  build + OpenRC). All assembled from one staging tree (`packaging/stage.sh`)
  with a libc-family guard.
- **One lifecycle helper** `/usr/lib/lustless/lustless-maintainer`
  (`configure`/`remove`/`purge`, idempotent): every format's scriptlets are
  thin callers; install/upgrade/removal semantics cannot drift between
  distros. DNS redirect, browser-policy merge, polkit and unit handling live
  here, with OpenRC branches for Alpine.
- `scripts/install.sh` — universal installer: detects the family, picks the
  package format, installs with the native tool.
- OpenRC service (`lustlessd`), XDG autostart for the tray agent (the only
  agent path on Alpine; safe beside the systemd user unit via
  GApplication single-instance).
- apk is abuild-built and signed; `.deb` dependency bug fixed for Debian 13
  (`policykit-1` → `polkitd`).

### Test matrix (live VMs, each distro's own ISO)

Fedora 44 PASS · Debian 13 PASS · Linux Mint 22.3 PASS · Ubuntu 24.04 LTS
PASS · Arch PASS (payload+configure; live root too small for the full dep
tree) · Alpine (musl + OpenRC lifecycle verified in container; VM install
blocked only by the testbed's community-index reachability) · Bazzite
(rpm scriptlets verified for ostree layering; VM GUI blocked by the Bazzite
Portal dialog). See `docs/impl/TEST-MATRIX.md` for evidence and caveats.

### Testbed

- 6 new qemux VMs (Debian, Mint, Fedora, Arch, Alpine, Bazzite; ports
  8011–8016), ISOs sha256-verified against publishers.
- `packaging/testbed/{serve.sh,vm/vm-install.sh,vm/vm-verify.sh}` —
  per-family install + acceptance harness (§6 checklist).
- `target/testbed/qmon.sh` — QEMU-monitor driver (sendkey/text/screendump)
  used for the matrix runs.
