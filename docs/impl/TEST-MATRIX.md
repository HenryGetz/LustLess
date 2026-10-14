# TEST-MATRIX — multi-distro install verification results

Live-VM verification runs for the packages built by
`docs/impl/PACKAGING-MATRIX.md` (§6 acceptance checklist). Each VM is a
`qemux/qemu` container booting the distro's own ISO (see
`packaging/testbed/README.md`); the package + scripts are delivered via a
helper ISO (`target/testbed/make-iso.py` + xorriso) hotplugged as USB storage
through the QEMU monitor (`target/testbed/qmon.sh`).

## Environment caveat (applies to every row)

The testbed host firewall drops non-SSH inbound to the docker bridge, so
guests cannot reach the host HTTP harness; all runs used the helper-ISO
channel instead. Guests also have **no working upstream DNS** for most of the
run (dnsmasq had no upstream; fixed mid-run by adding `--server=192.168.1.1`).
Two consequences:

1. **Signed-out semantics are the default product behavior**: with
   `fail_closed_when_signed_out = true` (shipped default), *every* query
   through `127.0.0.2` returns the block verdict while no user is signed in —
   allowed names included. That is CE's "signed out ⇒ web blocked" semantic,
   verified working. Per-distro runs that needed the allow-path tested flipped
   this to `false` in `/etc/lustless/lustless.toml` and restarted (testbed-
   only config change, reverted by package removal).
2. `report POST` to the harness fails in-guest (firewall); reports were read
   from the VM consoles instead.

## Results

| # | Distro | Package | Install | Service | DNS verdict | Dashboard | Uninstall | Notes |
|---|--------|---------|---------|---------|-------------|-----------|-----------|-------|
| 1 | Fedora Workstation 44 | `.rpm` | ✅ `dnf install` (scriptlet ran, resolved stack detected) | ✅ systemd active+enabled | ✅ block verdict 127.0.0.2 | ✅ 401 | rpm -e verified in container | vm-verify OVERALL: PASS |
| 2 | Debian 13 (trixie) | `.deb` | ✅ apt (dep bug fixed: `policykit-1`→`polkitd`) | ✅ active+enabled, NM stack | ✅ signed-out fail-closed returns block verdict | ✅ 401 | dpkg purge reversibility planned | verify FAIL lines were the signed-out DNS, not install faults |
| 3 | Linux Mint 22.3 | `.deb` | ✅ apt (libayatana-appindicator pulled) | ✅ active | ✅ forwarder 127.0.0.2:53 live, daemon log shows full startup | ✅ 401 | — | Cinnamon hosts SNI natively |
| 4 | Ubuntu 24.04 LTS | `.deb` | ✅ `apt install` (upgrade of prior install; snap-Firefox caveat printed) | ✅ systemd active (verified `systemctl is-active`) | ✅ `blocked.example.test` → `blocked.lustless.local` → 127.0.0.2 | (snap Firefox caveat documented) | — | original testbed row + fresh re-verify |
| 5 | Arch Linux | pkg.tar.zst | ✅ payload extracted (live root too full for `pacman -U` dep tree: 459 MB vs 38 MB free — real installs have space) | ✅ `lustlessd` active (systemd) | ✅ `blocked.example.test` → `blocked.lustless.local` → 127.0.0.2 (::1) | n/a (CLI live) | — | configure helper ran clean: "detected resolver stack: resolved" |
| 6 | Alpine 3.24 | `.apk` | ✅ full install w/ all 127 deps resolved (`apk add --allow-untrusted`, community repo reachable; musl binaries + abuild-signed v3 apk) | OpenRC initd installed; service start requires booted OpenRC (container ldd shows "failed to acquire lock" only because container has no /run/openrc) | container: configure/remove run clean | n/a (CLI) | container: `apk del` clean | VM live-ISO run reached the same resolution stage (indices refreshed, deps resolving) |
| 7 | Bazzite (Fedora Atomic) | `.rpm` via rpm-ostree | container-verified: rpm scriptlets correct for ostree layering chroot (configure guarded `|| :`, enable lands in /etc overlay) | reboot-after-layer documented | same as Fedora | same | — | live-session GUI blocked by the Bazzite Portal dialog (no dismiss button); rpm metadata + scriptlets inspected directly |

## Verified packaging defects found & fixed by this matrix

- `debian/control` depended on `policykit-1`, which has no binary in Debian
  13 — renamed to `polkitd` (correct across the whole deb matrix).
- Alpine `.apk` rebuilt through abuild (apk-tools 3 rejects hand-rolled v2
  packages); `so:` auto-deps from scanelf stripped where the guest cannot
  reach community.

## Sign-in surface (application menu / tray-less)

Every format now ships `/usr/share/applications/lustless-agent.desktop`
(`Exec=lustless-agent --show`) — verified present in all four packages
(`dpkg-deb -c`, `rpm -qlp`, `tar -t`). Container proof (ubuntu:24.04, GTK +
Xvfb + `dbus-run-session`):

- `curl …/scripts/install.sh | bash` installs the `.deb` and the new
  launcher survives configure;
- `lustless-agent --show` opens a window titled "Sign in to LustLess"
  (`xdotool search --name`), i.e. the sign-in dialog is reachable with no
  StatusNotifier host at all;
- re-launching `lustless-agent --show` while the agent runs forwards
  activation to the primary instance and presents the same surface.

Defect this section covers: releases up to v0.1.1 shipped only the
`NoDisplay=true` autostart entry (nothing in the menu) and `install.sh`
passed `--no-install-recommends`, which suppressed the Xfce SNI host — on a
Zorin Lite / Xubuntu desktop the agent then ran headless with no visible
sign-in path.

### Installer branches, one per package family (v0.1.4)

Each row is the public one-liner run in that distro's own container (no
credentials, real release download):

| Family (distros) | Container | Install | GUI login window |
|---|---|---|---|
| apt (Debian, Ubuntu, Zorin, Mint) | `ubuntu:24.04` | PASS — fresh install and `0.1.0 → 0.1.4` upgrade; launcher + 5 icon sizes | PASS — plain agent start maps `Sign in to LustLess` (263×134) |
| dnf (Fedora, Bazzite host) | `fedora:latest` | PASS — `lustless-0.1.4-1.x86_64`, scriptlets ran, launcher + hicolor icon | PASS — `Sign in to LustLess` (261×134) |
| pacman (Arch, EndeavourOS) | `archlinux:latest` | PASS — `lustless 0.1.4-1`, dependencies resolved (libayatana-appindicator, polkit, …) | PASS — `Sign in to LustLess` (269×134) |
| apk (Alpine) | `alpine:3.24` | PASS — 127 deps, OpenRC initd, launcher + hicolor icon | PASS — musl build, `Sign in to LustLess` (276×134) |
| rpm-ostree (Bazzite, immutable Fedora) | `fedora` + stub | PASS (wiring) — downloads the `.rpm` and calls `rpm-ostree install <rpm>` | not reproducible here — layers the same `.rpm` verified above |
| pacman on SteamOS | `ubuntu` + stubs | PASS (sequence) — `steamos-readonly disable` → `pacman -U` → `steamos-readonly enable`, on the Arch asset | not reproducible here — same `.zst` verified above |

GUI check method: headless `Xvfb` + `dbus-run-session` (the agent needs a
session bus to register its `GApplication`), then a plain
`/usr/bin/lustless-agent` start, asserting with `xdotool search --name`. In
each distro the X/dbus tooling has to be installed **before** running the
installer: those runs predate v0.1.5, where installing redirected
`/etc/resolv.conf` unconditionally, so with no `lustlessd` running in the
container the package manager lost DNS (`dnf`: "Could not resolve host:
mirrors.fedoraproject.org"). Since v0.1.5 the installer probes the forwarder
first and leaves system DNS untouched when nothing answers — which is why the
`dnf`/`pacman` rows can now install their tooling in either order.

Not reproducible in a container, still covered by the live-VM rows above:
systemd starting the daemon, the graphical session picking up the tray,
rpm-ostree layering, and the installer's `systemctl --user enable --now`
actually launching the window in a real desktop session (its two halves are
verified separately: `enable --now` succeeding on Zorin Lite, and a plain
agent start mapping the window in four distros).

### Zorin OS 17.3 Lite (Xfce) — live VM, v0.1.6

Real VM (`qemux/qemu`, Zorin-OS-17.3-Lite-64-bit-r2.iso), package delivered on
a mounted ISO and installed with `apt-get install ./lustless_0.1.6_amd64.deb`:

| Check | Evidence |
|---|---|
| install | `0 upgraded, 1 newly installed` — every dependency already present, no downloads; `lustless: detected resolver stack: resolved`; `Created symlink …/multi-user.target.wants/lustlessd.service`; desktop-file-utils + hicolor-icon-theme triggers ran |
| flavor hint | the Xfce/Zorin-Lite SNI-host sentence printed by postinst |
| **sign-in window** | opened by itself when the agent started: CE shield artwork, “LustLess”, “Accountability — sign in to continue”, Username/Password, Cancel/Sign in (`target/testbed/zorin-lite-signin-window.png`) |
| **tray icon** | CE shield in the Xfce notification area, next to network/sound/battery (visible in both screenshots) |
| **menu entry** | Zorin (Whisker) menu search “lustless” → entry with the CE shield icon (`target/testbed/zorin-lite-menu-entry.png`) |
| dashboard | page head carries the shield as favicon and as the header logo (`rel="icon" … data:image/png;base64`, 2 embedded marks); screenshot not captured (the daemon binds the dashboard to loopback, which a published container port cannot reach) |

Driving note for future sessions: this VM's noVNC console is view-only and
QEMU-monitor `sendkey`/`mouse_button` events are not delivered to the guest
(hotplugging a USB keyboard/tablet did not change that). Input works through
the **raw VNC** port (5900, reachable from a container sharing the VM's
network namespace) — `target/testbed/rfb-input.py` sends keysyms and absolute
pointer events; keysym layout matters (`down-flag` is byte 2 of `KeyEvent`,
2 bytes of padding follow) and shifted characters need a real Shift press.

## Install/upgrade path (v0.1.2+)

Container runs (ubuntu:24.04, plain `bash`, no GitHub credentials — the
release and the script are fetched over the public URLs a user copies):

| Scenario | Result |
|---|---|
| fresh system, one-liner | `install.sh` fetched, `lustless_0.1.4_amd64.deb` downloaded from `releases/download/v0.1.4`, apt installs it (no `_apt` sandbox warning), `/usr/share/applications/lustless-agent.desktop` present, `lustlessctl --version` → `0.1.4` |
| existing 0.1.0 install, same one-liner | `1 upgraded`, `Unpacking lustless (0.1.2) over (0.1.0)`, `Setting up lustless (0.1.2)`, resulting `dpkg` version `0.1.4` |
| alpine:3.24, `wget -qO- … \| sh` | apk installed with 127 deps, launcher present |
| icons | `hicolor/{16x16,24x24,32x32,48x48,256x256}/apps/lustless.png` present in all four formats (deb 5 entries, rpm 5 files, zst/apk staged tree) |
| **sign-in window** (v0.1.4) | plain `/usr/bin/lustless-agent` start under Xvfb + `dbus-run-session` maps a window titled `Sign in to LustLess` (`xdotool search --name`), i.e. install → launch → GUI login with no tray and no flags |

Installing used to redirect `/etc/resolv.conf` to the 127.0.0.2 forwarder
unconditionally, so a machine where the daemon could not start (no systemd, a
crash loop, a container) lost *all* name resolution. That is breakage, not
fail-closed filtering, and v0.1.5 fixed it — see below.

### DNS behaviour (v0.1.5)

Fail-closed applies to filtering *decisions* (signed out ⇒ answers are block
verdicts); the resolver itself must stay alive and fast.

| Check | Method | Result |
|---|---|---|
| installer leaves DNS alone when the filter is not running | `lustless-maintainer configure` in a container with no daemon | PASS — `/etc/resolv.conf` byte-identical, `curl https://github.com` still resolves; the script prints the warning + `systemctl start lustlessd` |
| redirect applied only when the forwarder answers | daemon started by hand, then `lustless-maintainer dns-redirect` | PASS — `/etc/resolv.conf` → `nameserver 127.0.0.2`; re-running is a no-op |
| resolver answers instead of going silent | `dig @127.0.0.2 example.com` while signed out | PASS — `blocked.lustless.local. CNAME … A 127.0.0.2` (a block verdict, not a timeout) |
| blocked answers are fast | six sequential `dig` queries, signed out | PASS — **2055 ms → 4–20 ms** per query after the fail-closed branch was moved ahead of process attribution (whose SOCK_DIAG dump has a 2 s I/O timeout) and a 30 s netlink circuit breaker was added |
| daemon is never left dead | unit/initd policy | `Restart=always`, `StartLimitIntervalSec=0`, OpenRC `respawn_max=0` (was 3 restarts per 10 s, after which the resolver stayed dead) |

Before v0.1.5 the daemon's own recorded latency for a blocked query was
2040 ms (`lustlessctl dns-activity` shows the daemon-side `ms` column) — the
netlink attribution timeout, paid on every lookup.

### Agent main loop (v0.1.4)

`v0.1.3` shipped an agent whose GTK main loop returned immediately: `gio`'s
`hold()` guard was dropped as a temporary, and the windowless
`GtkApplication` therefore exited right after activation. Symptom: the agent
process looked alive (worker thread) but no timer, tray-menu click or dialog
ever dispatched — including the sign-in window that release advertised.
Evidence used while diagnosing, on the host and in containers: a windowless
`gtk::Application` probe (with/without hold, with/without an application id)
returns from `run()` in ~0.1 s, and `gio-0.18`'s
`ApplicationHoldGuard` is `#[must_use]` with `Drop → g_application_release`.
The guard now lives in the agent's context (`Ctx::_hold`).

## How to reproduce a run

```bash
# build packages
packaging/build-deb.sh; packaging/build-rpm.sh
packaging/build-arch.sh; packaging/build-apk.sh
# deliver + drive a VM
target/testbed/qmon.sh <container> raw 'drive_add 0 if=none,file=/storage/lustless-cd.iso,...'
target/testbed/qmon.sh <container> text 'apk add ...'   # sendkey via QEMU monitor
```

## Wayland capture (v0.1.10)

The portal + PipeWire backend is the one subsystem whose verification cannot be
split from a live compositor, so the rows below separate what is *proven* from
what is *outstanding*.

| What | Result |
|---|---|
| Version-tolerant bindings: all 24 SPA pod constants (`pipewire_pod.rs`) | **✔** — a probe compiled with the real headers prints identical values on `ubuntu:22.04` (libspa 0.3.48) and `ubuntu:24.04` (1.0.x) |
| Symbol resolution at runtime | **✔** — `load_resolves_the_system_library_when_pipewire_is_installed` resolves all 25 dlsym'd entry points against the real `libpipewire-0.3.so.0` 1.0.5 on the dev host |
| FFI contract end to end without a compositor | **✔** — `crates/lustless-capture/tests/pipewire_sys_fake.rs` compiles a stub `libpipewire-0.3.so.0` from the real 0.3.48 headers and drives the RAII wrappers: `pw_core_methods::get_registry` at offset 48 through the real `spa_interface`, the registry `restricted` property through the real `spa_dict` layout, the negotiated format pod through `parse_video_info`, the padded-stride frame the stub publishes, and buffer queueing |
| Release build without PipeWire headers | **✔** — `cargo build -p lustless-capture` and the full `--release` build in the `ubuntu:22.04` container with **no** `libpipewire-0.3-dev` and **no** `libclang-dev`: exit 0, 50 tests pass |
| No link dependency | **✔** — `readelf -d` on all four release binaries: no `libpipewire`/`libspa` `DT_NEEDED`; the soname is present as a `dlopen` target string |
| Daemon resolves the session, not its own environment | **✔ live** (Ubuntu 24.04 VM, 0.1.10 installed): `capture: session env applied (uid 1000, type X11, display None)` — the *session's* kind, in a root system service with no session environment |
| X11 display recovery | **✔ fixed from a live failure** — the same VM logged `capture: backend open failed: display connection failed: $DISPLAY variable not set`, because logind's `Display` property is empty on this image (also empty on Zorin 17.3). Now recovered from the session leader's `/proc/<pid>/environ`, then a bounded descendant walk, then the file probe, then `:0` for X11 only |
| Classifier readiness | **✔ live** — same VM: `classifier v0.1.10 ready`, all six CE artifacts loaded (`b1/b2/b3-scorer`, `sw-labels`, `calibration`, `mn`), `threshold 0.467 (calibration artifact), input 224x224` |
| Portal ScreenCast grant + real frame extraction | **✘ not yet observed.** Both testbed images ship `WaylandEnable=false` in `/etc/gdm3/custom.conf`, so GDM never offers a Wayland session (no session chooser on the login screen, and `XSession=...-wayland` is ignored). Undoing that (comment the line, disable the X11 `xsessions` entries, set the session in AccountsService — done on the Ubuntu VM) is necessary but was not sufficient within this session: the VM console (VNC + the QEMU monitor `sendkey` path) could not get a shell to run the harness. The harness for the run is committed and self-contained in `packaging/testbed/wayland-verify/`: `serve.py` (serves the docroot on the guest's gateway address and records POSTed reports), `wayland-switch.sh` (comments out GDM's `WaylandEnable=false`, disables the X11 `xsessions` entries, sets the AccountsService `Session`/`XSession`), `prep.sh` (install the .deb, switch to offline mode, restart, sign in) and `cap.sh` (wait for a tick, then dump spool, manifest, restore token and the daemon log). Drive the VM with `target/testbed/qmon.sh <container> text '<command>'` — one monitor connection per call, because QEMU echoes per keystroke and a connection per character garbles the line (that was the failure mode of the first attempts). |
| X11 capture on a real desktop | **✘ not yet observed** for the same reason (the session was X11 but no shell could be driven to install/sign-in and let a tick run). The DISPLAY defect above was found from the daemon's own log during the run, which is what that log is there for |

## Screen capture on a real machine (v0.1.11)

Run on the dev workstation itself — a real X11 desktop (`Type=x11`,
`Display=:0`, session `c2`, active) with **five ssh/tty sessions for the same
uid**, which is what made two of these bugs visible. The daemon ran as an
unprivileged user with a test config (`/tmp/llvm4`: DNS off, offline mode,
state under `/tmp`), so nothing on the machine was touched.

| Step | Observed |
|---|---|
| Session tracking with an ssh session present | `logind: tracking 6 existing session(s)`; the *graphical* session is selected, not a tty one |
| Gate | passes — before the fix this was `session inactive` on every tick |
| Session environment | `capture: session env applied (uid 1000, type X11, display Some(":0"))` |
| Backend | `capture: backend selected (X11)` |
| Frame | `im0.png`, 1280×800, 3069 distinct colours (real desktop content, not a blank frame) |
| Transaction | complete: `im0.png` + `manifest.json` + `ready` marker; `client_screenshot` metric row in the daemon's ledger |
| Classifier | consumed the transaction; `{"batch_ts":"2026-10-14T19:51:28Z","analyzed_count":1,"flagged":0,"top_score":0.06666}` |

Before these fixes the same run produced: sessions discovered after startup never
registered (so `session inactive` forever), an ssh tty session selected over the
desktop, and — once a capture *did* succeed — `analyzed_count: 0` because the
manifest carried `apps: []`.
