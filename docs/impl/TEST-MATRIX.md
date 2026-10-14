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
