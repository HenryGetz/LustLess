# Changelog

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
