# Changelog

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
