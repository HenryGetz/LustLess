# Changelog

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
