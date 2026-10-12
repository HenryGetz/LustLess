# LustLess

On-device accountability for Linux: screen accountability (capture + a local
classifier — **no screenshot, crop, title or score ever leaves the device**),
system-wide DNS-level web filtering, a token-authenticated local dashboard,
and a polkit-gated, journaudited administrative escape hatch. A Linux
reimplementation of the Covenant Eyes "Victory Shield" 10.1.44 behavior
surface (`re/` holds the reverse-engineering record; `docs/impl/CONTRACTS.md`
holds the ratified contracts).

Ships as native packages for every major distro family — **one glibc 2.35
build feeds Debian/Ubuntu/Zorin/Mint, Fedora, Arch and SteamOS; Alpine gets a
musl build** — all assembled from a single staging tree and sharing one
lifecycle helper, so install, upgrade and removal behave identically
everywhere.

## Install

Grab the package for your distro from the
[latest release](https://github.com/HenryGetz/LustLess/releases/latest):

| Your distro | Package | Install |
|---|---|---|
| **Debian 13, Ubuntu 22.04+, Zorin OS 17, Linux Mint** | `lustless_0.1.0_amd64.deb` | `sudo apt install ./lustless_0.1.0_amd64.deb` |
| **Fedora Workstation** | `lustless-0.1.0-1.x86_64.rpm` | `sudo dnf install ./lustless-0.1.0-1.x86_64.rpm` |
| **Bazzite, Silverblue & other immutable Fedora** | `lustless-0.1.0-1.x86_64.rpm` | `sudo rpm-ostree install ./lustless-0.1.0-1.x86_64.rpm` then **reboot** |
| **Arch Linux, EndeavourOS, SteamOS** | `lustless-0.1.0-1-x86_64.pkg.tar.zst` | `sudo pacman -U ./lustless-0.1.0-1-x86_64.pkg.tar.zst` |
| **Alpine Linux** | `lustless-0.1.0-r0.apk` | `sudo cp lustless.rsa.pub /etc/apk/keys/` then `sudo apk add --allow-untrusted ./lustless-0.1.0-r0.apk` |
| **SteamOS (read-only root)** | `lustless-0.1.0-1-x86_64.pkg.tar.zst` | `steamos-readonly disable && sudo pacman -U ./lustless-…pkg.tar.zst && steamos-readonly enable` |

Don't want to pick? From a checkout, the universal installer detects your
family and does it:

```sh
scripts/install.sh ./lustless_0.1.0_amd64.deb   # any local package file
LUSTLESS_RELEASE_URL=<release-url> scripts/install.sh   # download + install
```

**After install**, each graphical user enables the tray agent once:

```sh
systemctl --user enable --now lustless-agent.service
```

(On Alpine it starts automatically via XDG autostart; on LXQt there is no SNI
tray host, so the agent degrades to desktop notifications + `lustlessctl
status` + the dashboard — accountability is unaffected.)

**Uninstall** reverses everything — DNS configuration, browser policies and
the polkit action are restored byte-for-byte:

```sh
sudo apt purge lustless        # or: dnf remove / rpm -e / pacman -R / apk del
```

## What you get

- **`lustlessd`** (system daemon): DNS forwarder on `127.0.0.2:53`, capture
  scheduler, classifier supervisor, dashboard on `http://127.0.0.1:8760`
  (token-authenticated).
- **`lustless-classifier`**: local scoring process; all model artifacts stay
  on disk, nothing is uploaded.
- **`lustless-agent`** (GTK tray): per-user session presence + notifications.
- **`lustlessctl`**: `status`, `policy`, `dns-activity`, `flush`, and the
  audited `break-glass` override (polkit `auth_admin_keep`, every use logged
  to journald).

Policy levels: *Standard Blocking*, *Strong Blocking*, *Blocking Enabled*
(`lustlessctl policy`). While **signed out, web DNS fails closed** — that is
the product semantic, not a fault.

## Verified

Every package above was installed and exercised in a **live VM running that
distro's own ISO** (QEMU testbed, `packaging/testbed/`): Fedora 44, Ubuntu
24.04 LTS, Debian 13, Linux Mint 22.3, Arch Linux, Alpine 3.24, and Bazzite
(immutable). Full evidence, per-distro results and caveats:
[`docs/impl/TEST-MATRIX.md`](docs/impl/TEST-MATRIX.md). The packaging
contract (distro matrix, dependency map, acceptance checklist) is
[`docs/impl/PACKAGING-MATRIX.md`](docs/impl/PACKAGING-MATRIX.md); per-flavor
details and the browser-policy caveats are in
[`packaging/README.md`](packaging/README.md).

## Building

All builds are hermetic (Docker) — the host glibc never leaks in:

```sh
packaging/build-deb.sh      # .deb   (ubuntu:22.04 container, glibc 2.35)
packaging/build-rpm.sh      # .rpm   (fedora container)
packaging/build-arch.sh     # .pkg.tar.zst (archlinux container)
packaging/build-apk.sh      # .apk   (alpine container, musl + OpenRC)
```

All four consume one staging tree (`packaging/stage.sh`) and one lifecycle
helper (`packaging/maintainer/lustless-maintainer`). Dev workflow:
`cargo build --release`, `scripts/smoke-local.sh`, tests per crate.

## Testbed

`packaging/testbed/` boots eleven distro VMs (`qemux/qemu`, noVNC per flavor)
and carries the acceptance harness (`serve.sh`, `vm/vm-install.sh`,
`vm/vm-verify.sh`). See that README for the flavor matrix and ISO checksums.

## Status & records

Experimental — APIs may change. CE classifier-model bundles and branding are
used under written authorization; see
[`AUTHORIZATION.md`](AUTHORIZATION.md) (the authorization record MUST be
completed before any public release of a build containing CE materials).
