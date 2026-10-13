# LustLess

Covenant Eyes for Linux? Doesn't exist. Never has. Probably never will.

So we made one.

```sh
curl -fsSL https://github.com/HenryGetz/LustLess/releases/latest/download/install.sh | sudo bash
```

That's the whole install. It reads your distro, grabs the matching package,
installs it, starts the agent — and the sign-in window opens by itself. Log
in there. Manual packages, caveats and uninstall are
[below](#other-ways-to-install).

Cue 200 pages of reverse engineering, a Rust workspace, and seven distros
of very specific suffering. What you get:

- **Your screen gets watched.** A classifier judges it *on your machine*.
  No screenshot, crop, title or score leaves the device. That's not a
  privacy setting. That's just how it's built. cope.
- **The web gets filtered.** DNS-level, system-wide, before your browser
  gets any ideas. Signed out? Everything fails closed. That's not a bug,
  that's the product.
- **A dashboard** at `http://127.0.0.1:8760` so you can watch it work.
- **You can't turn it off.** Ask politely via polkit, give a reason, enjoy
  your permanent journal receipt. Nice try though.

`lustlessctl status` · `lustlessctl policy` · `lustlessctl break-glass <reason>`

## Install

One line. Copy, paste, forget about it:

```sh
curl -fsSL https://github.com/HenryGetz/LustLess/releases/latest/download/install.sh | sudo bash
```

It detects the distro family (apt / dnf / rpm-ostree / pacman / apk), pulls
the matching package from the [latest release][rel], installs it with the
native tool, starts the per-user agent — which then opens the sign-in window.
Variants:

```sh
# no curl
wget -qO- https://github.com/HenryGetz/LustLess/releases/latest/download/install.sh | sudo bash
# no bash (Alpine)
curl -fsSL https://github.com/HenryGetz/LustLess/releases/latest/download/install.sh | sudo sh
# bleeding edge instead of the release
curl -fsSL https://raw.githubusercontent.com/HenryGetz/LustLess/main/scripts/install.sh | sudo bash
```

### Sign in

The install **ends on the LustLess sign-in window** — a signed-out agent opens
it automatically (the installer starts the agent for you, and it reopens at
each graphical login until you sign in). No tray required. You can also open
it any time from the **LustLess** entry in your application menu, or from a
terminal:

```sh
lustless-agent --show            # the sign-in / dashboard window
lustlessctl signin <username>    # headless (bare window manager, SSH)
```

### Uninstall

Reverses everything — DNS, browser policies and polkit state come back
exactly as found:

```sh
sudo apt purge lustless      # or: sudo dnf remove / sudo rpm-ostree uninstall
                             #     sudo pacman -R / sudo apk del
```

## Other ways to install

Prefer to pick the file yourself? Match distro to package:

| Distro | File | Command |
|---|---|---|
| Debian / Ubuntu / Zorin / Mint | `lustless_0.1.4_amd64.deb` | `sudo apt install ./lustless_0.1.4_amd64.deb` |
| Fedora | `lustless-0.1.4-1.x86_64.rpm` | `sudo dnf install ./lustless-0.1.4-1.x86_64.rpm` |
| Bazzite / immutable Fedora | `lustless-0.1.4-1.x86_64.rpm` | `sudo rpm-ostree install ./lustless-0.1.4-1.x86_64.rpm` && reboot |
| Arch / EndeavourOS | `lustless-0.1.4-1-x86_64.pkg.tar.zst` | `sudo pacman -U ./lustless-0.1.4-1-x86_64.pkg.tar.zst` |
| Alpine | `lustless-0.1.4-r0.apk` | `sudo cp lustless.rsa.pub /etc/apk/keys/ && sudo apk add --allow-untrusted ./lustless-0.1.4-r0.apk` |
| SteamOS | `lustless-0.1.4-1-x86_64.pkg.tar.zst` | `steamos-readonly disable && sudo pacman -U ./lustless-0.1.4-1-x86_64.pkg.tar.zst && steamos-readonly enable` |

Everything above is on the [latest release][rel]. Or run
`sudo sh scripts/install.sh` from a checkout.

## Does it actually work

We installed it in real VMs on seven distros and watched it block things:
Fedora 44, Ubuntu 24.04 LTS, Debian 13, Linux Mint 22.3, Arch, Alpine,
Bazzite. The receipts: [`docs/impl/TEST-MATRIX.md`](docs/impl/TEST-MATRIX.md).
The rules it follows: [`docs/impl/PACKAGING-MATRIX.md`](docs/impl/PACKAGING-MATRIX.md).
The per-flavor fine print: [`packaging/README.md`](packaging/README.md).

## Building

```sh
packaging/build-deb.sh   # or build-rpm.sh / build-arch.sh / build-apk.sh
```

All hermetic in Docker. Your host glibc stays home where it belongs.

## Deeper

`docs/impl/CONTRACTS.md` (the ratified contracts) · `re/` (how we learned
all this) · `packaging/testbed/` (the eleven-VM torture chamber) ·
`scripts/smoke-local.sh`

Experimental. Things may change. Your screen still never leaves your machine.

[rel]: https://github.com/HenryGetz/LustLess/releases/latest
