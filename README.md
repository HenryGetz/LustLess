# LustLess

Covenant Eyes for Linux? Doesn't exist. Never has. Probably never will.

So we made one.

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

One line. Copy, paste, forget about it — detects your distro, downloads the
right package, installs it, starts the tray agent:

```sh
curl -fsSL https://github.com/HenryGetz/LustLess/releases/latest/download/install.sh | sudo bash
```

No curl? `wget -qO- <same-url> | sudo bash`. No bash (Alpine)? Same line with
`| sudo sh`. Bleeding edge instead of the release:
`curl -fsSL https://raw.githubusercontent.com/HenryGetz/LustLess/main/scripts/install.sh | sudo bash`

Would rather choose yourself? You have a distro. We have a package. Match them:

| Distro | File | Command |
|---|---|---|
| Debian / Ubuntu / Zorin / Mint | `lustless_0.1.0_amd64.deb` | `sudo apt install ./lustless_0.1.0_amd64.deb` |
| Fedora | `lustless-0.1.0-1.x86_64.rpm` | `sudo dnf install ./lustless-0.1.0-1.x86_64.rpm` |
| Bazzite / immutable Fedora | `lustless-0.1.0-1.x86_64.rpm` | `sudo rpm-ostree install ./lustless-0.1.0-1.x86_64.rpm` && reboot |
| Arch / EndeavourOS | `lustless-0.1.0-1-x86_64.pkg.tar.zst` | `sudo pacman -U ./lustless-0.1.0-1-x86_64.pkg.tar.zst` |
| Alpine | `lustless-0.1.0-r0.apk` | `sudo cp lustless.rsa.pub /etc/apk/keys/ && sudo apk add --allow-untrusted ./lustless-0.1.0-r0.apk` |
| SteamOS | `lustless-0.1.0-1-x86_64.pkg.tar.zst` | `steamos-readonly disable && sudo pacman -U ./lustless-0.1.0-1-x86_64.pkg.tar.zst && steamos-readonly enable` |

All of it: [latest release](https://github.com/HenryGetz/LustLess/releases/latest).

Can't be bothered to choose? `scripts/install.sh` figures it out for you.

After install, the tray agent is already running for your user (the installer
starts it). **Sign in from the “LustLess” entry in your application menu** —
it opens the sign-in dialog; once signed in, the same entry opens the
dashboard. On a bare window manager with no tray there is still
`lustlessctl signin <username>`.

Headless/no-tray hosts (LXQt, plain Xfce without the indicator plugin): the
same application-menu entry is the sign-in surface, and notifications report
state changes.

Uninstall reverses everything — your DNS, browser policies and polkit state
come back exactly as found. `sudo apt purge lustless` (or the dnf/rpm/pacman/
apk equivalent). It's politer than you are.

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
