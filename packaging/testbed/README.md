# Distro VM Testbed

Disposable QEMU virtual machines running inside Docker, used for testing
`.deb` package installs against real desktop targets before touching the
Windows-side findings. Five flavors are defined: **Zorin OS 17.3 Core 64-bit
(r2)** (the original GNOME target), **Zorin OS 17.3 Lite**, **Xubuntu**,
**Ubuntu**, and **Lubuntu** — see the [flavor matrix](#flavor-matrix).

Each VM is driven by [`qemux/qemu-docker`](https://github.com/qemus/qemu-docker)
(image `qemux/qemu`), which serves a web-based noVNC viewer on its host port
from the matrix (zorin-vm: **8006**).
Note: the image is `qemux/qemu` on Docker Hub; `qemux/qemu-docker` is the
GitHub repo name, not an image.

## Prerequisites

- Linux host with KVM (`/dev/kvm` present, user in `kvm` group or running
  docker as root)
- Docker + Compose v2 (`docker compose`)
- `/dev/net/tun` present (created by the `tun` kernel module)

## Flavor matrix

| Flavor | Desktop shell | ISO (in `target/testbed/iso/`) | SHA256 | noVNC port | Storage dir (in `target/testbed/`) | Compose profile |
|--------|---------------|--------------------------------|--------|------------|------------------------------------|-----------------|
| Zorin OS 17.3 Core 64-bit (r2) | GNOME | `Zorin-OS-17.3-Core-64-bit-r2.iso` | `c1510d1e16ec50c884faeb4e32326ba8d2e38d2cf22698b649168011d00220f6` | 8006 | `zorin_storage` | *(none — always enabled)* |
| Zorin OS 17.3 Lite 64-bit (r2) | Xfce | `Zorin-OS-17.3-Lite-64-bit-r2.iso` | `6d3ed727c5295ca29eda578177ce918267ea775b70a80d5812fd97f614a76cb8` | 8007 | `zorin_lite_storage` | `zorin-lite` |
| Xubuntu 24.04.5 LTS | Xfce | `xubuntu-24.04.5-desktop-amd64.iso` | `4ed869ebf2b9f2f6118c1b60b9ed07576e8fe3d5cdfe10aae06869e669878b81` | 8008 | `xubuntu_storage` | `xubuntu` |
| Ubuntu 24.04.5.1 LTS | GNOME | `ubuntu-24.04.5.1-desktop-amd64.iso` | `4da4a0c9035da8e68a59a838674f403f0a54472c78a83b4fb7f78d03588f85a7` | 8009 | `ubuntu_storage` | `ubuntu` |
| Lubuntu 24.04.5 LTS | LXQt | `lubuntu-24.04.5-desktop-amd64.iso` | `303a769f681014c801844e33d7918842878067eb644e3c418d699db25f4b4bc6` | 8010 | `lubuntu_storage` | `lubuntu` |
| Debian 13.7.0 live | GNOME | `debian-live-13.7.0-amd64-gnome.iso` | `e94859a83b305cae5125dc9c6080ced040c59d099ea7381e7f300fd1dba87a17` | 8011 | `debian_storage` | `debian` |
| Linux Mint 22.3 | Cinnamon | `linuxmint-22.3-cinnamon-64bit.iso` | `a081ab202cfda17f6924128dbd2de8b63518ac0531bcfe3f1a1b88097c459bd4` | 8012 | `mint_storage` | `mint` |
| Fedora Workstation 44-1.7 live | GNOME | `Fedora-Workstation-Live-44-1.7.x86_64.iso` | `1620295f6a00c27c3208f0c00b8ece4eab1ec69b9002152d97488bf26a426ddf` | 8013 | `fedora_storage` | `fedora` |
| Arch Linux 2026.10.01 | CLI live | `archlinux-2026.10.01-x86_64.iso` | `684ded26c63240ff4a41e8c25ee84ea6da233f557364821f13d12c2b0a9059a5` | 8014 | `arch_storage` | `arch` |
| Alpine 3.24.2 extended | CLI live | `alpine-extended-3.24.2-x86_64.iso` | `a22115a46a1bcd876234a6cd43797fe19f4acfc4512fb41ea64e16cc2ffb4d90` | 8015 | `alpine_storage` | `alpine` |
| Bazzite GNOME stable live | GNOME | `bazzite-gnome-stable-live-amd64.iso` | `8a8a448a922d047dd60f73f03fe7d3a8cd06798859166b3418712029cc32f8a0` | 8016 | `bazzite_storage` | `bazzite` |

All hashes were verified against the publishers' checksum files
(debian-cd SHA256SUMS, kernel.org linuxmint/fedora/arch mirrors, Alpine CDN
`.sha256`, `download.bazzite.gg` CHECKSUM). SteamOS has **no public install
ISO** (Deck recovery images only) — its `pacman`-based install path is
covered by the Arch VM, its immutable-root path by Bazzite; see
`packaging/README.md` for the on-device SteamOS procedure.

Every service follows the same pattern: `qemux/qemu`, `RAM_SIZE=4G`,
`CPU_CORES=4`, `DISK_SIZE=32G`, `/dev/kvm` + `/dev/net/tun`, `NET_ADMIN`,
`stop_grace_period: 2m`, its ISO bind-mounted read-write at `/boot.iso`
(a `:ro` bind crashloops — see [Layout](#layout)), and its host noVNC port
mapped to the container's fixed web-viewer port 8006. Open
`http://localhost:<port>` per the matrix.

### Why this matrix: bracketing glibc

- **Zorin OS 17** (Core and Lite) = **Ubuntu 22.04 base → glibc 2.35**
- **Ubuntu / Xubuntu / Lubuntu 24.04** = **Ubuntu 24.04 base → glibc 2.39**

The matrix brackets the supported glibc range: the oldest target ships
glibc 2.35, the newest glibc 2.39, so a `.deb` proven to install on all
five VMs neither leans on libc symbols newer than 2.39 nor escapes testing
against the 2.35 runtime that older LTS-derived desktops ship. Xubuntu
(Xfce) and Lubuntu (LXQt) additionally cover the alternate desktop stacks
on the same 24.04/glibc-2.39 base as Ubuntu's GNOME.

### Per-VM commands

Run from `packaging/testbed/`. **Always name the service** in
`up`/`stop`/`down`: services without a profile (zorin-vm) are always
selected, so a bare `docker compose --profile xubuntu down` would also stop
**and remove zorin-vm's container** (confirmed with `--dry-run`). Scoping
each command to one service keeps it confined to that VM.

```bash
cd packaging/testbed

# Zorin OS 17.3 Core (no profile — always enabled)
docker compose up -d zorin-vm
docker compose stop zorin-vm                # ACPI shutdown, keep container
docker compose down zorin-vm                # remove container, keep disk

# Zorin OS 17.3 Lite
docker compose --profile zorin-lite up -d zorin-lite-vm
docker compose --profile zorin-lite stop zorin-lite-vm
docker compose --profile zorin-lite down zorin-lite-vm

# Xubuntu
docker compose --profile xubuntu up -d xubuntu-vm
docker compose --profile xubuntu stop xubuntu-vm
docker compose --profile xubuntu down xubuntu-vm

# Ubuntu
docker compose --profile ubuntu up -d ubuntu-vm
docker compose --profile ubuntu stop ubuntu-vm
docker compose --profile ubuntu down ubuntu-vm

# Lubuntu
docker compose --profile lubuntu up -d lubuntu-vm
docker compose --profile lubuntu stop lubuntu-vm
docker compose --profile lubuntu down lubuntu-vm
```

`up -d <service>` boots only that VM (inactive profiles are never
selected); `stop`/`down` wait up to `stop_grace_period` (2m) for the guest
to flush on ACPI poweroff; `down <service>` removes only that VM's
container — the disk stays in its storage dir from the matrix. Watch a
boot with `docker logs -f <container>` (`zorin-os`, `zorin-lite-os`,
`xubuntu-os`, `ubuntu-os`, `lubuntu-os`).

Note: `docker compose config` with no flags renders only zorin-vm (services
of inactive profiles are filtered out). To render all five services:

```bash
docker compose --profile zorin-lite --profile xubuntu --profile ubuntu \
  --profile lubuntu config
```

## ISO provenance

### Zorin OS 17.3 Core (original target)

| Field  | Value |
|--------|-------|
| Distro | Zorin OS 17.3 Core 64-bit (r2) — from the [official Zorin archive](https://zorin.com/os/archive/) |
| File   | `target/testbed/iso/Zorin-OS-17.3-Core-64-bit-r2.iso` (3,771,187,200 bytes) |
| URL    | <https://mirrors.edge.kernel.org/zorinos-isos/17/Zorin-OS-17.3-Core-64-bit-r2.iso> (Kernel.org, the "World" mirror listed on [zorin.com/os/download/17/core](https://zorin.com/os/download/17/core/)) |
| Alt URL | `https://zrn.co/17core64` (official shortlink from the Zorin download page; currently resolves to the Purdue mirror) |
| SHA256 | `c1510d1e16ec50c884faeb4e32326ba8d2e38d2cf22698b649168011d00220f6` |

The SHA256 matches the checksum published by Zorin at
<https://help.zorin.com/docs/getting-started/check-the-integrity-of-your-copy-of-zorin-os/>
("Zorin OS 17.3 Core 64-bit (r2)"). Verify with:

```bash
sha256sum target/testbed/iso/Zorin-OS-17.3-Core-64-bit-r2.iso
```

To (re-)download with resume support:

```bash
mkdir -p target/testbed/iso
curl -C - -L --fail --retry 5 --retry-delay 10 \
  -o target/testbed/iso/Zorin-OS-17.3-Core-64-bit-r2.iso \
  https://mirrors.edge.kernel.org/zorinos-isos/17/Zorin-OS-17.3-Core-64-bit-r2.iso
```

### Additional flavor ISOs

| Distro | File | URL | SHA256 (vendor-published) | Checksum source |
|--------|------|-----|---------------------------|-----------------|
| Zorin OS 17.3 Lite 64-bit (r2) | `Zorin-OS-17.3-Lite-64-bit-r2.iso` | <https://mirrors.edge.kernel.org/zorinos-isos/17/Zorin-OS-17.3-Lite-64-bit-r2.iso> (Kernel.org, the "World" mirror listed on [zorin.com/os/download/17/lite](https://zorin.com/os/download/17/lite/)) | `6d3ed727c5295ca29eda578177ce918267ea775b70a80d5812fd97f614a76cb8` | Zorin integrity page, entry "Zorin OS 17.3 Lite 64-bit (r2)" — identical to the mirror's `SHA256SUMS.txt` |
| Xubuntu 24.04.5 LTS | `xubuntu-24.04.5-desktop-amd64.iso` | <https://cdimage.ubuntu.com/xubuntu/releases/24.04.5/release/xubuntu-24.04.5-desktop-amd64.iso> | `4ed869ebf2b9f2f6118c1b60b9ed07576e8fe3d5cdfe10aae06869e669878b81` | <https://cdimage.ubuntu.com/xubuntu/releases/24.04.5/release/SHA256SUMS> |
| Ubuntu 24.04.5.1 LTS Desktop | `ubuntu-24.04.5.1-desktop-amd64.iso` | <https://releases.ubuntu.com/24.04/ubuntu-24.04.5.1-desktop-amd64.iso> | `4da4a0c9035da8e68a59a838674f403f0a54472c78a83b4fb7f78d03588f85a7` | <https://releases.ubuntu.com/24.04/SHA256SUMS> |
| Lubuntu 24.04.5 LTS | `lubuntu-24.04.5-desktop-amd64.iso` | <https://cdimage.ubuntu.com/lubuntu/releases/24.04.5/release/lubuntu-24.04.5-desktop-amd64.iso> | `303a769f681014c801844e33d7918842878067eb644e3c418d699db25f4b4bc6` | <https://cdimage.ubuntu.com/lubuntu/releases/24.04.5/release/SHA256SUMS> |

Download (resume-safe — re-run the same command after an interrupted
transfer and `curl -C -` continues where it left off):

```bash
mkdir -p target/testbed/iso
for u in \
  https://mirrors.edge.kernel.org/zorinos-isos/17/Zorin-OS-17.3-Lite-64-bit-r2.iso \
  https://cdimage.ubuntu.com/xubuntu/releases/24.04.5/release/xubuntu-24.04.5-desktop-amd64.iso \
  https://releases.ubuntu.com/24.04/ubuntu-24.04.5.1-desktop-amd64.iso \
  https://cdimage.ubuntu.com/lubuntu/releases/24.04.5/release/lubuntu-24.04.5-desktop-amd64.iso
do
  curl -C - -L --fail --retry 10 --retry-delay 15 --retry-all-errors \
    -o "target/testbed/iso/${u##*/}" "$u"
done
```

Verify all four against the vendors' published checksums:

```bash
cd target/testbed/iso
sha256sum -c <<'EOF'
6d3ed727c5295ca29eda578177ce918267ea775b70a80d5812fd97f614a76cb8  Zorin-OS-17.3-Lite-64-bit-r2.iso
4ed869ebf2b9f2f6118c1b60b9ed07576e8fe3d5cdfe10aae06869e669878b81  xubuntu-24.04.5-desktop-amd64.iso
4da4a0c9035da8e68a59a838674f403f0a54472c78a83b4fb7f78d03588f85a7  ubuntu-24.04.5.1-desktop-amd64.iso
303a769f681014c801844e33d7918842878067eb644e3c418d699db25f4b4bc6  lubuntu-24.04.5-desktop-amd64.iso
EOF
```

Verified local file sizes (bytes, as downloaded): Zorin OS 17.3 Lite
`3,905,273,856` · Xubuntu `5,211,408,384` · Ubuntu `6,250,332,160` ·
Lubuntu `4,064,491,520`.

Mirror / release-series quirks:

- **Zorin**: zorin.com's integrity page now headlines Zorin OS 18.x but
  still lists the 17.3 hashes; the 17.3 Lite release is at revision **r2**
  (`…-r1`/`…-r2` are respins; r2 is current). Kernel.org's
  `zorinos-isos` mirror carries Zorin's own `SHA256SUMS.txt`, byte-identical
  to the published hash above.
- **Ubuntu Desktop**: the ubuntu.com/download/desktop page currently
  advertises 26.04.1 LTS; the latest **24.04-series** desktop image is
  published as `ubuntu-24.04.5.1-desktop-amd64.iso` — there is no
  `ubuntu-24.04.5-desktop-amd64.iso` on `releases.ubuntu.com/24.04/`
  (the desktop ISO of that point release carries version 24.04.5.1).
- **Xubuntu**: ubuntu.com/xubuntu/download is JavaScript-rendered and does
  not expose the ISO version in its HTML; the authoritative listing is
  <https://cdimage.ubuntu.com/xubuntu/releases/> — latest 24.04.x point
  release is 24.04.5. cdimage stores the ISOs and `SHA256SUMS` one level
  deeper, under `…/24.04.5/release/`.
- **Lubuntu**: lubuntu.me/downloads lists `lubuntu-24.04.5-desktop-amd64.iso`
  alongside newer 25.10/26.04.1 images — 24.04.5 is the latest 24.04.x
  point release. Same `release/` subdirectory layout on cdimage.

## Layout

```
packaging/testbed/
  docker-compose.yml        # all five VMs' Compose file
  README.md                 # this file
target/testbed/             # gitignored — VM data, not committed
  iso/                      # the five ISOs from the flavor matrix
  zorin_storage/            # zorin-vm      /storage:
  zorin_lite_storage/       # zorin-lite-vm /storage   data.img (32G disk),
  xubuntu_storage/          # xubuntu-vm    /storage   firmware vars, etc.
  ubuntu_storage/           # ubuntu-vm     /storage
  lubuntu_storage/          # lubuntu-vm    /storage
```

Each ISO is bind-mounted at `/boot.iso` (read-write is required — QEMU
attaches it via `usb-storage,removable=on`, which fails on a `:ro` mount);
qemu-docker's `findBootFile()` (src/install.sh) detects it, so the `BOOT`
env var is not needed. Once the disk has data (`<storage>/data.img`), the
VM boots from the disk and the ISO is ignored — exactly like a real
machine remembering its installed OS.

## Boot / open viewer / shutdown

```bash
cd packaging/testbed
docker compose up -d          # start zorin-vm in the background
docker logs -f zorin-os       # watch SeaBIOS/UEFI + guest boot messages
```

Open the web viewer: **<http://localhost:8006>** — noVNC; click *Connect*,
then use the desktop (or installer) with the mouse/keyboard in the browser
tab. Pass extra guest ports with the `ports:` list (e.g. `"2222:22"` for
guest SSH once installed). The other flavors boot the same way via
[Per-VM commands](#per-vm-commands); their viewers live on ports 8007–8010
per the matrix.

Graceful shutdown (ACPI, lets the guest flush its disk):

```bash
cd packaging/testbed
docker compose stop           # sends ACPI poweroff, waits up to stop_grace_period
```

`docker compose down` also works (removes the container, keeps the disk —
the disk lives in `target/testbed/zorin_storage/`). Force-kill only if
needed: `docker kill zorin-os`. With `restart: unless-stopped`, the VM
restarts automatically after a host reboot until you `docker compose stop`
it once. (These bare commands select zorin-vm only — flavor VMs are behind
profiles; when a profile is active, name the service as shown in
[Per-VM commands](#per-vm-commands).)

## Snapshot / reset

There is no qcow2 snapshotting here — the disk is a raw sparse file, so a
"snapshot" is just a file copy and a "reset" is delete-and-recreate (shown
for zorin-vm; for a flavor, add its `--profile` and service name as in
[Per-VM commands](#per-vm-commands) and use its storage dir):

```bash
cd packaging/testbed
docker compose stop

# Snapshot (VM must be stopped):
cp --sparse=always ../../target/testbed/zorin_storage/data.img \
   ../../target/testbed/zorin_storage/data.img.bak

# Reset to factory-fresh blank disk (re-prompts the Zorin installer next boot):
docker compose stop
rm -f ../../target/testbed/zorin_storage/data.img
docker compose up -d

# Restore snapshot:
docker compose stop
mv ../../target/testbed/zorin_storage/data.img.bak \
    ../../target/testbed/zorin_storage/data.img
docker compose up -d
```

Full nuke (disk + firmware state, ISO kept):

```bash
docker compose down
rm -rf ../../target/testbed/zorin_storage
docker compose up -d
```

## First boot: one-time manual step

On first boot the VM reaches the **Zorin OS live session / installer menu**
in the noVNC window. A human decision is needed once, in the GUI:

- **Try Zorin OS** (live session) — fine for throwaway `.deb` smoke tests;
  changes are lost on poweroff.
- **Install Zorin OS** — installs to the 32G disk; afterwards the VM boots
  straight to the installed system and `data.img` holds all state
  (back it up / reset as above).

The four flavor VMs behave the same way: each boots its own distro's
live/installer menu on first boot and needs the same one-time choice
(install to disk, or stay live). This phase is driven by hand via noVNC.
Later automation (preseed/kickstart or driving the installer) is out of
scope for this testbed.

## VM sizing (compose env)

`RAM_SIZE=4G`, `CPU_CORES=4`, `DISK_SIZE=32G`, set identically for all
five services in `packaging/testbed/docker-compose.yml`. `DISK_SIZE` can
also be raised in-place on an existing disk (then extend the partition in
the guest).

## Troubleshooting

- **`BdsDxe: failed to load Boot0003 ... HARDDISK` in logs on first boot is
  normal** — the UEFI tries the empty disk before falling back to the ISO
  (Boot0002 USB HARDDRIVE). Once Zorin is installed the disk boots first.
- **First boot takes several extra minutes**: after GRUB, the ISO runs its
  casper integrity check ("Checking md5sums… Checking
  ./casper/filesystem.squashfs") on the virtual optical drive before the
  live desktop appears. This is normal Zorin ISO behavior; wait it out.
  The 24.04 flavors do a similar media check on their first boot.
- `docker logs zorin-os` stays on "Booting image" / no desktop? Give it
  ~30–60 s; the live session is heavy. Still stuck: check `/dev/kvm` exists
  (`ls -l /dev/kvm`) — without KVM the VM is unusably slow (TCG fallback).
- Port busy (e.g. 8006): change the host side of that service's `ports:`
  entry (e.g. `"8016:8006"`), and update the viewer URL. The flavor ports
  8007–8010 are fixed in the compose file/matrix.
- Viewer asks for password: it should not — `PROTECT` is unset (N). If it
  ever does, that came from the `PROTECT` env var.
