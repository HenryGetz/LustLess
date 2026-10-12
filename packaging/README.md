# LustLess packaging (Debian · Ubuntu · Zorin · Mint · Fedora · Arch ·
# Alpine · Bazzite/SteamOS)

Builds and describes the four `lustless` binary packages defined by
`docs/impl/CONTRACTS.md` §4 (filesystem layout), §11 (watchdog/tamper/
uninstall) and §15 (packaging), across the full distro matrix in
`docs/impl/PACKAGING-MATRIX.md` (libc/init/format map, acceptance
checklist):

| package | file | covers |
|---|---|---|
| `.deb` | `lustless_0.1.0_amd64.deb` | Debian Stable, Ubuntu LTS, Zorin OS 17, Linux Mint |
| `.rpm` | `lustless-0.1.0-1.x86_64.rpm` | Fedora Workstation, Bazzite (`rpm-ostree install`) |
| Arch | `lustless-0.1.0-1-x86_64.pkg.tar.zst` | Arch Linux, SteamOS (`pacman -U`) |
| `.apk` | `lustless-0.1.0-r0.apk` | Alpine Linux (musl build, OpenRC service) |

One glibc-2.35 build (ubuntu:22.04 container) feeds the first three; Alpine
gets a separate musl build. All four are assembled from the **same staging
tree** (`packaging/stage.sh`) and share **one lifecycle helper**
(`/usr/lib/lustless/lustless-maintainer`) — the scriptlets of every format
are thin callers, so install/upgrade/remove behavior cannot drift between
distros. SteamOS has no public ISO; it shares Arch's package and Bazzite's
immutable-root install pattern (see "Immutable systems" below).

## Supported flavors

The packages install on this matrix (CONTRACTS §1, PACKAGING-MATRIX §1):

| flavor | desktop | session type | tray behavior |
|---|---|---|---|
| Zorin OS Lite 17 | Xfce | X11 | `xfce4-indicator-plugin` hosts the SNI tray icon (pulled by default as a Recommends; add the plugin to a panel if the icon is missing) |
| Zorin OS 17 Core | GNOME | X11/Wayland | AppIndicator GNOME extension hosts the tray icon (enabled by default) |
| Xubuntu 24.04 | Xfce | X11 | `xfce4-indicator-plugin` hosts the tray icon (Recommends) |
| Ubuntu 24.04 | GNOME | Wayland by default | AppIndicator GNOME extension hosts the tray icon (preinstalled-enabled; `gnome-shell-extension-appindicator` is declared in Suggests for minimal GNOME installs) |
| Lubuntu 24.04 | LXQt | X11 | **no SNI host** — the agent degrades gracefully: status reaches the user via desktop notifications plus `lustlessctl status` and the token-authenticated dashboard (`http://127.0.0.1:8760`); accountability itself is unaffected |
| Debian 13 | GNOME | Wayland/X11 | AppIndicator GNOME extension (install `gnome-shell-extension-appindicator` on minimal GNOME) |
| Linux Mint 22.3 | Cinnamon | X11 | Cinnamon hosts SNI applets natively |
| Fedora 44 / Bazzite | GNOME | Wayland | AppIndicator GNOME extension (`gnome-shell-extension-appindicator`) |
| Arch Linux | any | X11/Wayland | same GNOME/Xfce/LXQt rules as above |
| Alpine | none/CLI | — | no graphical stack: the agent runs only where an XDG autostart session exists; DNS filtering and the daemon work headless (OpenRC) |

The maintainer helper prints a matching flavor-aware hint at the end of the
install (detection via `XDG_CURRENT_DESKTOP`, with installed session files
as fallback since package-manager environments may drop the variable): Xfce
names `xfce4-indicator-plugin`, LXQt states the degradation path, GNOME adds
nothing extra.

Browser-policy caveat on these flavors: Ubuntu-family systems ship Firefox
**as a snap**, and its `policies.json` lives in the read-only squashfs —
see "Snap Firefox caveat" below. Snap Chromium is covered: `postinst`
installs the managed policy into its writable data area
(`/var/snap/chromium/current/etc/chromium/policies/managed/`) when the snap
is present. X11/Wayland capture selection per flavor is documented at the
`[capture]` section of `etc/lustless.toml`.

Install (any supported distro — the universal installer detects the family
and picks the right package; `LUSTLESS_RELEASE_URL` points it at a specific
release):

```sh
# from the repo root, or a checked-out tree
scripts/install.sh ./lustless_0.1.0_amd64.deb     # local file
scripts/install.sh                                # download + install
```

Or with the native tools:

```sh
sudo apt install ./lustless_0.1.0_amd64.deb        # Debian/Ubuntu/Zorin/Mint
sudo dnf install ./lustless-0.1.0-1.x86_64.rpm     # Fedora
sudo rpm-ostree install ./lustless-0.1.0-1.x86_64.rpm && sudo reboot   # Bazzite
sudo pacman -U ./lustless-0.1.0-1-x86_64.pkg.tar.zst                   # Arch/SteamOS
sudo apk add --allow-untrusted ./lustless-0.1.0-r0.apk                 # Alpine
```

Removal uses the same tool (`apt purge` / `dnf remove` / `rpm -e` /
`pacman -R` / `apk del`) — every family gets the full teardown below.

### Immutable systems (Bazzite, SteamOS)

`/usr` is read-only on both; everything LustLess writes lives in `/etc` and
`/var/lib` (writable overlays), so no deviation is needed. Bazzite:
`rpm-ostree install ./<rpm>` then reboot — the `%post` scriptlet runs in the
layering chroot, so the service *enable* lands in the `/etc` overlay and the
daemon starts on first boot (if a scriptlet is skipped by your ostree
version, run the helper once after reboot: `sudo /usr/lib/lustless/lustless-maintainer configure`).
SteamOS: `steamos-readonly disable`, then `pacman -U` (or keep the root
read-only and run everything in a distrobox container with the daemon on the
host — the packaging supports the native `pacman -U` path; re-enable
readonly afterwards).

## Layout

```
packaging/
  build-binaries.sh            compile the four binaries for one libc
                               family (glibc: ubuntu:22.04 container;
                               musl: alpine container)
  stage.sh                     assemble the shared payload tree
                               (target/pkg-root) — the single source for
                               all four package formats, with a libc-family
                               guard against packaging the wrong binaries
  build-deb.sh                 build lustless_0.1.0_amd64.deb
  build-rpm.sh                 build lustless-0.1.0-1.x86_64.rpm
  build-arch.sh                build lustless-0.1.0-1-x86_64.pkg.tar.zst
  build-apk.sh                 build lustless-0.1.0-r0.apk (Alpine adaptation:
                               systemd units dropped, OpenRC initd added)
  README.md                    this file
  maintainer/
    lustless-maintainer        ONE lifecycle helper staged to
                               /usr/lib/lustless/ — subcommands configure /
                               remove / purge; every format's scriptlets are
                               thin callers (PACKAGING-MATRIX §3)
  assets/                      CE logo/icon artwork (extracted from the shipped
                               binaries; provenance + authorization in
                               assets/README.md). `lustless-256.png` is staged
                               as /usr/share/pixmaps/lustless.png (control's
                               Icon: field); `lustless-32.png` and
                               `lustless-mark.png` are compiled into the agent
                               tray and the dashboard header respectively.
  debian/
    control                    package metadata (Depends per CONTRACTS §15)
    conffiles                  /etc/lustless/lustless.toml
    postinst                   thin caller → helper configure
    prerm                      thin caller → helper remove
    postrm                     dpkg-specific purge safety net (runs after
                               payload files are gone, so it is
                               self-contained; mirrors helper purge)
  rpm/
    lustless.spec              metadata + thin scriptlets → helper
  arch/
    PKGBUILD                   metadata; package() copies the stage tree
    lustless.install           thin scriptlets → helper
  alpine/
    APKBUILD                   metadata; musl payload, conffiles
    lustless.post-install      thin caller → helper configure
    lustless.pre-upgrade       thin caller → helper remove
    lustless.post-upgrade      thin caller → helper configure
    lustless.pre-deinstall     thin callers → helper remove + purge
  openrc/
    lustlessd.initd            OpenRC service (supervise-daemon) for Alpine
  xdg/
    lustless-app.desktop       application-menu launcher (`lustless-agent
                               --show`: sign-in dialog / dashboard) →
                               /usr/share/applications/lustless-agent.desktop
    lustless-agent.desktop     XDG autostart for the tray agent (single-
                               instance safe; the only agent path on Alpine)
  systemd/
    lustlessd.service          system unit (/usr/lib/systemd/system/)
    lustless-agent.service     user unit (/usr/lib/systemd/user/)
  polkit/
    org.lustless.policy        org.lustless.break-glass,
                               org.lustless.disable-protection (auth_admin_keep,
                               every use audited in the journal)
  browser-policies/            DoH-lockdown policies, installed merge-safely
    chrome.json / chromium.json / brave.json / edge.json
                               {"DnsOverHttpsMode": "off",
                                "BuiltInDnsClientEnabled": false}
    firefox.json               {"policies": {"DNSOverHTTPS":
                                {"Enabled": false, "Locked": true}}}
  etc/
    lustless.toml              sample system config (CONTRACTS §9.1 + capture
                               backend notes for the flavor matrix)
  testbed/                     VM testbed for the distro matrix (separate doc)
```

Staged copies the lifecycle helper install at runtime live under
`/usr/share/lustless/` in the built package: `polkit/org.lustless.policy`
and `browser-policies/*.json`. The polkit action and browser policies are
**not** package payload files at their final paths — the helper installs
them at configure time and removes or restores them at remove/purge, which
is what makes "remove only what we installed" and the Firefox merge
possible.

## Building

Requirements: Docker (all builds are hermetic container builds). From the
repo root:

```sh
packaging/build-deb.sh                # full build → ./lustless_0.1.0_amd64.deb
packaging/build-rpm.sh                # full build → ./lustless-0.1.0-1.x86_64.rpm
packaging/build-arch.sh               # full build → ./lustless-0.1.0-1-x86_64.pkg.tar.zst
packaging/build-apk.sh                # full build → ./lustless-0.1.0-r0.apk (musl)

packaging/build-deb.sh --skip-build   # repackage target/release/ binaries
```

Every builder: `build-binaries.sh <family>` (unless `--skip-build`) →
`stage.sh` (shared payload tree, with a libc-family guard) → format-specific
packaging. The glibc build compiles the Cargo workspace inside an
`ubuntu:22.04` container (rustup stable + the -dev packages for GTK3/ayatana
appindicator, OpenSSL — linked by the workspace's bundled SQLCipher —,
libsecret and X11/Xext/Xrandr) so the binaries target glibc 2.35
(CONTRACTS §2), never the host glibc; the Alpine build does the same in an
`alpine:3.24` container against musl. `--skip-build` skips the container and
only stages + packages; the four binaries must already exist in
`target/release/` with the right libc family (stage.sh verifies). Results
are untracked build artifacts at the repo root (`*.deb`, `*.rpm`,
`*.pkg.tar.zst`, `*.apk` are gitignored).

### Model bundle (no placeholders shipped)

The clean-room classifier model bundle (`manifest.json` + content-addressed
artifacts, CONTRACTS §7) is **not** committed. To package it, drop it into
`models/` at the repo root before building; `build-deb.sh` installs it as
`/usr/share/lustless/models/`. Without it the package still builds and
installs: `postinst` creates the empty 0755 `models/` directory, and an
admin can drop the bundle in later. Screen accountability needs the bundle
at runtime; DNS filtering does not.

## Install behavior (`postinst configure`, idempotent)

1. **State dirs** with CONTRACTS §4 modes: `/var/lib/lustless` (0700),
   `previous-config/` (0700), `spool/` (0700), `/var/log/lustless{,/classifier}`
   (0755 — the `<pid>.log` files themselves are 0600, daemon-written), plus
   `/usr/share/lustless/{models,dashboard}` (0755). No system user is
   created — the daemon runs as root.
2. **DNS redirect** — the active resolver stack is detected and the matching
   redirect is installed; prior config is always backed up under
   `/var/lib/lustless/previous-config/` first:

   | detected stack | redirect installed |
   |---|---|
   | systemd-resolved active | drop-in `/etc/systemd/resolved.conf.d/lustless.conf` with `[Resolve] DNS=127.0.0.2`, `Domains=~.` (global route wins over per-link DHCP DNS), empty `FallbackDNS=` (fail closed); resolved restarted |
   | NetworkManager active (no resolved) | dispatcher script `/etc/NetworkManager/dispatcher.d/90-lustless-dns` re-applies a `nameserver 127.0.0.2` `/etc/resolv.conf` after every NM rewrite (`up`/`dhcp4-change`/`dhcp6-change`/`connectivity-change`) |
   | plain `/etc/resolv.conf` | backup (symlink target or file copy) + replace with `nameserver 127.0.0.2` |

   The detected stack is recorded in `previous-config/dns-stack`, so the
   reversal in `prerm` uses the same branch even if the stack changed since.
3. **Browser DoH-lockdown policies** (so browsers cannot bypass the
   DNS-level filter, CONTRACTS §15): Chrome, Chromium, Brave and Edge get
   `…/policies/managed/lustless.json`; Firefox gets `policies.json` with
   `DNSOverHTTPS {Enabled:false, Locked:true}`. Snap Chromium (the default
   browser on Xubuntu, Lubuntu and Ubuntu) reads its managed policies from
   the writable data area `/var/snap/chromium/current/etc/chromium/policies/managed/`
   instead of `/etc/chromium` — when the snap is present, `postinst`
   installs `lustless.json` there too (recorded and removed symmetrically
   like the deb paths). Chromium-family files sit at
   our reserved name `lustless.json` in each vendor's `managed/` namespace,
   so an admin's own policy files (different names) are never touched; a
   differing pre-existing `lustless.json` is backed up before being
   overwritten. Firefox's fixed-name file is **merge-safe**: if
   `/usr/lib/firefox/policies.json` already exists it is never clobbered —
   only the `DNSOverHTTPS` policy is merged in (via `python3`, which is
   present on any Ubuntu/Zorin desktop; without it the file is left
   untouched and a warning names the policy to add by hand). Every action
   (installed/replaced/merged) is recorded in
   `previous-config/browser-policies.list`.
4. **Polkit action** installed to `/usr/share/polkit-1/actions/org.lustless.policy`
   (`auth_admin_keep` for both actions; descriptions name the journald audit
   path — unit `lustlessd.service`, tags `org.lustless.break-glass` /
   `org.lustless.disable-protection`). Note: the polkit version shipped in
   Ubuntu 22.04 loads action files at polkitd startup, so a reboot (or
   polkitd restart) may be needed before the actions are first visible.
5. **Enable + start** `lustlessd.service` (`deb-systemd-helper` /
   `deb-systemd-invoke`, so `policy-rc.d` is honored).
6. **Install marker** `/var/lib/lustless/last-install` (version, timestamp,
   detected DNS stack) plus a `lustless-postinst` journal breadcrumb.

The GTK tray agent is a user unit; postinst cannot enable it on behalf of
every graphical session, so each user runs:

```sh
systemctl --user daemon-reload
systemctl --user enable --now lustless-agent.service
```

## Uninstall behavior

Removal follows CE's teardown order (CONTRACTS §11); `prerm` runs the full
sequence on `remove`, `deconfigure` **and** `upgrade`, and `postinst`
re-applies everything on the following `configure` (symmetric across
upgrades):

1. **Bounded flush** — `timeout 10 lustlessctl flush` asks the daemon to
   drain the outbox (activity/metrics/telemetry) within 10 s; absence or
   timeout never blocks the uninstall.
2. **Stop units** — `lustlessd.service` stopped. The user agent is
   session-scoped and not reachable from a maintainer script; it idles out
   with its session.
3. **Reverse the DNS redirect exactly as found** (see guarantee below).
4. **Remove only our browser policies** — files we installed fresh are
   deleted; files we merged into or replaced are restored from their
   backups, byte-for-byte.

`postrm purge` then verifies the DNS configuration was restored (repairing
crashed-uninstall leftovers from the backups when available, warning loudly
if not), removes the polkit action (restoring a replaced original if there
was one), removes `/var/log/lustless`, and `daemon-reload`s.

### DNS-restore guarantee

Uninstall MUST leave the system's DNS configuration exactly as found
(CONTRACTS §11). The mechanism is a strict backup/restore pair managed by
the maintainer scripts:

* every pre-existing config file is captured under
  `/var/lib/lustless/previous-config/` **before** the redirect is written
  (symlinks are recorded by target, regular files by copy, absence by
  marker);
* `prerm` restores from that backup using the recorded `dns-stack` branch,
  restarts systemd-resolved when applicable, and deletes the backup entries
  it consumed;
* `postrm purge` re-checks for leftovers (`lustless.conf` drop-in, NM
  dispatcher script, a `nameserver 127.0.0.2` resolv.conf) as a safety net
  for crashed/forced removals.

### Snap Firefox caveat

Firefox installed as a snap keeps its `policies.json` inside the read-only
snap filesystem (`/snap/firefox/<rev>/usr/lib/firefox/policies.json`).
AppArmor confines the snap there, and a manual remount-write would be
reverted by the next snap refresh — so a `.deb` installer **cannot
reliably apply the DoH lockdown to snap Firefox**. `postinst` detects the
snap, installs the policy if (and only if) the in-snap directory is
writable, and otherwise prints a warning recommending the deb build of
Firefox. On systems where bypass-proof filtering matters, ship Firefox as
a deb (Zorin OS does) or re-verify `about:policies` after snap refreshes.
Deb Firefox (`/usr/lib/firefox/policies.json`) is fully covered.

### State kept on purge (documented Debian-policy deviation)

Debian policy expects `purge` to remove everything a package created. We
keep exactly one thing: on purge, `/var/lib/lustless` is moved (not
deleted) to `/var/lib/lustless-PreviousConfiguration` (timestamped if that
name is taken). An accountability deployment may need the local record for
audit/export after removal; nothing functional is left behind — the live
state path, config, units, polkit action, DNS redirect and browser policies
are all gone. Completing the purge is one command:

```sh
rm -rf /var/lib/lustless-PreviousConfiguration
```
