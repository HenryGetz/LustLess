# PACKAGING-MATRIX — multi-distro packaging and test contract

Authoritative contract for building and verifying LustLess on every supported
distro. Consumers: packaging build scripts (`packaging/build-*.sh`), the VM
testbed (`packaging/testbed/`), and the acceptance runs. Filesystem layout stays
`docs/impl/CONTRACTS.md` §4 (unchanged by this matrix).

## 1. Target matrix

| # | Distro (test target) | Base | libc | Package | Init | Desktop | Test VM (noVNC port) |
|---|---|---|---|---|---|---|---|
| 1 | Zorin OS 17 Lite / Core | Ubuntu 22.04 | glibc 2.35 | `.deb` | systemd | Xfce / GNOME | 8007 / 8006 (existing) |
| 2 | Ubuntu LTS 24.04 | Ubuntu 24.04 | glibc 2.39 | `.deb` | systemd | GNOME | 8009 (existing) |
| 3 | Xubuntu 24.04 / Lubuntu 24.04 | Ubuntu 24.04 | glibc 2.39 | `.deb` | systemd | Xfce / LXQt | 8008 / 8010 (existing) |
| 4 | Debian Stable (13, live GNOME) | Debian 13 | glibc ≥ 2.35 | `.deb` | systemd | GNOME | 8011 |
| 5 | Linux Mint (current, Cinnamon) | Ubuntu 24.04 | glibc ≥ 2.35 | `.deb` | systemd | Cinnamon | 8012 |
| 6 | Fedora Workstation (current) | Fedora | glibc ≥ 2.35 | `.rpm` | systemd | GNOME | 8013 |
| 7 | Arch Linux (current) | rolling | glibc (rolling) | pkg.tar.zst | systemd | CLI live (+XFCE optional) | 8014 |
| 8 | Alpine Linux (current, extended ISO) | musl | **musl** | `.apk` | **OpenRC** | CLI | 8015 |
| 9 | Bazzite (current, GNOME) | Fedora Atomic | glibc ≥ 2.35 | `.rpm` via `rpm-ostree` | systemd | GNOME | 8016 |

SteamOS: **no public install ISO exists** (only the Steam Deck recovery image),
so SteamOS-class coverage is row 7 (same `pacman` base) + row 9 (immutable
root). `packaging/README.md` MUST document the SteamOS procedure
(`steamos-readonly disable` + `pacman -U`, or a distrobox container).

Build rule: **one glibc build** (ubuntu:22.04 container, glibc 2.35 baseline,
`--no-default-features`) serves rows 1–7 and 9 — older glibc binaries run on
newer glibc, never the reverse. Row 8 gets a **separate musl build** in an
alpine container. The classifier is pure Rust (`onnx.rs` is a hand-rolled
evaluator — no `ort`/onnxruntime), so musl is expected to work; if a crate
blocks the musl build, fix minimally or report.

## 2. Package formats, names, outputs

All build outputs land at the **repo root** (gitignored — extend `.gitignore`
with `*.rpm`, `*.pkg.tar.zst`, `*.apk`):

| Format | File name | Builder |
|---|---|---|
| deb | `lustless_0.1.4_amd64.deb` | `packaging/build-deb.sh` |
| rpm | `lustless-0.1.4-1.x86_64.rpm` | `packaging/build-rpm.sh` |
| Arch | `lustless-0.1.4-1-x86_64.pkg.tar.zst` | `packaging/build-arch.sh` |
| apk | `lustless-0.1.4-r0.apk` | `packaging/build-apk.sh` |

The apk is **signed** with a project RSA key (`target/apk-key/`, gitignored;
the matching `lustless.rsa.pub` is emitted at the repo root and MUST ship
next to the package so installs verify — `apk add --allow-untrusted`
also works). It is assembled directly (control/data/signature streams
mirroring abuild's own byte layout) because abuild's mandatory fakeroot
packaging step crashes in container kernels without full fakeroot support.

Version stays `0.1.4` (matches the Cargo workspace). Package name is `lustless`
everywhere.

**Smart-build rule:** one staging tree is the single source of truth
(`packaging/stage.sh` builds `$repo_root/target/pkg-root/` with the §4 layout);
each `build-*.sh` consumes the stage and adds only format metadata/scriptlets.
The four packages MUST ship byte-identical payloads except for format metadata.

## 3. Maintainer logic — one helper, four scriptlets

All install/remove/upgrade logic lives in **one** script staged at
`/usr/lib/lustless/lustless-maintainer`, subcommands:

- `configure <old-version>` — units enable/restart, DNS redirect, polkit action
  install, browser policy merge (all recorded for reversal)
- `remove` — stop/disable units, restore DNS + browser policies + polkit
- `purge` — `remove` + drop state (keep the Debian-policy deviations already
  documented in `packaging/README.md`)

Current `packaging/debian/{postinst,prerm,postrm}` logic (DNS redirect,
`previous-config/` registry, browser-policy merge, polkit, flavor hints) is the
behavioral source of truth: extract it into the helper unchanged; the Debian
scriptlets become thin callers. rpm `%post/%preun/%postun`, Arch `.install`,
and apk `.post-install/.post-deinstall` call the same helper.

**Idempotency requirement:** the helper MUST be idempotent and safe to re-run
(`lustless-maintainer configure` by hand) because immutable systems may skip
scriptlets. Where a package manager runs no scriptlets at all, the operator
command in the README is the fallback.

## 4. Invariants (must hold on every distro)

1. **DNS:** after install, the system's name resolution goes through the local
   proxy (`127.0.0.2`, see `crates/lustless-dns/`), and a blocked test name is
   blocked while a normal name resolves. Mechanism per family:
   - systemd-resolved distros (Ubuntu, Zorin, Mint, Fedora, Bazzite): resolved
     config drop-in / `resolvectl` per the existing postinst behavior
   - plain `resolv.conf` distros (Debian default, Arch default, Alpine):
     managed swap with backup + restore
   - after `remove`/`purge`, the pre-install resolver state is restored exactly.
2. **Init:** `lustlessd` runs as a system service — systemd unit (rows 1–7, 9)
   or **OpenRC** init.d script (row 8) — enabled at boot. `lustless-agent` is a
   systemd *user* unit where user sessions are systemd (all glibc distros); on
   Alpine ship an XDG autostart `.desktop` fallback (may also be shipped
   everywhere as a harmless second path). Every format also ships the
   application-menu launcher (`/usr/share/applications/lustless-agent.desktop`,
   `Exec=lustless-agent --show`) — the sign-in surface on desktops without an
   SNI host, where the tray menu does not exist. LXQt/Alpine have no SNI host:
   agent degrades per `packaging/README.md`.
3. **Immutable (Bazzite/SteamOS):** install is `rpm-ostree install ./<rpm>` /
   `pacman -U <pkg>`; `/etc` writes must survive (they do — writable overlay);
   never write to `/usr` outside the package payload. Reboot expected after
   layering.
4. **Payload (§4 layout):** `/usr/bin/{lustlessd,lustless-classifier,lustless-agent,lustlessctl}`,
   `/usr/share/lustless/{models,dashboard,polkit,browser-policies}`,
   `/etc/lustless/lustless.toml` (conffile semantics per format), units or
   OpenRC scripts, pixmap icon. Model bundle staged by
   `crates/lustless-classifier/fetch-model.sh` (offline from `re/samples/`,
   upstream authorization covers the CE materials; private repo).

## 5. Dependency map (verify exact names against each distro's repos at build time)

| Capability | deb (existing control) | rpm (Fedora) | Arch | Alpine |
|---|---|---|---|---|
| TLS | `libssl3` | `openssl-libs` | `openssl` | `openssl` |
| Tray (GTK) | `libgtk-3-0` | `gtk3` | `gtk3` | `gtk+3.0` |
| Tray (SNI) | `libayatana-appindicator3-1` | `libayatana-appindicator-gtk3` | `libayatana-appindicator` | `libayatana-appindicator` (community) |
| Init | `systemd` | `systemd` | `systemd` | `openrc` |
| Auth | `policykit-1` | `polkit` | `polkit` | `polkit` |
| IPC | `dbus` | `dbus` | `dbus` | `dbus` |
| CA store | `ca-certificates` | `ca-certificates` | `ca-certificates` | `ca-certificates` |

Packages SHOULD declare these as hard deps (the tray may move to Recommends/
optdepends only where the format has no weaker class and the app still runs
headless).

## 6. Acceptance checklist (per distro — the definition of "it works")

Run in the distro's own VM; every box checked and the report saved to
`target/testbed/reports/<distro>.txt`:

1. **Install** from the local package file with the native tool
   (`apt install ./…` / `dnf install ./…` / `rpm-ostree install ./…` /
   `pacman -U …` / `apk add --allow-untrusted …` or local repo); all
   dependencies resolve from the distro's own repos (record anything pulled).
2. **Services:** `lustlessd` enabled + active (`systemctl` or
   `rc-service lustlessd status`); comes back after a reboot where the VM
   persists; `lustless-agent` active for the desktop user (or XDG autostart
   fallback on Alpine).
3. **Functional:** `lustlessctl status` healthy; `dig @127.0.0.2
   blocked.example.test` is blocked; `dig @127.0.0.2 example.com` resolves;
   dashboard `http://127.0.0.1:8760/` returns 200 (token URL from
   `lustlessctl`).
4. **Desktop:** tray/indicator visible on desktop rows (SNI host present);
   notification path works or degrades documentedly.
5. **Uninstall:** `apt purge` / `dnf remove` / `rpm -e` / `pacman -R` /
   `apk del` restores DNS to the pre-install state, removes package files and
   units, leaves no running processes.

## 7. Testbed conventions (existing, unchanged)

- VMs: `qemux/qemu` via `packaging/testbed/docker-compose.yml`, one service per
  flavor behind a compose profile; always name the service in up/stop/down.
- ISOs live in `target/testbed/iso/` (gitignored) with sha256 recorded in
  `packaging/testbed/README.md`.
- Host↔VM exchange: an HTTP server on the host (`packaging/testbed/serve.sh`,
  port 9996, listening on all interfaces) serves packages/scripts to VMs; VMs
  find it via their default gateway (`ip route` inside the VM — the harness
  scripts self-locate) and POST report files back. Sudo password in live
  sessions: `lustless123`. Reports land in `target/testbed/reports/`.
- VM interaction: noVNC web viewer on the service's host port (8006–8016);
  console screenshots land in `target/testbed/`.
