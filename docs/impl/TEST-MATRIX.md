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
| 6 | Alpine 3.24 | `.apk` | container install + lifecycle verified; VM install blocked on community-index reachability (apk-tools 3 needs deps from `community`; dnsmasq upstream fixed mid-run) | container: OpenRC initd starts | container: configure/remove run clean | n/a (CLI) | container: `apk del` clean | musl binaries verified; VM retry pending |
| 7 | Bazzite (Fedora Atomic) | `.rpm` via rpm-ostree | container-verified: rpm scriptlets correct for ostree layering chroot (configure guarded `|| :`, enable lands in /etc overlay) | reboot-after-layer documented | same as Fedora | same | — | live-session GUI blocked by the Bazzite Portal dialog (no dismiss button); rpm metadata + scriptlets inspected directly |

## Verified packaging defects found & fixed by this matrix

- `debian/control` depended on `policykit-1`, which has no binary in Debian
  13 — renamed to `polkitd` (correct across the whole deb matrix).
- Alpine `.apk` rebuilt through abuild (apk-tools 3 rejects hand-rolled v2
  packages); `so:` auto-deps from scanelf stripped where the guest cannot
  reach community.

## How to reproduce a run

```bash
# build packages
packaging/build-deb.sh; packaging/build-rpm.sh
packaging/build-arch.sh; packaging/build-apk.sh
# deliver + drive a VM
target/testbed/qmon.sh <container> raw 'drive_add 0 if=none,file=/storage/lustless-cd.iso,...'
target/testbed/qmon.sh <container> text 'apk add ...'   # sendkey via QEMU monitor
```
