# LustLess — RPM package (Fedora Workstation / Bazzite rpm-ostree;
# PACKAGING-MATRIX §4–§5). The payload tree is prebuilt by
# packaging/stage.sh (single source for all four formats) from the hermetic
# glibc-2.35 container build; this spec adds metadata + scriptlets only.
#
# The build container mounts the repo at /src (packaging/build-rpm.sh).

Name:           lustless
Version:        0.1.7
Release:        1
Summary:        Accountability client: screen accountability + DNS filtering (Linux edition)
License:        Proprietary
URL:            https://github.com/HenryGetz/LustLess
BuildArch:      x86_64
# ELF auto-requires map the bundled libs to this distro's packages (gtk3,
# openssl-libs, libayatana-appindicator-gtk3, polkit, dbus…); these manual
# entries cover the non-ELF runtime deps.
Requires:       ca-certificates python3

%description
Accountability client: on-device screen accountability (capture plus a local
classifier — screenshot data never leaves the device), DNS-level web
filtering with per-query verdicts via a local forwarder on 127.0.0.2:53, a
token-authenticated local dashboard, and a polkit-gated administrative
escape hatch.

Ships the lustlessd system daemon, the lustless-classifier scoring process,
the lustless-agent GTK tray helper (systemd user unit + XDG autostart), and
the lustlessctl CLI. See /etc/lustless/lustless.toml for configuration and
/usr/lib/lustless/lustless-maintainer for the package lifecycle helper.

%prep
# nothing — payload prebuilt by packaging/stage.sh.

%build
# nothing — prebuilt binaries.

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a /src/target/pkg-root/. %{buildroot}/

%files
%config(noreplace) /etc/lustless/lustless.toml
/etc/xdg/autostart/lustless-agent.desktop
/usr/share/applications/lustless-agent.desktop
/usr/bin/lustlessd
/usr/bin/lustless-classifier
/usr/bin/lustless-agent
/usr/bin/lustlessctl
/usr/lib/lustless/lustless-maintainer
%dir /usr/share/lustless
/usr/share/lustless/*
/usr/share/pixmaps/lustless.png
/usr/share/lustless/lustless-mark.png
/usr/share/icons/hicolor/*/apps/lustless.png
/usr/lib/systemd/system/lustlessd.service
/usr/lib/systemd/user/lustless-agent.service

%post
# Idempotent configure (PACKAGING-MATRIX §3). On rpm-ostree (Bazzite) this
# runs in a scriptlet chroot: the DNS redirect and enable-symlink land in
# the /etc overlay, the service start is ignored; the daemon comes up on the
# first boot after layering.
/usr/lib/lustless/lustless-maintainer configure "%{version}-%{release}" || :

%preun
# Runs BEFORE payload files are removed — the helper is always present here.
if [ "$1" -eq 0 ]; then
    # erase: full teardown, then finalize.
    /usr/lib/lustless/lustless-maintainer remove || :
    /usr/lib/lustless/lustless-maintainer purge || :
else
    # upgrade: teardown; the new package's %post re-applies everything.
    /usr/lib/lustless/lustless-maintainer remove || :
fi

%postun
# Payload is gone on erase — only reload the service manager (no-op inside
# an rpm-ostree scriptlet chroot; harmless).
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || :
fi

%changelog
* Sun Oct 12 2026 LustLess Maintainers <maintainers@lustless.invalid> - 0.1.0-1
- Initial multi-distro package (see docs/impl/PACKAGING-MATRIX.md).
