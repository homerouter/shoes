#!/usr/bin/env bash
# Package shoes binary into a Debian .deb package
set -euo pipefail

if [ "$#" -lt 4 ]; then
    echo "Usage: $0 <binary-path> <target-arch> <version> <output-dir>"
    echo "Example: $0 target/x86_64-unknown-linux-musl/release/shoes amd64 0.3.9 artifacts"
    exit 1
fi

BINARY="$1"
ARCH="$2"
VERSION="$3"
OUTDIR="$4"

if [ ! -f "$BINARY" ]; then
    echo "Error: Binary not found at $BINARY" >&2
    exit 1
fi

# Map Rust targets to Debian arch if full target triple was passed
case "$ARCH" in
    x86_64-*) ARCH="amd64" ;;
    aarch64-*) ARCH="arm64" ;;
    armv7-*) ARCH="armhf" ;;
    mips-*) ARCH="mips" ;;
esac

# Normalize version (remove leading 'v')
VERSION="${VERSION#v}"

PKG_NAME="shoes_${VERSION}_${ARCH}"
BUILD_ROOT="$(mktemp -d "/tmp/${PKG_NAME}.XXXXXX")"
chmod 755 "$BUILD_ROOT"
trap 'rm -rf "$BUILD_ROOT"' EXIT

# Create directory hierarchy
mkdir -p "$BUILD_ROOT/DEBIAN"
mkdir -p "$BUILD_ROOT/usr/bin"
mkdir -p "$BUILD_ROOT/lib/systemd/system"
mkdir -p "$BUILD_ROOT/etc/shoes"
mkdir -p "$BUILD_ROOT/usr/share/doc/shoes"

# Copy binary
cp "$BINARY" "$BUILD_ROOT/usr/bin/shoes"
chmod 755 "$BUILD_ROOT/usr/bin/shoes"

# Install systemd services
cat << 'SERVICE_EOF' > "$BUILD_ROOT/lib/systemd/system/shoes.service"
[Unit]
Description=shoes multi-protocol proxy server
Documentation=https://github.com/homerouter/shoes
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/shoes /etc/shoes/config.yaml
Restart=on-failure
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SERVICE_EOF
chmod 644 "$BUILD_ROOT/lib/systemd/system/shoes.service"

if [ -f "examples/shoes-desktop.service" ]; then
    sed 's|/usr/local/bin/shoes|/usr/bin/shoes|g' examples/shoes-desktop.service > "$BUILD_ROOT/lib/systemd/system/shoes-desktop.service"
    chmod 644 "$BUILD_ROOT/lib/systemd/system/shoes-desktop.service"
fi

# Example configs
if [ -f "examples/quickstart_socks.yaml" ]; then
    cp examples/quickstart_socks.yaml "$BUILD_ROOT/etc/shoes/config.yaml.example"
    chmod 644 "$BUILD_ROOT/etc/shoes/config.yaml.example"
fi
if [ -f "examples/tun_desktop.yaml" ]; then
    cp examples/tun_desktop.yaml "$BUILD_ROOT/etc/shoes/desktop.yaml.example"
    chmod 644 "$BUILD_ROOT/etc/shoes/desktop.yaml.example"
fi

# Documentation and licenses
if [ -f "LICENSE" ]; then
    cp LICENSE "$BUILD_ROOT/usr/share/doc/shoes/copyright"
    chmod 644 "$BUILD_ROOT/usr/share/doc/shoes/copyright"
fi
if [ -f "THIRD_PARTY_NOTICES.md" ]; then
    cp THIRD_PARTY_NOTICES.md "$BUILD_ROOT/usr/share/doc/shoes/"
    chmod 644 "$BUILD_ROOT/usr/share/doc/shoes/THIRD_PARTY_NOTICES.md"
fi
if [ -f "README.md" ]; then
    cp README.md "$BUILD_ROOT/usr/share/doc/shoes/"
    chmod 644 "$BUILD_ROOT/usr/share/doc/shoes/README.md"
fi

# Control file
cat << CONTROL_EOF > "$BUILD_ROOT/DEBIAN/control"
Package: shoes
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: debiansid <9624961+debiansid@users.noreply.github.com>
Homepage: https://github.com/homerouter/shoes
Description: A multi-protocol proxy server
 shoes is a fast, memory-safe, multi-protocol proxy server supporting
 Snell, Shadowsocks, Trojan, VLESS, VMess, Hysteria2, TUIC, and more.
CONTROL_EOF
chmod 644 "$BUILD_ROOT/DEBIAN/control"

# Maintainer scripts
cat << 'MAINT_EOF' > "$BUILD_ROOT/DEBIAN/postinst"
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
    if [ -d /run/systemd/system ]; then
        systemctl --system daemon-reload >/dev/null 2>&1 || true
    fi
fi
exit 0
MAINT_EOF
chmod 755 "$BUILD_ROOT/DEBIAN/postinst"

cat << 'MAINT_EOF' > "$BUILD_ROOT/DEBIAN/prerm"
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "upgrade" ] || [ "$1" = "deconfigure" ]; then
    if [ -d /run/systemd/system ]; then
        systemctl --system stop shoes.service >/dev/null 2>&1 || true
        systemctl --system stop shoes-desktop.service >/dev/null 2>&1 || true
    fi
fi
exit 0
MAINT_EOF
chmod 755 "$BUILD_ROOT/DEBIAN/prerm"

cat << 'MAINT_EOF' > "$BUILD_ROOT/DEBIAN/postrm"
#!/bin/sh
set -e
if [ "$1" = "purge" ] || [ "$1" = "remove" ]; then
    if [ -d /run/systemd/system ]; then
        systemctl --system daemon-reload >/dev/null 2>&1 || true
    fi
fi
exit 0
MAINT_EOF
chmod 755 "$BUILD_ROOT/DEBIAN/postrm"

# Build package
mkdir -p "$OUTDIR"
dpkg-deb --build --root-owner-group "$BUILD_ROOT" "${OUTDIR}/${PKG_NAME}.deb"
echo "Successfully built ${OUTDIR}/${PKG_NAME}.deb"
