#!/usr/bin/env bash
# Builds the anglerfish .deb from the repo's current working tree. Used
# both for local test builds and by .github/workflows/build-deb.yml, so
# there's exactly one place that knows how the package is put together.
#
# Version comes from $VERSION if set, otherwise from the git tag
# (GITHUB_REF=refs/tags/v*) or a dev/beta stamp derived from HEAD.
set -euo pipefail
cd "$(dirname "$0")"

jq empty package.json
bash -n anglerfi.sh
if command -v groff >/dev/null; then
    groff -man -Tascii -ww -z anglerfi.sh.1
else
    echo "build-deb.sh: groff not found, skipping man page lint"
fi

if [ -z "${VERSION:-}" ]; then
    if [[ "${GITHUB_REF:-}" == refs/tags/v* ]]; then
        VERSION="${GITHUB_REF#refs/tags/v}"
    else
        VERSION="0.1.0~beta.$(date +%Y%m%d%H%M).$(git rev-parse --short HEAD)"
    fi
fi

PKG_ROOT="build/anglerfish_${VERSION}_all"
rm -rf "$PKG_ROOT"
mkdir -p "$PKG_ROOT/DEBIAN" "$PKG_ROOT/usr/bin" "$PKG_ROOT/etc/anglerfish" "$PKG_ROOT/usr/share/man/man1"

install -m 755 anglerfi.sh "$PKG_ROOT/usr/bin/anglerfi.sh"
ln -sf anglerfi.sh "$PKG_ROOT/usr/bin/af"
install -m 644 package.json "$PKG_ROOT/etc/anglerfish/package.json"
gzip -9 -n -c anglerfi.sh.1 > "$PKG_ROOT/usr/share/man/man1/anglerfi.sh.1.gz"
ln -sf anglerfi.sh.1.gz "$PKG_ROOT/usr/share/man/man1/af.1.gz"

echo "/etc/anglerfish/package.json" > "$PKG_ROOT/DEBIAN/conffiles"

cat > "$PKG_ROOT/DEBIAN/control" <<EOF
Package: anglerfish
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: all
Depends: jq, wget, curl, tar, unzip, python3, git, iptables, iptables-persistent
Maintainer: zyg0th <core.zyg0th@gmail.com>
Description: Unified Package Manager for Offensive Security Box
 Wraps apt/go/manual installs behind one CLI so multiple package
 managers stop stepping on each other on an offensive security box.
EOF

if [[ "${GITHUB_REF:-}" != refs/tags/v* ]]; then
    printf ' .\n This is a beta / development build.\n' >> "$PKG_ROOT/DEBIAN/control"
fi

mkdir -p dist
dpkg-deb --root-owner-group --build "$PKG_ROOT" "dist/anglerfish_${VERSION}_all.deb"
dpkg-deb --info "dist/anglerfish_${VERSION}_all.deb"
echo "build-deb.sh: built dist/anglerfish_${VERSION}_all.deb"
