#!/bin/bash
# Install the CLI from official ParrotSec sources on Ubuntu/Debian.
set -euo pipefail

if [[ -e /var/lib/desktop-anon/state.json ]] || systemctl is-active --quiet anonsurfd.service; then
    echo 'Stop the existing session with make stop anon before installing.' >&2
    exit 1
fi

sudo -v
sudo apt-get update
sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    macchanger golang-go tor iptables network-manager procps sudo make git \
    ca-certificates python3

build_dir=$(mktemp -d)
trap 'rm -rf -- "$build_dir"' EXIT
git clone --depth 1 https://github.com/ParrotSec/anonsurf.git "$build_dir/source"

# Build as the invoking user. Keep source and Go downloads in the temporary folder.
export GOPATH="$build_dir/gopath"
make -C "$build_dir/source" anonsurf-cli dnstool make-torrc anondaemon safekill

stage="$build_dir/package"
make -C "$build_dir/source" mk-folders inst-bins inst-configs DESTDIR="$stage"
chmod 600 "$stage/etc/anonsurf/anonsurf.cfg"
mkdir -p "$stage/DEBIAN"
version=$(sed -n '1s/^[^(]*(\([^)]*\)).*/\1/p' "$build_dir/source/debian/changelog")
architecture=$(dpkg --print-architecture)
cat > "$stage/DEBIAN/control" <<EOF
Package: anonsurf
Version: ${version}+local1
Architecture: ${architecture}
Maintainer: Local installation <root@localhost>
Depends: iptables, network-manager, procps, tor, systemd, sudo
Description: AnonSurf command-line Tor routing toolkit
 Built locally from the official ParrotSec source, CLI only.
EOF
cat > "$stage/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
systemctl daemon-reload
EOF
chmod 755 "$stage/DEBIAN/postinst"
dpkg-deb --root-owner-group --build "$stage" "$build_dir/anonsurf-local.deb"
sudo dpkg -i "$build_dir/anonsurf-local.deb"
anonsurf --version
macchanger --version
echo 'Installation complete. Start with make anon; restore with make stop anon.'
