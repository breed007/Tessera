#!/usr/bin/env bash
#
# Tessera standalone installer for Debian/Ubuntu (and other systemd Linux).
# Fetches the latest GitHub release and installs the native package when possible,
# otherwise drops the binary + systemd unit in place. Designed to be trivially
# adaptable to the community-scripts.org (ProxmoxVE Helper-Scripts) framework:
# in a Debian LXC, this is essentially "download the .deb, dpkg -i".
#
#   sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/tessera/tessera/main/scripts/install.sh)"
#
set -euo pipefail

REPO="tessera/tessera"
APP="tessera"

err() { echo "error: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

[ "$(id -u)" -eq 0 ] || err "run as root (sudo)."

case "$(uname -m)" in
	x86_64|amd64) ARCH=amd64 ;;
	aarch64|arm64) ARCH=arm64 ;;
	*) err "unsupported architecture: $(uname -m)" ;;
esac

echo "==> Resolving latest ${APP} release"
TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep -oE '"tag_name":\s*"[^"]+"' | head -1 | cut -d'"' -f4)"
[ -n "${TAG:-}" ] || err "could not determine the latest release tag"
VER="${TAG#v}"
echo "    ${TAG}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if have dpkg && have apt-get; then
	DEB="${APP}_${VER}_linux_${ARCH}.deb"
	echo "==> Installing ${DEB} via apt"
	curl -fsSL -o "${TMP}/${DEB}" "https://github.com/${REPO}/releases/download/${TAG}/${DEB}"
	apt-get install -y "${TMP}/${DEB}"
elif have rpm; then
	RPM="${APP}-${VER}-1.$([ "$ARCH" = amd64 ] && echo x86_64 || echo aarch64).rpm"
	echo "==> Installing ${RPM}"
	curl -fsSL -o "${TMP}/${RPM}" "https://github.com/${REPO}/releases/download/${TAG}/${RPM}"
	rpm -Uvh "${TMP}/${RPM}"
else
	echo "==> No package manager detected; installing the tarball manually"
	TGZ="${APP}_${VER}_linux_${ARCH}.tar.gz"
	curl -fsSL -o "${TMP}/${TGZ}" "https://github.com/${REPO}/releases/download/${TAG}/${TGZ}"
	tar -xzf "${TMP}/${TGZ}" -C "${TMP}"
	install -m 0755 "${TMP}/${APP}" /usr/bin/${APP}
	mkdir -p /etc/tessera
	[ -f /etc/tessera/config.yaml ] || install -m 0640 "${TMP}/tessera.example.yaml" /etc/tessera/config.yaml
	# Pull the unit + maintainer setup from the repo for non-packaged installs.
	curl -fsSL -o /lib/systemd/system/tessera.service "https://raw.githubusercontent.com/${REPO}/${TAG}/deploy/tessera.service"
	curl -fsSL "https://raw.githubusercontent.com/${REPO}/${TAG}/deploy/scripts/postinstall.sh" | sh
fi

echo "${VER}" > /etc/tessera/version
echo "==> Done. Review /etc/tessera/config.yaml, then: systemctl start tessera"
