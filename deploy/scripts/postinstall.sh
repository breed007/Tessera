#!/bin/sh
# nfpm postinstall — runs after the package unpacks (.deb/.rpm/.apk).
# Portable across useradd (Debian/RHEL) and adduser (Alpine/BusyBox).
set -e

# Dedicated, unprivileged system user/group.
if ! getent group tessera >/dev/null 2>&1; then
	groupadd --system tessera 2>/dev/null || addgroup -S tessera 2>/dev/null || true
fi
if ! getent passwd tessera >/dev/null 2>&1; then
	useradd --system --gid tessera --home-dir /var/lib/tessera \
		--shell /usr/sbin/nologin --comment "Tessera IPAM" tessera 2>/dev/null \
		|| adduser -S -G tessera -h /var/lib/tessera -s /sbin/nologin tessera 2>/dev/null \
		|| true
fi

# Data directory (the SQLite DB lives here).
mkdir -p /var/lib/tessera
chown -R tessera:tessera /var/lib/tessera
chmod 0750 /var/lib/tessera

# Config directory is root-owned, group-readable by the service.
if [ -d /etc/tessera ]; then
	chown -R root:tessera /etc/tessera 2>/dev/null || true
	chmod 0750 /etc/tessera 2>/dev/null || true
	[ -f /etc/tessera/config.yaml ] && chmod 0640 /etc/tessera/config.yaml 2>/dev/null || true
fi

# Fresh install vs upgrade: deb passes "configure <old-version>" ($2 empty on a
# first install); rpm passes a count ($1 = 2 on upgrade).
fresh=1
[ "${1:-}" = "configure" ] && [ -n "${2:-}" ] && fresh=0
[ "${1:-}" = "2" ] && fresh=0

if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload 2>/dev/null || true
	systemctl enable tessera.service 2>/dev/null || true
	# restart (not start) so an upgrade actually picks up the new binary; on a
	# fresh install this simply starts it so first-run setup is ready.
	systemctl restart tessera.service 2>/dev/null || true

	if [ "$fresh" -eq 1 ]; then
		IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
		[ -n "$IP" ] || IP="<this-host>"
		echo ""
		echo "  ✓ Tessera is installed and running."
		echo ""
		echo "    Open  http://${IP}:10404  and create your admin account."
		echo ""
		echo "  Everything else is configured in the UI (Settings). No config editing"
		echo "  needed. Full reference: /usr/share/doc/tessera/tessera.example.yaml"
		echo ""
	fi
fi

exit 0
