#!/bin/sh
# nfpm preremove — deb prerm / rpm %preun / apk pre-deinstall.
#
# Stop AND disable the service while its unit file still exists (so the enable
# symlinks are cleaned up properly), but ONLY on a real removal — never during an
# upgrade, where the service is stopped/restarted by the new package's postinstall.
#
# Argument conventions differ per packager:
#   deb : "remove" | "upgrade <ver>" | "deconfigure ..." | "failed-upgrade <ver>"
#   rpm : a count — 0 = final erase, 1 = upgrade
#   apk : (no argument)
set -e

case "${1:-}" in
	upgrade | failed-upgrade | 1)
		# Upgrade in progress — leave the running, enabled service alone.
		;;
	*)
		if command -v systemctl >/dev/null 2>&1; then
			systemctl stop tessera.service 2>/dev/null || true
			systemctl disable tessera.service 2>/dev/null || true
		fi
		;;
esac

exit 0
