#!/bin/sh
# nfpm postremove — deb postrm / rpm %postun / apk post-deinstall.
#
#   apt remove   → keep data + the tessera user so a reinstall resumes the same
#                  inventory; just reload systemd. (The conffile is also kept by
#                  dpkg on remove.)
#   apt purge    → ALSO delete the data dir, runtime secrets, config dir, and the
#                  dedicated system user/group — a clean, complete teardown.
#
# Argument conventions:
#   deb : "remove" | "purge" | "upgrade <ver>" | "disappear" | "abort-*"
#   rpm : a count — 0 = final erase, 1 = upgrade   (rpm has no "purge")
#   apk : (no argument)
set -e

if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload 2>/dev/null || true
fi

if [ "${1:-}" = "purge" ]; then
	# Runtime state dpkg doesn't track (SQLite DB, master secret.key, setup-token)
	# plus the package-owned data dir.
	rm -rf /var/lib/tessera 2>/dev/null || true

	# dpkg removes the conffile itself on purge; drop the now-empty config dir.
	rm -f /etc/tessera/config.yaml 2>/dev/null || true
	rmdir /etc/tessera 2>/dev/null || true

	# Dedicated system user/group (best effort, portable across distros).
	if getent passwd tessera >/dev/null 2>&1; then
		userdel tessera 2>/dev/null || deluser tessera 2>/dev/null || true
	fi
	if getent group tessera >/dev/null 2>&1; then
		groupdel tessera 2>/dev/null || delgroup tessera 2>/dev/null || true
	fi
fi

exit 0
