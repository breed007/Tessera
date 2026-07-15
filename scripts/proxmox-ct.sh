#!/usr/bin/env bash
#
# Tessera — Proxmox VE LXC installer.
#
# Run this ON THE PROXMOX HOST (the PVE shell), as root. It creates a small,
# unprivileged Debian container, installs Tessera from a .deb you supply, and
# starts it. Then browse to the container's IP:10404 and create the admin account.
#
#   # from a URL you can reach:
#   DEB_URL="https://your-host/tessera_amd64.deb" bash -c "$(cat proxmox-ct.sh)"
#
#   # or from a .deb sitting on the PVE host:
#   DEB_FILE="/root/tessera_amd64.deb" bash proxmox-ct.sh
#
# Everything is overridable by env var — see the defaults below.
#
# NETWORK / SPAN NOTE: this creates ONE management interface (net0, DHCP). The
# passive SPAN/mirror sensor is intentionally NOT set up — it needs a dedicated
# mirror-port NIC, a privileged container, and the pcap build. The default install
# discovers via the active prober + UniFi + Proxmox + DHCP collectors, none of
# which need a SPAN port. See "Adding a SPAN sensor later" printed at the end.

set -euo pipefail

# ── tunables (env-overridable) ───────────────────────────────────────────────
CTID="${CTID:-}"                       # blank → next free id
HOSTNAME="${HOSTNAME:-tessera}"
CORES="${CORES:-1}"                    # Tessera idles ~50–150 MB; 1 core is plenty
RAM="${RAM:-1024}"                     # MB
SWAP="${SWAP:-512}"                    # MB
DISK="${DISK:-8}"                      # GB (DB + logs headroom)
BRIDGE="${BRIDGE:-vmbr0}"              # management bridge
STORAGE="${STORAGE:-local-lvm}"        # rootfs storage
TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-local}"
TEMPLATE="${TEMPLATE:-debian-12-standard}" # substring match against pveam list
DEB_URL="${DEB_URL:-}"                 # http(s) URL to the .deb
DEB_FILE="${DEB_FILE:-}"               # OR a local path on the PVE host
UNPRIVILEGED="${UNPRIVILEGED:-1}"

err() { echo "error: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

[ "$(id -u)" -eq 0 ] || err "run as root on the Proxmox host."
have pct || err "pct not found — run this on a Proxmox VE host, not inside a container."
[ -n "$DEB_URL" ] || [ -n "$DEB_FILE" ] || err "set DEB_URL=<url> or DEB_FILE=<path> to the Tessera .deb (build it with 'goreleaser release --snapshot')."
[ -z "$DEB_FILE" ] || [ -f "$DEB_FILE" ] || err "DEB_FILE not found: $DEB_FILE"

# ── resolve a container id ───────────────────────────────────────────────────
if [ -z "$CTID" ]; then
	CTID="$(pvesh get /cluster/nextid 2>/dev/null || echo 900)"
fi
pct status "$CTID" >/dev/null 2>&1 && err "CTID $CTID already exists — set CTID=<free id>."

# ── ensure a Debian template is present ──────────────────────────────────────
echo "==> Locating a $TEMPLATE template on $TEMPLATE_STORAGE"
TMPL="$(pveam list "$TEMPLATE_STORAGE" 2>/dev/null | awk '{print $1}' | grep -F "$TEMPLATE" | head -1 || true)"
if [ -z "$TMPL" ]; then
	echo "    not found; updating template catalog and downloading"
	pveam update >/dev/null 2>&1 || true
	AVAIL="$(pveam available --section system | awk '{print $2}' | grep -F "$TEMPLATE" | sort | tail -1 || true)"
	[ -n "$AVAIL" ] || err "no $TEMPLATE template available; run 'pveam available' and set TEMPLATE=<name>."
	pveam download "$TEMPLATE_STORAGE" "$AVAIL"
	TMPL="$(pveam list "$TEMPLATE_STORAGE" | awk '{print $1}' | grep -F "$TEMPLATE" | head -1)"
fi
echo "    $TMPL"

# ── create + start the container ─────────────────────────────────────────────
echo "==> Creating CT $CTID ($HOSTNAME): ${CORES} core / ${RAM}MB / ${DISK}GB on $BRIDGE"
pct create "$CTID" "$TMPL" \
	--hostname "$HOSTNAME" \
	--cores "$CORES" --memory "$RAM" --swap "$SWAP" \
	--rootfs "${STORAGE}:${DISK}" \
	--net0 "name=eth0,bridge=${BRIDGE},ip=dhcp" \
	--features nesting=1 \
	--unprivileged "$UNPRIVILEGED" \
	--onboot 1 \
	--description "Tessera — discovery-first IPAM"

pct start "$CTID"
echo "==> Waiting for the container network"
for _ in $(seq 1 30); do
	pct exec "$CTID" -- getent hosts deb.debian.org >/dev/null 2>&1 && break
	sleep 2
done

# ── install Tessera inside the CT ────────────────────────────────────────────
echo "==> Installing dependencies"
pct exec "$CTID" -- bash -c "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates curl >/dev/null"

echo "==> Installing Tessera"
if [ -n "$DEB_FILE" ]; then
	pct push "$CTID" "$DEB_FILE" /tmp/tessera.deb
else
	pct exec "$CTID" -- bash -c "curl -fsSL -o /tmp/tessera.deb '$DEB_URL'"
fi
pct exec "$CTID" -- bash -c "DEBIAN_FRONTEND=noninteractive apt-get install -y /tmp/tessera.deb && rm -f /tmp/tessera.deb"

# ── report ───────────────────────────────────────────────────────────────────
IP="$(pct exec "$CTID" -- bash -c "hostname -I | awk '{print \$1}'" 2>/dev/null | tr -d '[:space:]')"
cat <<EOF

────────────────────────────────────────────────────────────────────────────
 Tessera is installed in CT $CTID ($HOSTNAME).

   Open:   http://${IP:-<container-ip>}:10404
   Then:   create the admin account (open first-run — first visitor is admin).

 Enable collectors under Settings once you're in:
   • Proxmox VE  — point it at this host's API (read-only token) to name your VMs/CTs
   • UniFi       — for topology + the switch port map
   • Active prober / DHCP — for discovery without a SPAN port

 Adding a SPAN/mirror sensor later (advanced, optional):
   The passive sensor needs mirrored traffic + libpcap, which this default CT
   doesn't have. To add it:
     1. On the PVE host, attach a 2nd bridge to the SPAN/mirror port and add it
        to the CT:   pct set $CTID -net1 name=eth1,bridge=vmbrX
     2. Make the CT privileged (recreate with UNPRIVILEGED=0) so it can put the
        NIC in promiscuous mode.
     3. Install a pcap-enabled Tessera build (the stock .deb is pure-Go, no pcap)
        and enable the sensor on that interface in Settings.
────────────────────────────────────────────────────────────────────────────
EOF
