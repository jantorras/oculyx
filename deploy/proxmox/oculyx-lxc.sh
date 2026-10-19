#!/usr/bin/env bash
# Create an Oculyx server in a new Proxmox VE LXC container (Debian 12, unprivileged).
# Run this on the Proxmox host shell as root:
#
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/jantorras/oculyx/main/deploy/proxmox/oculyx-lxc.sh)"
#
# Everything has a sensible default; override with flags (see --help) or just press Enter.
set -euo pipefail

REPO="${OCULYX_REPO:-jantorras/oculyx}"
VERSION="${OCULYX_VERSION:-latest}"
CTID=""
CT_HOSTNAME="oculyx"
CORES=2
RAM=1024
SWAP=512
DISK=8
BRIDGE="vmbr0"
IPCFG="dhcp"
GW=""
VLAN=""
STORAGE=""
TSTORE=""
PORT=8080
YES="false"
UPDATE_CTID=""

if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; N=$'\033[0m'; else B=""; G=""; R=""; Y=""; N=""; fi
step() { printf '\n%s==>%s %s\n' "$B" "$N" "$*"; }
ok()   { printf '  %s+%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '\n%sERROR:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

usage() {
  cat <<EOF
Create an Oculyx server in a new Proxmox LXC container.

Usage: bash oculyx-lxc.sh [options]

  --ctid <id>           container ID (default: next free ID)
  --hostname <name>     container hostname (default: $CT_HOSTNAME)
  --cores <n>           CPU cores (default: $CORES)
  --memory <MB>         RAM (default: $RAM)
  --disk <GB>           root disk size (default: $DISK)
  --storage <name>      storage for the container disk (default: local-lvm, else first available)
  --template-storage <name>  storage that holds templates (default: first with vztmpl, usually "local")
  --bridge <vmbrN>      network bridge (default: $BRIDGE)
  --ip <cidr|dhcp>      IPv4 address, e.g. 192.168.1.50/24 (default: dhcp)
  --gw <ip>             gateway (needed with a static --ip)
  --vlan <tag>          VLAN tag
  --port <n>            Oculyx HTTP port (default: $PORT)
  --version <v>         Oculyx release (default: latest)
  --update <ctid>       upgrade Oculyx inside an existing container and exit
  -y, --yes             do not ask for confirmation
  -h, --help            this help
EOF
}

need() { [ "$#" -ge 2 ] && [ -n "$2" ] || die "Option $1 needs a value"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --ctid) need "$@"; CTID="$2"; shift 2 ;;
    --hostname) need "$@"; CT_HOSTNAME="$2"; shift 2 ;;
    --cores) need "$@"; CORES="$2"; shift 2 ;;
    --memory) need "$@"; RAM="$2"; shift 2 ;;
    --disk) need "$@"; DISK="$2"; shift 2 ;;
    --storage) need "$@"; STORAGE="$2"; shift 2 ;;
    --template-storage) need "$@"; TSTORE="$2"; shift 2 ;;
    --bridge) need "$@"; BRIDGE="$2"; shift 2 ;;
    --ip) need "$@"; IPCFG="$2"; shift 2 ;;
    --gw) need "$@"; GW="$2"; shift 2 ;;
    --vlan) need "$@"; VLAN="$2"; shift 2 ;;
    --port) need "$@"; PORT="$2"; shift 2 ;;
    --version) need "$@"; VERSION="$2"; shift 2 ;;
    --update) need "$@"; UPDATE_CTID="$2"; shift 2 ;;
    -y|--yes) YES="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1 (try --help)" ;;
  esac
done

command -v pct >/dev/null 2>&1 && command -v pveam >/dev/null 2>&1 && command -v pvesm >/dev/null 2>&1 \
  || die "This must run on a Proxmox VE host (pct/pveam/pvesm not found)."
[ "$(id -u)" -eq 0 ] || die "Run as root on the Proxmox host."

if [ -n "$UPDATE_CTID" ]; then
  step "Updating Oculyx in container $UPDATE_CTID"
  pct status "$UPDATE_CTID" >/dev/null 2>&1 || die "Container $UPDATE_CTID does not exist."
  pct exec "$UPDATE_CTID" -- oculyx-update
  exit 0
fi

# ------------------------------------------------------------------ choose defaults
if [ -z "$CTID" ]; then CTID="$(pvesh get /cluster/nextid 2>/dev/null)" || die "Could not get a free container ID."; fi
pct status "$CTID" >/dev/null 2>&1 && die "Container ID $CTID already exists. Pick another with --ctid."

if [ -z "$STORAGE" ]; then
  mapfile -t roots < <(pvesm status --content rootdir 2>/dev/null | awk 'NR>1 && $3=="active" {print $1}')
  [ "${#roots[@]}" -gt 0 ] || die "No storage that can hold container disks was found."
  STORAGE="${roots[0]}"
  for s in "${roots[@]}"; do [ "$s" = "local-lvm" ] && STORAGE="local-lvm"; done
fi
if [ -z "$TSTORE" ]; then
  TSTORE="$(pvesm status --content vztmpl 2>/dev/null | awk 'NR>1 && $3=="active" {print $1; exit}')"
  [ -n "$TSTORE" ] || die "No storage that can hold templates was found."
fi
NET="name=eth0,bridge=$BRIDGE,firewall=0,ip=$IPCFG"
[ -n "$GW" ] && NET="$NET,gw=$GW"
[ -n "$VLAN" ] && NET="$NET,tag=$VLAN"
[ "$IPCFG" != "dhcp" ] && [ -z "$GW" ] && warn "Static IP without --gw: the container will have no route out and cannot download Oculyx."

printf '%sOculyx LXC installer%s\n' "$B" "$N"
cat <<EOF

  Container   : $CTID ($CT_HOSTNAME), unprivileged Debian 12
  Resources   : $CORES core(s), ${RAM} MB RAM, ${DISK} GB disk on '$STORAGE'
  Network     : bridge $BRIDGE, ip=$IPCFG${GW:+, gw=$GW}${VLAN:+, vlan=$VLAN}
  Oculyx      : $VERSION from github.com/$REPO, port $PORT

EOF
if [ "$YES" != "true" ] && [ -t 0 ]; then
  read -r -p "Create it now? [Y/n] " reply
  case "${reply:-y}" in y|Y|yes|YES) ;; *) echo "Cancelled."; exit 0 ;; esac
fi

# ------------------------------------------------------------------ template
step "Preparing the Debian template"
pveam update >/dev/null 2>&1 || warn "Could not refresh the template list (offline?); using what is available."
TEMPLATE="$(pveam available --section system 2>/dev/null | awk '$2 ~ /^debian-12-standard/ {print $2}' | sort -V | tail -1)"
[ -n "$TEMPLATE" ] || TEMPLATE="$(pveam available --section system 2>/dev/null | awk '$2 ~ /^debian-13-standard/ {print $2}' | sort -V | tail -1)"
[ -n "$TEMPLATE" ] || die "No Debian template found in 'pveam available'."
if pveam list "$TSTORE" 2>/dev/null | grep -q "$TEMPLATE"; then ok "$TEMPLATE already downloaded"; else pveam download "$TSTORE" "$TEMPLATE" >/dev/null && ok "Downloaded $TEMPLATE"; fi

# ------------------------------------------------------------------ container
step "Creating container $CTID"
pct create "$CTID" "$TSTORE:vztmpl/$TEMPLATE" \
  --hostname "$CT_HOSTNAME" --cores "$CORES" --memory "$RAM" --swap "$SWAP" \
  --rootfs "$STORAGE:$DISK" --net0 "$NET" \
  --unprivileged 1 --features nesting=1 --onboot 1 --ostype debian --tags oculyx \
  --description "Oculyx monitoring server (https://github.com/$REPO). Update with: oculyx-lxc.sh --update $CTID" >/dev/null
ok "Container created"
pct start "$CTID"

step "Waiting for the network"
up="no"
for _ in $(seq 1 60); do
  if pct exec "$CTID" -- getent hosts github.com >/dev/null 2>&1; then up="yes"; break; fi
  sleep 2
done
[ "$up" = "yes" ] || die "The container has no internet access. Check the bridge/VLAN/gateway, then run: pct destroy $CTID && retry."
ok "Online"

step "Installing Oculyx inside the container"
pct exec "$CTID" -- bash -c "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates xz-utils >/dev/null"
pct exec "$CTID" -- bash -c "curl -fsSL https://raw.githubusercontent.com/$REPO/main/deploy/install-server.sh | OCULYX_REPO='$REPO' OCULYX_VERSION='$VERSION' OCULYX_PORT='$PORT' bash" \
  || die "The installer failed. Inspect with: pct enter $CTID   (remove with: pct stop $CTID && pct destroy $CTID)"

ip="$(pct exec "$CTID" -- hostname -I 2>/dev/null | awk '{print $1}')"
printf '\n%sDone.%s Oculyx is running in container %s:  %shttp://%s:%s%s\n' "$G$B" "$N" "$CTID" "$B" "${ip:-<container-ip>}" "$PORT" "$N"
cat <<EOF

  Next steps
    - Sign in with the admin password printed above, then change it (Settings > My account).
    - Add servers: Add server button in the web UI; Proxmox hosts and LXCs can use the --native mode.
    - HTTPS: put a reverse proxy in front and set OCULYX_TRUST_PROXY=1 in /etc/oculyx/oculyx.env.
    - Update later:  bash oculyx-lxc.sh --update $CTID     (or inside the container: oculyx-update)
    - Back up:       vzdump $CTID   (the whole database lives in /var/lib/oculyx)
EOF
