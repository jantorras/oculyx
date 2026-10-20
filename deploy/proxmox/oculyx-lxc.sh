#!/usr/bin/env bash
# Create an Oculyx server in a new Proxmox VE LXC container (Debian 12, unprivileged).
# Run this on the Proxmox host shell as root:
#
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/jantorras/oculyx/main/deploy/proxmox/oculyx-lxc.sh)"
#
# Run without options it opens an interactive menu (default or advanced settings, update an existing
# container). Pass flags (see --help) or -y for unattended use.
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
CUSTOM="false"   # a setting flag was given: skip the interactive menu

if [ -t 1 ]; then B=$'\033[1m'; D=$'\033[2m'; G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; C=$'\033[36m'; N=$'\033[0m'; else B=""; D=""; G=""; R=""; Y=""; C=""; N=""; fi
ok()   { printf '  %s✔%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '\n  %s✖ ERROR:%s %b\n' "$R" "$N" "$*" >&2; exit 1; }
cancel() { printf '\n  Cancelled.\n'; exit 0; }

banner() {
  printf '%s' "$C"
  cat <<'EOF'

   ___   ____ _   _ _  __   ___  __
  / _ \ / ___| | | | | \ \ / / \/ /
 | | | | |   | | | | |  \ V / \  /
 | |_| | |___| |_| | |___| |  /  \
  \___/ \____|\___/|_____|_| /_/\_\

EOF
  printf '%s  Self-hosted monitoring, security and Docker management%s\n' "$N$D" "$N"
  printf '  github.com/%s\n\n' "$REPO"
}

usage() {
  cat <<EOF
Create an Oculyx server in a new Proxmox LXC container.

Usage: bash oculyx-lxc.sh [options]      (no options: interactive menu)

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
  -y, --yes             do not ask anything, use the defaults / the flags given
  -h, --help            this help
EOF
}

need() { [ "$#" -ge 2 ] && [ -n "$2" ] || die "Option $1 needs a value"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --ctid) need "$@"; CTID="$2"; CUSTOM="true"; shift 2 ;;
    --hostname) need "$@"; CT_HOSTNAME="$2"; CUSTOM="true"; shift 2 ;;
    --cores) need "$@"; CORES="$2"; CUSTOM="true"; shift 2 ;;
    --memory) need "$@"; RAM="$2"; CUSTOM="true"; shift 2 ;;
    --disk) need "$@"; DISK="$2"; CUSTOM="true"; shift 2 ;;
    --storage) need "$@"; STORAGE="$2"; CUSTOM="true"; shift 2 ;;
    --template-storage) need "$@"; TSTORE="$2"; CUSTOM="true"; shift 2 ;;
    --bridge) need "$@"; BRIDGE="$2"; CUSTOM="true"; shift 2 ;;
    --ip) need "$@"; IPCFG="$2"; CUSTOM="true"; shift 2 ;;
    --gw) need "$@"; GW="$2"; CUSTOM="true"; shift 2 ;;
    --vlan) need "$@"; VLAN="$2"; CUSTOM="true"; shift 2 ;;
    --port) need "$@"; PORT="$2"; CUSTOM="true"; shift 2 ;;
    --version) need "$@"; VERSION="$2"; CUSTOM="true"; shift 2 ;;
    --update) need "$@"; UPDATE_CTID="$2"; shift 2 ;;
    -y|--yes) YES="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1 (try --help)" ;;
  esac
done

command -v pct >/dev/null 2>&1 && command -v pveam >/dev/null 2>&1 && command -v pvesm >/dev/null 2>&1 \
  || die "This must run on a Proxmox VE host (pct/pveam/pvesm not found)."
[ "$(id -u)" -eq 0 ] || die "Run as root on the Proxmox host."

LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT

# run "message" command...   shows a spinner, keeps the output for errors
run() {
  local msg="$1" pid i=0 frames='|/-\'; shift
  "$@" >"$LOG" 2>&1 &
  pid=$!
  if [ -t 1 ]; then
    while kill -0 "$pid" 2>/dev/null; do printf '\r  %s%s%s %s' "$C" "${frames:i:1}" "$N" "$msg"; i=$(( (i + 1) % 4 )); sleep 0.15; done
  fi
  if wait "$pid"; then
    printf '\r\033[K'; ok "$msg"
  else
    printf '\r\033[K  %s✖%s %s\n' "$R" "$N" "$msg"; tail -n 15 "$LOG" | sed 's/^/      /'; return 1
  fi
}

# ------------------------------------------------------------------ interactive pieces
UI="false"
if [ "$YES" != "true" ] && [ "$CUSTOM" != "true" ] && [ -z "$UPDATE_CTID" ] && [ -t 0 ] && [ -t 1 ] && command -v whiptail >/dev/null 2>&1; then UI="true"; fi
wt_menu()  { whiptail --backtitle "Oculyx" --title "$1" --menu "$2" 18 72 8 "${@:3}" 3>&1 1>&2 2>&3; }
wt_input() { whiptail --backtitle "Oculyx" --title "$1" --inputbox "$2" 10 66 "$3" 3>&1 1>&2 2>&3; }
wt_yesno() { whiptail --backtitle "Oculyx" --title "$1" --yesno "$2" 12 66; }
wt_msg()   { whiptail --backtitle "Oculyx" --title "$1" --msgbox "$2" 10 66; }

# ask_num <var> <title> <prompt> <min> <max>
ask_num() {
  local var="$1" cur="${!1}" v
  while :; do
    v="$(wt_input "$2" "$3" "$cur")" || cancel
    if [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge "$4" ] && [ "$v" -le "$5" ]; then printf -v "$var" '%s' "$v"; return; fi
    wt_msg "$2" "Enter a whole number between $4 and $5."
  done
}

detect_defaults() {
  [ -n "$CTID" ] || { CTID="$(pvesh get /cluster/nextid 2>/dev/null)" || die "Could not get a free container ID."; }
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
}

# the Oculyx containers on this node (tagged by this script)
oculyx_containers() {
  local id
  for id in $(pct list 2>/dev/null | awk 'NR>1 {print $1}'); do
    pct config "$id" 2>/dev/null | grep -qE '^tags:.*oculyx' && printf '%s\n' "$id"
  done
}

pick_update() {
  local items=() id name st
  while read -r id; do
    [ -n "$id" ] || continue
    name="$(pct config "$id" | awk '/^hostname:/ {print $2}')"; st="$(pct status "$id" | awk '{print $2}')"
    items+=("$id" "$name ($st)")
  done < <(oculyx_containers)
  if [ "${#items[@]}" -eq 0 ]; then wt_msg "Update" "No Oculyx container found on this node.\n\nContainers created by this script are tagged 'oculyx'. Use --update <CTID> for others."; return 1; fi
  UPDATE_CTID="$(wt_menu "Update Oculyx" "Which container do you want to update?" "${items[@]}")" || cancel
}

advanced_settings() {
  ask_num CTID "Container ID" "Container ID:" 100 999999999
  CT_HOSTNAME="$(wt_input "Hostname" "Container hostname:" "$CT_HOSTNAME")" || cancel
  ask_num CORES "CPU" "CPU cores:" 1 64
  ask_num RAM "Memory" "RAM in MB (1024 is plenty for a small fleet):" 512 65536
  ask_num DISK "Disk" "Disk size in GB (metrics history lives here):" 4 4096
  local items=() name type avail
  while read -r name type avail; do items+=("$name" "$type, $((avail / 1024 / 1024)) GB free"); done \
    < <(pvesm status --content rootdir 2>/dev/null | awk 'NR>1 && $3=="active" {print $1, $2, $6}')
  STORAGE="$(wt_menu "Storage" "Where should the container disk live?" "${items[@]}")" || cancel
  BRIDGE="$(wt_input "Network" "Network bridge:" "$BRIDGE")" || cancel
  if wt_yesno "IP address" "Get the address automatically with DHCP?\n\nChoose No to set a static address."; then
    IPCFG="dhcp"; GW=""
  else
    IPCFG="$(wt_input "Static IP" "IPv4 address with prefix, e.g. 192.168.1.50/24:" "")" || cancel
    GW="$(wt_input "Gateway" "Gateway, e.g. 192.168.1.1:" "")" || cancel
  fi
  VLAN="$(wt_input "VLAN" "VLAN tag (leave empty for none):" "$VLAN")" || cancel
  ask_num PORT "Port" "Port for the Oculyx web interface:" 1 65535
}

ui_menu() {
  local choice
  banner
  choice="$(wt_menu "Oculyx LXC installer" "What do you want to do?" \
    1 "Install with default settings (recommended)" \
    2 "Install with advanced settings" \
    3 "Update an existing Oculyx container" \
    4 "Cancel")" || cancel
  case "$choice" in
    1) ;;
    2) advanced_settings ;;
    3) pick_update || ui_menu ;;
    *) cancel ;;
  esac
}

# ------------------------------------------------------------------ update an existing container
do_update() {
  pct status "$UPDATE_CTID" >/dev/null 2>&1 || die "Container $UPDATE_CTID does not exist."
  [ "$(pct status "$UPDATE_CTID" | awk '{print $2}')" = "running" ] || pct start "$UPDATE_CTID"
  printf '\n  Updating Oculyx in container %s%s%s (the database is backed up first)\n\n' "$B" "$UPDATE_CTID" "$N"
  # containers created before oculyx-update existed fall back to the installer itself
  pct exec "$UPDATE_CTID" -- env LC_ALL=C.UTF-8 bash -c "command -v oculyx-update >/dev/null && exec oculyx-update || curl -fsSL https://raw.githubusercontent.com/$REPO/main/deploy/install-server.sh | bash -s -- --update"
}

if [ -n "$UPDATE_CTID" ]; then banner; do_update; exit 0; fi

detect_defaults
if [ "$UI" = "true" ]; then
  ui_menu
  [ -z "$UPDATE_CTID" ] || { do_update; exit 0; }
else
  banner
fi

pct status "$CTID" >/dev/null 2>&1 && die "Container ID $CTID already exists. Pick another with --ctid."
NET="name=eth0,bridge=$BRIDGE,firewall=0,ip=$IPCFG"
[ -n "$GW" ] && NET="$NET,gw=$GW"
[ -n "$VLAN" ] && NET="$NET,tag=$VLAN"
[ "$IPCFG" != "dhcp" ] && [ -z "$GW" ] && warn "Static IP without a gateway: the container will have no route out and cannot download Oculyx."

SUMMARY="Container   $CTID ($CT_HOSTNAME), unprivileged Debian 12
Resources   $CORES core(s), ${RAM} MB RAM, ${DISK} GB disk on '$STORAGE'
Network     bridge $BRIDGE, ip=$IPCFG${GW:+, gw=$GW}${VLAN:+, vlan=$VLAN}
Oculyx      $VERSION from github.com/$REPO, port $PORT"

if [ "$UI" = "true" ]; then
  wt_yesno "Ready to create" "$SUMMARY\n\nCreate it now?" || cancel
  clear
  banner
else
  printf '%s\n\n' "$SUMMARY" | sed 's/^/  /'
  if [ "$YES" != "true" ] && [ -t 0 ]; then
    read -r -p "  Create it now? [Y/n] " reply
    case "${reply:-y}" in y|Y|yes|YES) ;; *) cancel ;; esac
  fi
fi

# ------------------------------------------------------------------ template
printf '\n  %sCreating the container%s\n' "$B" "$N"
pveam update >/dev/null 2>&1 || warn "Could not refresh the template list (offline?); using what is available."
TEMPLATE="$(pveam available --section system 2>/dev/null | awk '$2 ~ /^debian-12-standard/ {print $2}' | sort -V | tail -1)"
[ -n "$TEMPLATE" ] || TEMPLATE="$(pveam available --section system 2>/dev/null | awk '$2 ~ /^debian-13-standard/ {print $2}' | sort -V | tail -1)"
[ -n "$TEMPLATE" ] || die "No Debian template found in 'pveam available'."
if pveam list "$TSTORE" 2>/dev/null | grep -q "$TEMPLATE"; then ok "Template $TEMPLATE already downloaded"; else run "Downloading $TEMPLATE" pveam download "$TSTORE" "$TEMPLATE" || die "Template download failed."; fi

run "Creating container $CTID" pct create "$CTID" "$TSTORE:vztmpl/$TEMPLATE" \
  --hostname "$CT_HOSTNAME" --cores "$CORES" --memory "$RAM" --swap "$SWAP" \
  --rootfs "$STORAGE:$DISK" --net0 "$NET" \
  --unprivileged 1 --features nesting=1 --onboot 1 --ostype debian --tags oculyx \
  --description "Oculyx monitoring server (https://github.com/$REPO). Update: run oculyx-lxc.sh and pick Update, or oculyx-update inside the container." \
  || die "Could not create the container."
run "Starting container $CTID" pct start "$CTID" || die "Could not start the container."

wait_net() { local _; for _ in $(seq 1 60); do pct exec "$CTID" -- getent hosts github.com >/dev/null 2>&1 && return 0; sleep 2; done; return 1; }
run "Waiting for the network" wait_net \
  || die "The container has no internet access. Check the bridge/VLAN/gateway, then run: pct destroy $CTID --purge  and retry."

# A brand-new container runs apt by itself on first boot and holds its lock; wait for it instead of failing.
base_pkgs() {
  local _
  for _ in $(seq 1 60); do
    pct exec "$CTID" -- env LC_ALL=C.UTF-8 DEBIAN_FRONTEND=noninteractive bash -c 'apt-get update -qq && apt-get install -y -qq curl ca-certificates xz-utils' && return 0
    sleep 5
  done
  return 1
}
run "Installing base packages" base_pkgs || die "Could not install base packages in the container. Inspect with: pct enter $CTID"

printf '\n  %sInstalling Oculyx%s\n' "$B" "$N"
pct exec "$CTID" -- env LC_ALL=C.UTF-8 bash -c "curl -fsSL https://raw.githubusercontent.com/$REPO/main/deploy/install-server.sh | OCULYX_REPO='$REPO' OCULYX_VERSION='$VERSION' OCULYX_PORT='$PORT' bash" \
  || die "The installer failed. Inspect with: pct enter $CTID   (remove with: pct destroy $CTID --purge)"

ip="$(pct exec "$CTID" -- hostname -I 2>/dev/null | awk '{print $1}')"
printf '\n  %s✔ Done.%s Oculyx is running in container %s\n\n      %shttp://%s:%s%s\n\n' "$G$B" "$N" "$CTID" "$B" "${ip:-<container-ip>}" "$PORT" "$N"
cat <<EOF
  Next steps
    - Sign in with the admin password printed above, then change it (Settings > My account).
    - Add servers with the "Add server" button; Proxmox hosts and LXCs use the --native mode.
    - Use your own domain with HTTPS, no ports to open: Settings > Domain (Cloudflare Tunnel).
    - Update later:  run this script again and pick "Update"   (or inside the container: oculyx-update)
    - Back up:       vzdump $CTID   (the whole database lives in /var/lib/oculyx)
EOF
