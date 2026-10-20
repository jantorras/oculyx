#!/usr/bin/env bash
# Oculyx agent installer.
# Read it first if you like:  curl -fsSL __SERVER__/install.sh | less
# Install (as root):          curl -fsSL __SERVER__/install.sh | bash -s -- --token <TOKEN>
#         (with sudo):        curl -fsSL __SERVER__/install.sh | sudo bash -s -- --token <TOKEN>
set -euo pipefail

SERVER="__SERVER__"
TOKEN=""
NAME="$(hostname 2>/dev/null || echo host)"
ALLOW_ACTIONS="false"
INSTALL_DOCKER="false"
RUNTIME="docker"
MODE="install"
PURGE="false"
DIR="${OCULYX_DIR:-/opt/oculyx-agent}"
CONTAINER="oculyx-agent"
VOLUME="oculyx-agent"
IMAGE="oculyx-agent:local"
UNIT="oculyx-agent"
STATE_DIR="/var/lib/oculyx-agent"
NODE_DIR="/opt/node"

if [ -t 1 ]; then
  B=$'\033[1m'; G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; D=$'\033[2m'; N=$'\033[0m'
else
  B=""; G=""; R=""; Y=""; D=""; N=""
fi
step() { printf '\n%s==>%s %s\n' "$B" "$N" "$*"; }
ok()   { printf '  %s+%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
fail() { printf '\n%sERROR:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

usage() {
  cat <<EOF
Oculyx agent installer

Usage: sudo bash install.sh --token <TOKEN> [options]

  --token <TOKEN>     one-time enrollment token from the Oculyx web UI
  --name <NAME>       name shown in Oculyx (default: this host's name)
  --native            run as a systemd service (no Docker needed; ideal for Proxmox hosts and LXC)
  --allow-actions     let Oculyx start/stop/restart containers on this host (default: read-only)
  --install-docker    (Docker mode) install Docker automatically if it is missing
  --server <URL>      Oculyx server address (default: $SERVER)
  --uninstall         remove the agent (add --purge to also forget its credentials)
  -h, --help          show this help

Default mode runs the agent in a Docker container. Running the installer again
upgrades the agent in place and keeps its identity.
EOF
}

need() { [ "$#" -ge 2 ] && [ -n "$2" ] || fail "Option $1 needs a value"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --token) need "$@"; TOKEN="$2"; shift 2 ;;
    --name) need "$@"; NAME="$2"; shift 2 ;;
    --server) need "$@"; SERVER="${2%/}"; shift 2 ;;
    --native) RUNTIME="native"; shift ;;
    --allow-actions) ALLOW_ACTIONS="true"; shift ;;
    --install-docker) INSTALL_DOCKER="true"; shift ;;
    --uninstall) MODE="uninstall"; shift ;;
    --purge) PURGE="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Unknown option: $1 (try --help)" ;;
  esac
done

printf '%sOculyx agent installer%s  %s%s%s\n' "$B" "$N" "$D" "$SERVER" "$N"

[ "$(uname -s)" = "Linux" ] || fail "This installer supports Linux only."
[ "$(id -u)" -eq 0 ] || fail "Please run as root (no sudo on this host? log in as root). With sudo: curl -fsSL $SERVER/install.sh | sudo bash -s -- --token <TOKEN>"

# ---- uninstall (handles whichever runtime was used) ----
if [ "$MODE" = "uninstall" ]; then
  step "Removing the Oculyx agent"
  removed="no"
  if command -v systemctl >/dev/null 2>&1 && [ -f "/etc/systemd/system/$UNIT.service" ]; then
    systemctl disable --now "$UNIT" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$UNIT.service" "/etc/$UNIT.env"
    systemctl daemon-reload >/dev/null 2>&1 || true
    [ "$PURGE" = "true" ] && rm -rf "$STATE_DIR"
    ok "Service removed"; removed="yes"
  fi
  if command -v docker >/dev/null 2>&1; then
    docker rm -f "$CONTAINER" >/dev/null 2>&1 && { ok "Container removed"; removed="yes"; } || true
    docker rmi "$IMAGE" >/dev/null 2>&1 || true
    if [ "$PURGE" = "true" ]; then docker volume rm "$VOLUME" >/dev/null 2>&1 && ok "Credentials removed" || true; fi
  fi
  rm -rf "$DIR"
  [ "$removed" = "yes" ] || warn "No installed agent found"
  printf '\nDone. You can also delete the host from the Oculyx web UI.\n'
  exit 0
fi

step "Checking requirements"
command -v curl >/dev/null 2>&1 || fail "curl is required (apt-get install -y curl)."
ok "curl"

ensure_xz() {
  command -v xz >/dev/null 2>&1 && return 0
  if command -v apt-get >/dev/null 2>&1; then apt-get update -qq >/dev/null && apt-get install -y -qq xz-utils >/dev/null
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q xz >/dev/null
  elif command -v yum >/dev/null 2>&1; then yum install -y -q xz >/dev/null
  else fail "xz is required to unpack Node.js. Please install it and retry."; fi
}

# Node.js >= 24 (the agent runs TypeScript directly). Uses the official tarball, checksum verified.
ensure_node() {
  node_major() { "$1" -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0; }
  if [ -x "$NODE_DIR/bin/node" ] && [ "$(node_major "$NODE_DIR/bin/node")" -ge 24 ]; then
    NODE_BIN="$NODE_DIR/bin/node"; NPM_BIN="$NODE_DIR/bin/npm"; ok "Node.js $("$NODE_BIN" -v) (already installed)"; return 0
  fi
  if command -v node >/dev/null 2>&1 && [ "$(node_major "$(command -v node)")" -ge 24 ]; then
    NODE_BIN="$(command -v node)"; NPM_BIN="$(command -v npm)"; ok "Node.js $(node -v)"; return 0
  fi
  if ldd --version 2>&1 | grep -qi musl; then fail "Alpine/musl is not supported in native mode. Use Docker mode or a Debian/Ubuntu/RHEL-family host."; fi
  case "$(uname -m)" in x86_64) arch="x64" ;; aarch64|arm64) arch="arm64" ;; *) fail "Unsupported CPU architecture: $(uname -m)" ;; esac
  step "Installing Node.js 24 (official build)"
  ensure_xz
  base="https://nodejs.org/dist/latest-v24.x"
  line="$(curl -fsSL --max-time 30 "$base/SHASUMS256.txt" | grep "linux-$arch.tar.xz" | head -1)" || fail "Could not reach nodejs.org"
  sha="${line%% *}"; file="${line##* }"
  tmp="$(mktemp -d)"
  curl -fsSL --max-time 300 "$base/$file" -o "$tmp/$file" || fail "Node.js download failed"
  [ "$(sha256sum "$tmp/$file" | cut -d' ' -f1)" = "$sha" ] || fail "Node.js checksum mismatch; aborting."
  rm -rf "$NODE_DIR"; mkdir -p "$NODE_DIR"
  tar -xJf "$tmp/$file" -C "$NODE_DIR" --strip-components=1
  rm -rf "$tmp"
  NODE_BIN="$NODE_DIR/bin/node"; NPM_BIN="$NODE_DIR/bin/npm"
  ok "Node.js $("$NODE_BIN" -v) in $NODE_DIR"
}

if [ "$RUNTIME" = "docker" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    if [ "$INSTALL_DOCKER" = "true" ]; then
      step "Installing Docker (get.docker.com)"
      curl -fsSL https://get.docker.com | sh
      systemctl enable --now docker >/dev/null 2>&1 || true
    else
      fail "Docker is not installed. Re-run with --install-docker to install it, or use --native to run without Docker."
    fi
  fi
  docker info >/dev/null 2>&1 || fail "Docker is installed but not running. Try: systemctl start docker"
  ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '')"
else
  [ -d /run/systemd/system ] || fail "Native mode needs systemd. Use Docker mode on this host."
  ok "systemd"
  ensure_node
fi

curl -fsS --max-time 10 "$SERVER/healthz" >/dev/null 2>&1 \
  || fail "Cannot reach the Oculyx server at $SERVER from this machine. Check the address, DNS and firewall."
ok "Oculyx server reachable"

have_identity="no"
if [ "$RUNTIME" = "docker" ]; then docker volume inspect "$VOLUME" >/dev/null 2>&1 && have_identity="yes"
else [ -f "$STATE_DIR/credentials.json" ] && have_identity="yes"; fi
if [ -z "$TOKEN" ] && [ "$have_identity" = "no" ]; then
  fail "--token is required for a first install. Create one in Oculyx: Settings > Add hosts."
fi

step "Downloading the agent"
rm -rf "$DIR.new"
mkdir -p "$DIR.new"
curl -fsS --max-time 20 "$SERVER/agent/manifest.txt" | while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in *..*|/*) fail "Refusing unsafe path from server: $f" ;; esac
  mkdir -p "$DIR.new/$(dirname "$f")"
  curl -fsS --max-time 30 "$SERVER/agent/files/$f" -o "$DIR.new/$f"
done
[ -f "$DIR.new/Dockerfile" ] || fail "The server did not provide the agent files."
rm -rf "$DIR"
mv "$DIR.new" "$DIR"
ok "Agent files in $DIR"

# ------------------------------------------------------------------ docker runtime
if [ "$RUNTIME" = "docker" ]; then
  step "Building the agent image (first run takes ~30s)"
  docker build -q -t "$IMAGE" "$DIR" >/dev/null || fail "Docker build failed. Run 'docker build $DIR' to see why."
  ok "Image $IMAGE"

  step "Starting the agent"
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  args=(run -d --name "$CONTAINER" --restart unless-stopped --network host --pid host
    -v /:/host:ro -v /var/run/docker.sock:/var/run/docker.sock -v "$VOLUME":/var/lib/oculyx
    -e "OCULYX_SERVER=$SERVER" -e "OCULYX_NAME=$NAME" -e HOST_ROOT=/host -e "OCULYX_ALLOW_ACTIONS=$ALLOW_ACTIONS")
  if [ -n "$TOKEN" ]; then args+=(-e "OCULYX_ENROLL_TOKEN=$TOKEN"); fi
  docker "${args[@]}" "$IMAGE" >/dev/null || fail "Could not start the agent container."
  get_logs() { docker logs "$CONTAINER" 2>&1 || true; }
else
# ------------------------------------------------------------------ native runtime
  step "Installing agent dependencies"
  ( cd "$DIR" && NODE_ENV=production PATH="$(dirname "$NODE_BIN"):$PATH" "$NPM_BIN" install --omit=dev --no-audit --no-fund --silent ) \
    || fail "npm install failed in $DIR"
  ok "Dependencies installed"

  step "Starting the agent (systemd service $UNIT)"
  mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
  {
    echo "OCULYX_SERVER=$SERVER"
    echo "OCULYX_NAME=$NAME"
    echo "OCULYX_ALLOW_ACTIONS=$ALLOW_ACTIONS"
    echo "OCULYX_STATE_DIR=$STATE_DIR"
    if [ -n "$TOKEN" ]; then echo "OCULYX_ENROLL_TOKEN=$TOKEN"; fi
  } > "/etc/$UNIT.env"
  chmod 600 "/etc/$UNIT.env"
  cat > "/etc/systemd/system/$UNIT.service" <<EOF
[Unit]
Description=Oculyx monitoring agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/$UNIT.env
WorkingDirectory=$DIR
ExecStart=$NODE_BIN --disable-warning=ExperimentalWarning $DIR/src/main.ts
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
$([ "$ALLOW_ACTIONS" = "true" ] || echo 'ProtectSystem=full')

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "$UNIT" >/dev/null 2>&1
  systemctl restart "$UNIT"
  get_logs() { journalctl -u "$UNIT" --no-pager -n 200 -o cat 2>&1 || true; }
fi

connected="no"
for _ in $(seq 1 25); do
  logs="$(get_logs)"
  if printf '%s' "$logs" | grep -q 'enrollment rejected'; then
    fail "The server rejected the token. It may have expired or already been used. Create a new one in Settings > Add hosts."
  fi
  if printf '%s' "$logs" | grep -q ' connected$'; then connected="yes"; break; fi
  sleep 1
done

# the one-time token is useless once the agent has its own credentials; do not leave it on disk
if [ "$connected" = "yes" ] && [ "$RUNTIME" = "native" ]; then sed -i '/^OCULYX_ENROLL_TOKEN=/d' "/etc/$UNIT.env"; fi

if [ "$connected" = "yes" ]; then
  ok "Connected to Oculyx"
  printf '\n%sAll set.%s "%s" should now appear in %s\n' "$G$B" "$N" "$NAME" "$SERVER"
else
  warn "The agent is running but has not confirmed the connection yet."
  if [ "$RUNTIME" = "docker" ]; then printf '  Check it with: docker logs %s\n' "$CONTAINER"; else printf '  Check it with: journalctl -u %s -e\n' "$UNIT"; fi
fi
if [ "$ALLOW_ACTIONS" = "true" ]; then
  printf '  %sContainer start/stop/restart from the UI is enabled for this host.%s\n' "$D" "$N"
else
  printf '  %sRead-only mode. Re-run with --allow-actions to manage containers from the UI.%s\n' "$D" "$N"
fi
