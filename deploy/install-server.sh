#!/usr/bin/env bash
# Oculyx server installer for Debian/Ubuntu (bare metal, VM or LXC). No Docker needed.
#
#   curl -fsSL https://raw.githubusercontent.com/jantorras/oculyx/main/deploy/install-server.sh | sudo bash
#
# Run it again (or `oculyx-update`) to upgrade; your data is backed up first and kept.
set -euo pipefail

REPO="${OCULYX_REPO:-jantorras/oculyx}"
VERSION="${OCULYX_VERSION:-latest}"      # latest | v0.1.0 | main (build from source)
TARBALL="${OCULYX_TARBALL:-}"            # local path or URL of an oculyx.tar.gz (used by CI / offline installs)
PORT="${OCULYX_PORT:-8080}"
PREFIX="/opt/oculyx"
DATA="/var/lib/oculyx"
ETC="/etc/oculyx"
SVC_USER="oculyx"
UNIT="oculyx"
NODE_DIR="/opt/node"
MODE="install"
PURGE="false"

if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; D=$'\033[2m'; N=$'\033[0m'; else B=""; G=""; R=""; Y=""; D=""; N=""; fi
step() { printf '\n%s==>%s %s\n' "$B" "$N" "$*"; }
ok()   { printf '  %s+%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!%s %s\n' "$Y" "$N" "$*"; }
fail() { printf '\n%sERROR:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

usage() {
  cat <<EOF
Oculyx server installer

Usage: sudo bash install-server.sh [options]

  --version <v>     release to install: latest (default), a tag such as v0.1.0, or main (build from source)
  --port <n>        HTTP port (default 8080)
  --update          upgrade an existing install (same as running again)
  --uninstall       stop and remove the service (keeps your data unless --purge)
  --purge           with --uninstall: also delete the database and settings
  -h, --help        show this help

Env: OCULYX_REPO (default $REPO), OCULYX_TARBALL (install from a local file/URL)
EOF
}

need() { [ "$#" -ge 2 ] && [ -n "$2" ] || fail "Option $1 needs a value"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --version) need "$@"; VERSION="$2"; shift 2 ;;
    --port) need "$@"; PORT="$2"; shift 2 ;;
    --update) MODE="install"; shift ;;
    --uninstall) MODE="uninstall"; shift ;;
    --purge) PURGE="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Unknown option: $1 (try --help)" ;;
  esac
done

[ "$(uname -s)" = "Linux" ] || fail "Linux only."
[ "$(id -u)" -eq 0 ] || fail "Please run as root (sudo)."
[ -d /run/systemd/system ] || fail "systemd is required."
case "$PORT" in ''|*[!0-9]*) fail "Invalid port: $PORT" ;; esac

if [ "$MODE" = "uninstall" ]; then
  step "Removing Oculyx server"
  systemctl disable --now "$UNIT" >/dev/null 2>&1 || true
  rm -rf "/etc/systemd/system/$UNIT.service" "/etc/systemd/system/$UNIT.service.d" "$PREFIX" "$PREFIX.old" /usr/local/bin/oculyx-update
  systemctl daemon-reload || true
  if [ "$PURGE" = "true" ]; then rm -rf "$DATA" "$ETC"; ok "Data and settings deleted"; else ok "Data kept in $DATA (add --purge to delete it)"; fi
  exit 0
fi

printf '%sOculyx server installer%s  %s%s (%s)%s\n' "$B" "$N" "$D" "$REPO" "$VERSION" "$N"

# ------------------------------------------------------------------ prerequisites
step "Checking requirements"
command -v apt-get >/dev/null 2>&1 || fail "This installer supports Debian/Ubuntu (apt). Use the Docker install on other distributions."
export DEBIAN_FRONTEND=noninteractive
need_pkgs=""
for c in curl tar xz ca-certificates; do
  case "$c" in
    xz) command -v xz >/dev/null 2>&1 || need_pkgs="$need_pkgs xz-utils" ;;
    ca-certificates) [ -d /etc/ssl/certs ] || need_pkgs="$need_pkgs ca-certificates" ;;
    *) command -v "$c" >/dev/null 2>&1 || need_pkgs="$need_pkgs $c" ;;
  esac
done
if [ -n "$need_pkgs" ]; then
  installed="no"
  for _ in $(seq 1 60); do
    # shellcheck disable=SC2086
    if apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq $need_pkgs >/dev/null 2>&1; then installed="yes"; break; fi
    sleep 5   # another apt process (e.g. first boot) holds the lock
  done
  [ "$installed" = "yes" ] || fail "Could not install:$need_pkgs (apt is busy or offline)."
fi
ok "curl, tar, xz"

# Node.js >= 24: official tarball, checksum verified
if command -v node >/dev/null 2>&1 && [ "$(node -p 'process.versions.node.split(".")[0]')" -ge 24 ]; then
  NODE_BIN="$(command -v node)"; NPM_BIN="$(command -v npm)"; ok "Node.js $(node -v)"
else
  case "$(uname -m)" in x86_64) arch="x64" ;; aarch64|arm64) arch="arm64" ;; *) fail "Unsupported CPU architecture: $(uname -m)" ;; esac
  step "Installing Node.js 24 (official build)"
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
fi
PATH="$(dirname "$NODE_BIN"):$PATH"; export PATH

# ------------------------------------------------------------------ fetch the application
step "Downloading Oculyx"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fetched="no"
if [ -n "$TARBALL" ]; then
  case "$TARBALL" in http*) curl -fsSL "$TARBALL" -o "$work/oculyx.tar.gz" ;; *) cp "$TARBALL" "$work/oculyx.tar.gz" ;; esac
  fetched="yes"
elif [ "$VERSION" != "main" ]; then
  if [ "$VERSION" = "latest" ]; then url="https://github.com/$REPO/releases/latest/download"; else url="https://github.com/$REPO/releases/download/$VERSION"; fi
  if curl -fsSL --max-time 120 "$url/oculyx.tar.gz" -o "$work/oculyx.tar.gz" 2>/dev/null; then
    if curl -fsSL --max-time 20 "$url/oculyx.tar.gz.sha256" -o "$work/oculyx.tar.gz.sha256" 2>/dev/null; then
      ( cd "$work" && sha256sum -c oculyx.tar.gz.sha256 >/dev/null ) || fail "Release checksum mismatch; aborting."
      ok "Release checksum verified"
    fi
    fetched="yes"
  else
    warn "No published release found for '$VERSION'; building from source instead."
  fi
fi

mkdir -p "$work/pkg"
if [ "$fetched" = "yes" ]; then
  tar -xzf "$work/oculyx.tar.gz" -C "$work/pkg"
else
  ref="main"; [ "$VERSION" != "latest" ] && [ "$VERSION" != "main" ] && ref="$VERSION"
  step "Building from source ($ref)"
  mkdir -p "$work/src"
  curl -fsSL "https://github.com/$REPO/archive/$ref.tar.gz" | tar -xz -C "$work/src" --strip-components=1
  ( cd "$work/src" && "$NPM_BIN" ci --no-audit --no-fund --silent && "$NPM_BIN" run build:web --silent ) || fail "Source build failed."
  mkdir -p "$work/pkg/web"
  cp -r "$work/src/server" "$work/src/agent" "$work/src/package.json" "$work/src/package-lock.json" "$work/pkg/"
  cp -r "$work/src/web/dist" "$work/pkg/web/dist"
  cp "$work/src/web/package.json" "$work/pkg/web/package.json"
  rm -rf "$work/pkg/server/node_modules" "$work/pkg/agent/node_modules"
fi
[ -f "$work/pkg/server/src/main.ts" ] || fail "The downloaded package is incomplete."
[ -d "$work/pkg/web/dist" ] || fail "The downloaded package has no web UI."
ok "Package ready"

step "Installing dependencies"
( cd "$work/pkg" && NODE_ENV=production "$NPM_BIN" ci --omit=dev -w server -w agent --no-audit --no-fund --silent ) || fail "npm ci failed."
ok "Dependencies installed"

# ------------------------------------------------------------------ service account + layout
id "$SVC_USER" >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin "$SVC_USER"
mkdir -p "$DATA/backups" "$ETC"
chown -R "$SVC_USER:$SVC_USER" "$DATA"
chmod 750 "$DATA"

upgrading="no"
if [ -d "$PREFIX" ]; then
  upgrading="yes"
  step "Upgrading (data is backed up first)"
  systemctl stop "$UNIT" >/dev/null 2>&1 || true
  ts="$(date +%Y%m%d-%H%M%S)"
  for f in "$DATA"/oculyx.db "$DATA"/oculyx.db-wal "$DATA"/oculyx.db-shm; do [ -f "$f" ] && cp -p "$f" "$DATA/backups/$(basename "$f")-$ts"; done
  ls -1t "$DATA"/backups 2>/dev/null | tail -n +15 | while read -r old; do rm -f "$DATA/backups/$old"; done
  rm -rf "$PREFIX.old"
  mv "$PREFIX" "$PREFIX.old"
  ok "Backup saved in $DATA/backups"
fi
mv "$work/pkg" "$PREFIX"
chown -R root:root "$PREFIX"

# ------------------------------------------------------------------ configuration (kept across upgrades)
if [ ! -f "$ETC/oculyx.env" ]; then
  cat > "$ETC/oculyx.env" <<EOF
# Oculyx server settings. Restart after editing:  systemctl restart oculyx
PORT=$PORT
HOST=0.0.0.0
# Set to 1 when Oculyx runs behind a reverse proxy that terminates TLS (Caddy, nginx, Traefik, ...)
OCULYX_TRUST_PROXY=0
# Metrics history to keep, in days
OCULYX_RETENTION_DAYS=14
# Optional: first admin password (otherwise a random one is generated and printed once)
# OCULYX_ADMIN_PASSWORD=
EOF
  chmod 640 "$ETC/oculyx.env"; chgrp "$SVC_USER" "$ETC/oculyx.env"
elif [ "$PORT" != "8080" ]; then
  sed -i "s/^PORT=.*/PORT=$PORT/" "$ETC/oculyx.env"
fi

cat > "/etc/systemd/system/$UNIT.service" <<EOF
[Unit]
Description=Oculyx monitoring server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
WorkingDirectory=$PREFIX
Environment=OCULYX_DATA=$DATA OCULYX_WEB=$PREFIX/web/dist OCULYX_AGENT_DIR=$PREFIX/agent NODE_ENV=production
EnvironmentFile=$ETC/oculyx.env
ExecStart=$NODE_BIN --disable-warning=ExperimentalWarning server/src/main.ts
Restart=on-failure
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

# sandboxing lives in a drop-in so it can be dropped if the host (e.g. an LXC without nesting) cannot do it
harden() {
  mkdir -p "/etc/systemd/system/$UNIT.service.d"
  cat > "/etc/systemd/system/$UNIT.service.d/hardening.conf" <<EOF
[Service]
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
EOF
}
harden

cat > /usr/local/bin/oculyx-update <<EOF
#!/usr/bin/env bash
# Upgrade Oculyx to the latest release (backs up the database first).
exec bash -c 'curl -fsSL https://raw.githubusercontent.com/$REPO/main/deploy/install-server.sh | bash -s -- --update "\$@"' _ "\$@"
EOF
chmod 755 /usr/local/bin/oculyx-update

# ------------------------------------------------------------------ start
step "Starting Oculyx"
systemctl daemon-reload
systemctl enable "$UNIT" >/dev/null 2>&1
start_ok() { systemctl restart "$UNIT" && for _ in $(seq 1 30); do curl -fsS --max-time 2 "http://127.0.0.1:$(grep -m1 '^PORT=' "$ETC/oculyx.env" | cut -d= -f2)/healthz" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
if ! start_ok; then
  if journalctl -u "$UNIT" --no-pager -n 30 2>/dev/null | grep -qiE 'NAMESPACE|226'; then
    warn "This host cannot apply systemd sandboxing (typical for an LXC without nesting); continuing without it."
    rm -rf "/etc/systemd/system/$UNIT.service.d"; systemctl daemon-reload
    start_ok || { journalctl -u "$UNIT" --no-pager -n 30; fail "Oculyx did not start."; }
  else
    journalctl -u "$UNIT" --no-pager -n 30
    fail "Oculyx did not start. See the log above."
  fi
fi
ok "Oculyx is running"

port="$(grep -m1 '^PORT=' "$ETC/oculyx.env" | cut -d= -f2)"
ip="$(hostname -I 2>/dev/null | awk '{print $1}')"; ip="${ip:-localhost}"
pw="$(journalctl -u "$UNIT" --no-pager -o cat 2>/dev/null | grep -o 'with password: .*' | tail -1 | sed 's/^with password: //')" || pw=""

printf '\n%sOculyx is ready:%s  http://%s:%s\n' "$G$B" "$N" "$ip" "$port"
if [ -n "$pw" ] && [ "$upgrading" = "no" ]; then
  printf '  Sign in as  %sadmin%s  with password  %s%s%s\n  (shown once - change it under Settings > My account)\n' "$B" "$N" "$B" "$pw" "$N"
fi
printf '  %sUpdate later with: oculyx-update     Logs: journalctl -u oculyx -f%s\n' "$D" "$N"
printf '  %sPutting it behind HTTPS? Set OCULYX_TRUST_PROXY=1 in %s/oculyx.env%s\n' "$D" "$ETC" "$N"
