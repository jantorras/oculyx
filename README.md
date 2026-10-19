<h1 align="center">Oculyx</h1>

<p align="center">
  Self-hosted server monitoring, security checks and Docker management for your Linux fleet.<br>
  One lightweight server, many agents that connect <b>outbound</b>. Runs happily in a Proxmox LXC.
</p>

<p align="center"><img src="docs/screenshots/overview.png" alt="Oculyx overview dashboard" width="900"></p>

## What you get

- **Monitoring** — CPU, memory, disk, network and load per host, with history up to 7 days, threshold and offline alerts, webhook / Telegram notifications.
- **Docker** — container inventory with live CPU/memory, logs, and start / stop / restart (opt-in per host).
- **Security** — SSH and account hardening checks, exposed risky ports and port-change events, file integrity monitoring, SSH brute-force detection, sudo / login events, pending security updates, Docker posture (privileged, `docker.sock`, host network, root user, unpinned tags) and a security score per host.
- **Teams** — admin / operator / viewer roles, audit log, login rate limiting. UI in Catalan, Spanish and English, dark and light.
- **Easy to add servers** — one command per host, with a live "waiting for connection" wizard in the UI.

<p align="center">
  <img src="docs/screenshots/host.png" alt="Host detail" width="440">
  <img src="docs/screenshots/security.png" alt="Security findings" width="440">
  <img src="docs/screenshots/alerts.png" alt="Alerts" width="440">
  <img src="docs/screenshots/add-server.png" alt="Add server wizard" width="440">
</p>

## Install the server

Pick one. All three give you the same app; your data lives in one place (`/var/lib/oculyx`, or a Docker volume).

### A) Proxmox LXC (recommended for homelabs)

Run this in the **Proxmox host shell**. It creates an unprivileged Debian 12 container, installs Oculyx as a systemd service and prints the URL and first admin password.

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/jantorras/oculyx/main/deploy/proxmox/oculyx-lxc.sh)"
```

Defaults: 2 cores, 1 GB RAM, 8 GB disk, DHCP on `vmbr0`. Everything is overridable, e.g. a static address:

```bash
bash oculyx-lxc.sh --ip 192.168.1.50/24 --gw 192.168.1.1 --ctid 120 --storage local-zfs --yes
```

Update later with `bash oculyx-lxc.sh --update <CTID>` (or `oculyx-update` inside the container). Back up with `vzdump`.

### B) Any Debian / Ubuntu machine or VM (no Docker)

```bash
curl -fsSL https://raw.githubusercontent.com/jantorras/oculyx/main/deploy/install-server.sh | sudo bash
```

Installs Node.js 24 (official build, checksum verified), a dedicated `oculyx` user and a hardened systemd service. Re-run it, or run `oculyx-update`, to upgrade; the database is backed up first (`/var/lib/oculyx/backups`). Settings live in `/etc/oculyx/oculyx.env`. `--uninstall [--purge]` removes it.

### C) Docker Compose

```bash
git clone https://github.com/jantorras/oculyx && cd oculyx
docker compose up -d --build
docker compose logs oculyx | grep password     # first admin password, printed once
```

Set `OCULYX_DOMAIN` for automatic HTTPS through the bundled Caddy.

## Add servers to monitor

In the web UI click **Add server**, name it, and paste the command on the host:

```bash
curl -fsSL https://YOUR-OCULYX/install.sh | $(command -v sudo) bash -s -- --token ocx_... --name web-02
```

`$(command -v sudo)` makes the same line work as root (a Proxmox shell has no `sudo`) and as a sudo user on Ubuntu/Debian.

| Mode | Flag | Use it for |
|---|---|---|
| Docker container | *(default)*, `--install-docker` to install Docker | hosts that already run Docker |
| System service | `--native` | Proxmox hosts, LXC containers, anything without Docker |

The installer checks requirements, downloads the agent from **your** server, starts it and confirms the connection. Re-running upgrades it; `--uninstall [--purge]` removes it; `--allow-actions` enables start/stop/restart of containers from the UI. Tokens are single-use and expire after 24 hours. Prefer to read it first? `curl -fsSL https://YOUR-OCULYX/install.sh | less`.

Set the address agents should use under *Settings → Add hosts → Edit* when it differs from the one in your browser (reverse proxy, different DNS name).

## HTTPS

Oculyx speaks plain HTTP; put TLS in front of it and set `OCULYX_TRUST_PROXY=1` in `/etc/oculyx/oculyx.env`. A minimal Caddy example:

```
oculyx.example.com {
    reverse_proxy 192.168.1.50:8080
}
```

Agents use WebSockets over the same address, so make sure your proxy allows them (Caddy, nginx-proxy-manager and Traefik do by default).

## Try it without installing anything

Needs Node.js 24+:

```bash
git clone https://github.com/jantorras/oculyx && cd oculyx
npm install && npm run build:web
npm run demo        # http://localhost:8080   admin / oculyx-demo-1234
```

The demo runs the real server with simulated hosts that speak the real agent protocol, plus a day of history.

## How it works

```
 [agent]  ──outbound WebSocket──▶  [server]  ◀──  web UI
  metrics, docker, security          API · SQLite · alert engine
```

- `server/` Fastify + SQLite (Node's built-in `node:sqlite`), no native dependencies.
- `agent/` collectors read `/proc`, the Docker socket and a few security-relevant files; it only ever dials out.
- `web/` React + Vite, no UI framework.
- Node 24 runs the TypeScript directly, so there is no build step for the server or agent.

## Security notes

- Agents are **read-only** unless started with `--allow-actions`. Remember that access to `docker.sock` is root-equivalent on that host.
- Run the server behind HTTPS. Agent credentials are per-agent secrets, stored hashed on the server; enrollment tokens are single-use and short-lived.
- The agent installer and bundle are served unauthenticated on purpose (a fresh machine fetches them with `curl`); they contain no secrets.
- Found a vulnerability? Please open a private security advisory on GitHub instead of a public issue.

## Status and roadmap

Early (v0.x). Not done yet: 2FA, CVE scanning for packages and images, CIS benchmark audit, active response (blocking IPs), container terminal, PostgreSQL backend for very large fleets, tests beyond the end-to-end install check in CI.

## License

[MIT](LICENSE)
