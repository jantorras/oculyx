/**
 * Demo simulator: several fake hosts speaking the real agent protocol, so the full
 * server/UI pipeline can be explored without Linux machines or Docker.
 * Usage: OCULYX_SERVER=http://localhost:8080 OCULYX_SIM_TOKENS=tok1,tok2,tok3 node agent/src/sim.ts
 */
import { createHash } from 'node:crypto';
import { runControls, score } from './sca.ts';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { Connection } from './connection.ts';
import type { AgentEvent, ContainerInfo, Finding, HostInfo, MetricsSample, Port, Provider } from './protocol.ts';

const GB = 1024 ** 3;
const rnd = (a: number, b: number) => a + Math.random() * (b - a);
const clamp = (v: number, a: number, b: number) => Math.max(a, Math.min(b, v));

interface SimHost {
  name: string;
  os: string;
  kernel: string;
  cpus: number;
  cpuModel: string;
  memGb: number;
  diskGb: number;
  cpu: [number, number]; // base, amplitude
  mem: number; // base %
  disk: number;
  net: number; // base bytes/s
  containers: [string, string, string, string[], boolean?][]; // name,image,state,ports,[privileged]
  findings: Finding[];
  ports: Port[];
  eventKinds: string[];
}

const P = (port: number, exposed = true): Port => ({ port, proto: 'tcp', addr: exposed ? '0.0.0.0' : 'loopback', exposed });

const HOSTS: SimHost[] = [
  {
    name: 'web-prod-01', os: 'Ubuntu 24.04.1 LTS', kernel: '6.8.0-48-generic', cpus: 8, cpuModel: 'AMD EPYC 7413', memGb: 32, diskGb: 480,
    cpu: [34, 22], mem: 61, disk: 54, net: 2_400_000,
    containers: [
      ['nginx-proxy', 'nginx:1.27-alpine', 'running', ['0.0.0.0:80->80/tcp', '0.0.0.0:443->443/tcp']],
      ['shop-api', 'registry.local/shop-api:2.14.3', 'running', ['127.0.0.1:3000->3000/tcp']],
      ['shop-worker', 'registry.local/shop-worker:2.14.3', 'running', []],
      ['redis-cache', 'redis:7', 'running', ['0.0.0.0:6379->6379/tcp']],
      ['postgres-main', 'postgres:16.4', 'running', ['127.0.0.1:5432->5432/tcp']],
      ['cron-reports', 'registry.local/reports:1.2.0', 'exited', []],
    ],
    findings: [
      { checkId: 'port:tcp:6379', severity: 'high', title: 'Redis exposed on port 6379', detail: 'Listening on 0.0.0.0:6379/tcp. Bind it to localhost or restrict it with a firewall.' },
      { checkId: 'docker:port:redis-cache:6379', severity: 'high', title: 'Redis published to all interfaces by redis-cache', detail: 'Bind to 127.0.0.1:6379 instead.' },
      { checkId: 'ssh:bruteforce:185.220.101.34', severity: 'high', title: 'SSH brute-force from 185.220.101.34', detail: '212 failed logins in the last hour (users: root, admin, ubuntu, test, oracle, postgres). Consider blocking the address or installing fail2ban.' },
      { checkId: 'ssh:password-auth', severity: 'medium', title: 'SSH password authentication enabled', detail: 'Prefer key-based auth: "PasswordAuthentication no".' },
      { checkId: 'docker:root:shop-api', severity: 'low', title: 'Container shop-api runs as root', detail: 'Set a non-root USER in the image or via --user.' },
      { checkId: 'docker:latest:redis-cache', severity: 'low', title: 'Container redis-cache uses an unpinned image tag', detail: 'redis:7 - pin a version or digest.' },
      { checkId: 'sys:updates', severity: 'low', title: '14 pending package updates', detail: 'Run: apt update && apt upgrade' },
      { checkId: 'net:no-ids', severity: 'medium', title: 'No intrusion prevention (fail2ban / CrowdSec)', detail: 'Repeated failed logins are not blocked automatically. fail2ban bans offending addresses at the firewall.' },
      { checkId: 'ssh:max-auth-tries', severity: 'low', title: 'SSH allows 6 authentication attempts per connection', detail: 'Lower MaxAuthTries to 3 to slow brute-force attempts.' },
    ],
    ports: [P(22), P(80), P(443), P(6379), P(3000, false), P(5432, false)],
    eventKinds: ['ssh_failed', 'ssh_failed', 'ssh_login', 'sudo', 'sudo_suspicious', 'ssh_login_after_failures'],
  },
  {
    name: 'db-primary', os: 'Debian GNU/Linux 12 (bookworm)', kernel: '6.1.0-26-amd64', cpus: 16, cpuModel: 'Intel Xeon Silver 4314', memGb: 128, diskGb: 1800,
    cpu: [52, 30], mem: 92, disk: 88, net: 9_800_000,
    containers: [],
    findings: [
      { checkId: 'ssh:root-login', severity: 'high', title: 'SSH permits root login', detail: 'Set "PermitRootLogin no" in sshd_config.' },
      { checkId: 'sys:sec-updates', severity: 'high', title: '6 pending security updates', detail: 'Run: apt update && apt upgrade' },
      { checkId: 'fw:inactive', severity: 'medium', title: 'No active host firewall detected', detail: 'Enable ufw or nftables.' },
      { checkId: 'fim:etc/ssh/sshd_config', severity: 'medium', title: 'File modified: /etc/ssh/sshd_config', detail: 'Differs from the recorded baseline. If the change was intentional, accept it as the new baseline.' },
      { checkId: 'sys:auto-updates', severity: 'medium', title: 'Automatic security updates are not enabled', detail: 'Install and enable unattended-upgrades so known vulnerabilities are patched without waiting for you.' },
      { checkId: 'sys:sysctl', severity: 'medium', title: '6 kernel network/security settings are not hardened', detail: 'net.ipv4.conf.all.rp_filter=1, net.ipv4.conf.all.accept_redirects=0, net.ipv4.tcp_syncookies=1, kernel.dmesg_restrict=1' },
      { checkId: 'acct:su-open', severity: 'low', title: 'Any local user may try to su to root', detail: 'Restrict su to a dedicated group (pam_wheel).' },
    ],
    ports: [P(22), P(5432), P(9100)],
    eventKinds: ['ssh_login', 'sudo', 'fim', 'ssh_key_added', 'user_created'],
  },
  {
    name: 'edge-gateway', os: 'Ubuntu 22.04.5 LTS', kernel: '5.15.0-122-generic', cpus: 4, cpuModel: 'Intel Core i5-12400', memGb: 16, diskGb: 240,
    cpu: [18, 12], mem: 47, disk: 41, net: 14_000_000,
    containers: [
      ['traefik', 'traefik:v3.1', 'running', ['0.0.0.0:80->80/tcp', '0.0.0.0:443->443/tcp']],
      ['portainer-legacy', 'portainer/portainer-ce:latest', 'running', ['0.0.0.0:9000->9000/tcp'], true],
      ['wireguard', 'linuxserver/wireguard:1.0.20210914', 'running', ['0.0.0.0:51820->51820/udp'], true],
      ['uptime-probe', 'registry.local/probe:0.9', 'exited', []],
    ],
    findings: [
      { checkId: 'docker:sock:portainer-legacy', severity: 'high', title: 'Container portainer-legacy mounts the Docker socket', detail: 'Equivalent to root on the host.' },
      { checkId: 'docker:priv:wireguard', severity: 'high', title: 'Container wireguard runs privileged', detail: 'Drop --privileged and add only NET_ADMIN.' },
      { checkId: 'docker:hostnet:traefik', severity: 'medium', title: 'Container traefik uses host networking' },
      { checkId: 'docker:latest:portainer-legacy', severity: 'low', title: 'Container portainer-legacy uses an unpinned image tag' },
      { checkId: 'ssh:password-auth', severity: 'medium', title: 'SSH password authentication enabled', detail: 'Passwords can be guessed; keys cannot. Deploy a key from the panel, test it, then turn passwords off.' },
      { checkId: 'net:no-ids', severity: 'medium', title: 'No intrusion prevention (fail2ban / CrowdSec)', detail: 'Repeated failed logins are not blocked automatically.' },
    ],
    ports: [P(22), P(80), P(443), P(9000), P(51820)],
    eventKinds: ['port_opened', 'ssh_login', 'persistence_changed', 'reverse_shell'],
  },
];

function simProvider(h: SimHost): Provider {
  const t0 = Date.now() + rnd(0, 10_000);
  const state = new Map(h.containers.map((c) => [c[0], c[2]]));
  const events: AgentEvent[] = [];
  let simSent = false;
  let spike = 0;
  const idOf = (i: number) => `${(0xa1b2c3d4e5f6 + i * 7919).toString(16).padStart(12, '0')}${'0'.repeat(52)}`;
  const info: HostInfo = { hostname: h.name, os: h.os, kernel: h.kernel, arch: 'x86_64', cpus: h.cpus, cpuModel: h.cpuModel, memTotal: h.memGb * GB, docker: h.containers.length > 0, agentVersion: '0.1.0-sim', actions: true, canHarden: true };
  const hostKeys = [{ user: 'root', type: 'ssh-ed25519', fingerprint: 'SHA256:Jq1x0kq0m7ZkQpV8Pq3dYkq0s2mWf9v8nE1l0aVbZ4o', comment: 'maria@laptop' }, { user: 'deploy', type: 'ssh-ed25519', fingerprint: 'SHA256:wP9l0cH2dTq1uYz7nB3vXrK5sA8eM4jG6fD2oLhQ1iU', comment: 'ci-deploy' }];
  const FIX_MAP: Record<string, string> = { 'ssh:password-auth': 'ssh.password-auth', 'ssh:root-login': 'ssh.root-login', 'fw:inactive': 'firewall.enable', 'sys:sysctl': 'sysctl.apply', 'net:no-ids': 'fail2ban.install', 'ssh:max-auth-tries': 'ssh.max-auth-tries', 'acct:su-open': 'su.restrict', 'sys:auto-updates': 'autoupdates.enable' };
  const PREVIEW: Record<string, { title: string; steps: string[]; warning?: string; confirm?: boolean }> = {
    'ssh.password-auth': { title: 'Turn off SSH password logins', steps: ['PasswordAuthentication no', 'KbdInteractiveAuthentication no', 'Accounts with a key: root (1), deploy (1)'], warning: 'Only key-based logins will work afterwards. Make sure you tested a key login first.', confirm: true },
    'ssh.root-login': { title: 'Allow root SSH login only with keys', steps: ['PermitRootLogin prohibit-password'], warning: 'Root will no longer be able to log in with a password.' },
    'firewall.enable': { title: 'Enable the firewall (default deny)', steps: ['Default policy: deny incoming, allow outgoing', 'Allow 22/tcp (currently listening)', 'Allow 5432/tcp (currently listening)', 'Enable ufw'], warning: 'Only the ports listed above stay reachable.', confirm: true },
    'sysctl.apply': { title: 'Apply kernel hardening settings', steps: ['net.ipv4.conf.all.rp_filter = 1', 'net.ipv4.tcp_syncookies = 1', 'kernel.dmesg_restrict = 1'] },
    'fail2ban.install': { title: 'Install fail2ban', steps: ['apt-get install fail2ban', 'Enable the sshd jail: 5 failures in 10 minutes bans the address for 1 hour'] },
    'ssh.max-auth-tries': { title: 'Limit SSH authentication attempts', steps: ['MaxAuthTries 3'] },
    'su.restrict': { title: 'Restrict su to a dedicated group', steps: ['Create the group "sugroup"', 'Require membership of sugroup to use su'] },
    'autoupdates.enable': { title: 'Enable automatic security updates', steps: ['apt-get install unattended-upgrades', 'Enable the daily timers'] },
  };

  const eventFor = (kind: string): AgentEvent => {
    const ip = `${Math.floor(rnd(2, 223))}.${Math.floor(rnd(0, 255))}.${Math.floor(rnd(0, 255))}.${Math.floor(rnd(1, 254))}`;
    switch (kind) {
      case 'ssh_failed': return { type: 'ssh_failed', severity: 'medium', message: `${Math.floor(rnd(6, 60))} failed SSH logins from ${ip}`, data: { ip } };
      case 'ssh_login': return { type: 'ssh_login', severity: 'info', message: `SSH login: deploy from 10.0.0.${Math.floor(rnd(2, 40))} (publickey)`, data: {} };
      case 'sudo': return { type: 'sudo', severity: 'info', message: 'sudo by deploy: /usr/bin/systemctl restart nginx', data: {} };
      case 'port_opened': return { type: 'port_opened', severity: 'medium', message: `New listening port tcp/${Math.floor(rnd(3000, 9000))}`, data: {} };
      case 'sudo_suspicious': return { type: 'sudo_suspicious', severity: 'high', message: 'Suspicious sudo by deploy (setting the SUID/SGID bit): /usr/bin/chmod u+s /tmp/.x', data: { user: 'deploy' } };
      case 'ssh_login_after_failures': return { type: 'ssh_login_after_failures', severity: 'critical', message: `admin logged in from ${ip} right after 9 failed attempts from the same address: the password may have been guessed`, data: { user: 'admin', ip } };
      case 'ssh_key_added': return { type: 'ssh_key_added', severity: 'high', message: 'New SSH key authorized for root: SHA256:Jq1x0kq0m7ZkQpV8Pq3dYkq0s2mWf9v8nE1l0aVbZ4o (backup@laptop)', data: { user: 'root' } };
      case 'user_created': return { type: 'user_created', severity: 'high', message: 'New local account: support2 (uid 1004, shell /bin/bash)', data: { user: 'support2' } };
      case 'persistence_changed': return { type: 'persistence_changed', severity: 'high', message: '/etc/cron.d/sysupdate created', data: { file: 'etc/cron.d/sysupdate' } };
      case 'reverse_shell': return { type: 'reverse_shell', severity: 'critical', message: 'A shell (pid 48213) has its input and output wired to a network socket: likely a reverse shell', data: { pid: 48213 } };
      default: return { type: 'fim', severity: 'medium', message: '/etc/ssh/sshd_config modified', data: {} };
    }
  };

  return {
    info: async () => info,
    async metrics(): Promise<MetricsSample> {
      const t = (Date.now() - t0) / 1000;
      if (spike > 0) spike--;
      else if (Math.random() < 0.01) spike = 8;
      const cpu = clamp(h.cpu[0] + Math.sin(t / 45) * h.cpu[1] * 0.6 + rnd(-6, 6) + (spike ? 40 : 0), 1, 100);
      const mem = clamp(h.mem + Math.sin(t / 300) * 1.2 + rnd(-0.4, 0.4), 5, 99);
      const net = h.net * (0.6 + Math.sin(t / 30) * 0.4 + Math.random() * 0.5);
      return {
        cpu, memTotal: h.memGb * GB, memUsed: (mem / 100) * h.memGb * GB, diskTotal: h.diskGb * GB, diskUsed: (h.disk / 100) * h.diskGb * GB,
        rx: net, tx: net * rnd(0.3, 0.7), load1: (cpu / 100) * h.cpus * rnd(0.7, 1.1), uptime: 86400 * 23 + t,
      };
    },
    async docker(): Promise<ContainerInfo[] | null> {
      if (!h.containers.length) return null;
      return h.containers.map(([name, image, , ports], i) => {
        const st = state.get(name)!;
        const running = st === 'running';
        return {
          id: idOf(i), name, image, state: st,
          status: running ? 'Up 3 days' : st === 'exited' ? 'Exited (1) 2 hours ago' : st,
          exitCode: st === 'exited' ? 1 : 0, created: Date.now() - 86400_000 * (3 + i), ports,
          cpu: running ? rnd(0.1, 14) : undefined, mem: running ? rnd(30, 900) * 1024 * 1024 : undefined, memLimit: running ? 2 * GB : undefined,
        };
      });
    },
    async security() {
      if (Math.random() < 0.5) events.push(eventFor(h.eventKinds[Math.floor(Math.random() * h.eventKinds.length)]));
      return { findings: h.findings.map((f) => ({ ...f, fix: FIX_MAP[f.checkId] })), ports: h.ports };
    },
    drainEvents: () => events.splice(0),
    configure: () => { simSent = false; },
    drainMessages() {
      if (simSent) return [];
      simSent = true;
      const controls = runControls().map((c) => {
        const roll = (parseInt(createHash('md5').update(h.name + c.id).digest('hex').slice(0, 4), 16) % 100);
        const fail = roll < (h.eventKinds.length > 3 ? 45 : 22);
        return { ...c, status: fail ? 'fail' : 'pass', detail: fail ? 'simulated' : undefined };
      });
      return [
        { t: 'sca', ts: Date.now(), score: score(controls as any), controls },
        { t: 'inventory', ts: Date.now(), os: { id: 'ubuntu', version: '22.04', name: 'Ubuntu 22.04.3 LTS' },
          packages: [['openssl', '3.0.2-0ubuntu1.10', 'openssl'], ['sudo', '1.9.9-1ubuntu2.2', 'sudo'], ['curl', '7.81.0-1ubuntu1.6', 'curl'], ['nginx', '1.18.0-6ubuntu14.3', 'nginx'], ['bash', '5.1-6ubuntu1', 'bash'], ['openssh-server', '1:8.9p1-3ubuntu0.1', 'openssh']],
          services: ['ssh', 'cron', 'nginx', 'rsyslog'] },
      ];
    },
    async command(action, args) {
      if (action === 'checks.run') { simSent = false; return { ok: true }; }
      if (action === 'admin.overview') return {
        users: [
          { user: 'root', uid: 0, shell: '/bin/bash', login: true, locked: false, sudo: true },
          { user: 'deploy', uid: 1000, shell: '/bin/bash', login: true, locked: false, sudo: true },
          { user: 'maria', uid: 1001, shell: '/bin/bash', login: true, locked: false, sudo: false },
          { user: 'backup', uid: 1002, shell: '/usr/sbin/nologin', login: false, locked: true, sudo: false },
        ],
        sessions: [{ user: 'deploy', tty: 'pts/0', since: '2026-10-20 09:14', from: '10.0.0.5' }],
        services: [
          { unit: 'nginx.service', active: 'active', sub: 'running', description: 'A high performance web server', enabled: 'enabled' },
          { unit: 'postgresql.service', active: 'active', sub: 'exited', description: 'PostgreSQL RDBMS', enabled: 'enabled' },
          { unit: 'cron.service', active: 'active', sub: 'running', description: 'Regular background program processing daemon', enabled: 'enabled' },
          { unit: 'fail2ban.service', active: 'failed', sub: 'failed', description: 'Fail2Ban Service', enabled: 'enabled' },
          { unit: 'redis-server.service', active: 'inactive', sub: 'dead', description: 'Advanced key-value store', enabled: 'disabled' },
        ],
        firewall: { tool: 'ufw', active: true, rules: ['22/tcp  ALLOW IN  Anywhere', '443/tcp  ALLOW IN  Anywhere', '80/tcp  ALLOW IN  Anywhere'] },
        banned: ['185.220.101.34'], fail2ban: false,
        updates: { pending: 14, security: 5 }, rebootRequired: true,
      };
      if (action === 'admin.apply') return { steps: [`${args.op}: done (demo)`] };
      if (action === 'ssh.list') return { keys: hostKeys, users: ['root', 'deploy'], passwordAuth: 'yes', permitRootLogin: 'yes', managed: false };
      if (action === 'ssh.authorize') {
        hostKeys.push({ user: String(args.user), type: 'ssh-ed25519', fingerprint: 'SHA256:' + Buffer.from(String(args.key)).toString('base64').slice(8, 51).padEnd(43, 'x'), comment: String(args.key).split(' ')[2] ?? '' });
        return { steps: [`authorized the key for ${args.user}`] };
      }
      if (action === 'ssh.revoke') {
        const i = hostKeys.findIndex((k) => k.user === args.user && k.fingerprint === args.fingerprint);
        if (i >= 0) hostKeys.splice(i, 1);
        return { steps: [`removed the key from ${args.user}`] };
      }
      if (action === 'harden.preview') {
        const p = PREVIEW[String(args.fix)];
        if (!p) throw new Error('unknown fix');
        return p;
      }
      if (action === 'harden.apply') {
        const p = PREVIEW[String(args.fix)];
        if (!p) throw new Error('unknown fix');
        if (p.confirm && args.args?.confirm !== true) throw new Error('Confirmation required: tick the box saying you tested a key login.');
        for (let i = h.findings.length - 1; i >= 0; i--) if (FIX_MAP[h.findings[i].checkId] === args.fix) h.findings.splice(i, 1);
        return { steps: p.steps };
      }
      if (action === 'docker.logs') {
        const now = Date.now();
        return Array.from({ length: 40 }, (_, i) => `${new Date(now - (40 - i) * 4000).toISOString()} ${['GET /healthz 200 1ms', 'GET /api/orders 200 23ms', 'POST /api/cart 201 41ms', 'worker: processed job ' + Math.floor(rnd(1000, 9999)), 'cache hit ratio 0.' + Math.floor(rnd(80, 99))][i % 5]}`).join('\n');
      }
      if (action === 'fim.rebaseline') {
        const i = h.findings.findIndex((f) => f.checkId.startsWith('fim:'));
        if (i >= 0) h.findings.splice(i, 1);
        return { ok: true };
      }
      const c = h.containers.find((_, i) => idOf(i) === args.id);
      if (!c) throw new Error('no such container');
      if (action === 'docker.stop') state.set(c[0], 'exited');
      else if (action === 'docker.start' || action === 'docker.restart') state.set(c[0], 'running');
      return { ok: true };
    },
  };
}

const server = process.env.OCULYX_SERVER ?? 'http://localhost:8080';
const tokens = (process.env.OCULYX_SIM_TOKENS ?? '').split(',').filter(Boolean);
if (import.meta.main) {
  HOSTS.forEach((h, i) => {
    const stateDir = resolve(process.env.OCULYX_STATE_DIR ?? './demo-agents', h.name);
    mkdirSync(stateDir, { recursive: true });
    void new Connection({ server, name: h.name, stateDir, enrollToken: tokens[i], metricsEvery: 3000, dockerEvery: 5000, securityEvery: 20_000 }, simProvider(h)).run();
  });
}
