/**
 * Demo simulator: several fake hosts speaking the real agent protocol, so the full
 * server/UI pipeline can be explored without Linux machines or Docker.
 * Usage: OCULYX_SERVER=http://localhost:8080 OCULYX_SIM_TOKENS=tok1,tok2,tok3 node agent/src/sim.ts
 */
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
    ],
    ports: [P(22), P(80), P(443), P(6379), P(3000, false), P(5432, false)],
    eventKinds: ['ssh_failed', 'ssh_failed', 'ssh_login', 'sudo'],
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
    ],
    ports: [P(22), P(5432), P(9100)],
    eventKinds: ['ssh_login', 'sudo', 'fim'],
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
    ],
    ports: [P(22), P(80), P(443), P(9000), P(51820)],
    eventKinds: ['port_opened', 'ssh_login'],
  },
];

function simProvider(h: SimHost): Provider {
  const t0 = Date.now() + rnd(0, 10_000);
  const state = new Map(h.containers.map((c) => [c[0], c[2]]));
  const events: AgentEvent[] = [];
  let spike = 0;
  const idOf = (i: number) => `${(0xa1b2c3d4e5f6 + i * 7919).toString(16).padStart(12, '0')}${'0'.repeat(52)}`;
  const info: HostInfo = { hostname: h.name, os: h.os, kernel: h.kernel, arch: 'x86_64', cpus: h.cpus, cpuModel: h.cpuModel, memTotal: h.memGb * GB, docker: h.containers.length > 0, agentVersion: '0.1.0-sim' };

  const eventFor = (kind: string): AgentEvent => {
    const ip = `${Math.floor(rnd(2, 223))}.${Math.floor(rnd(0, 255))}.${Math.floor(rnd(0, 255))}.${Math.floor(rnd(1, 254))}`;
    switch (kind) {
      case 'ssh_failed': return { type: 'ssh_failed', severity: 'medium', message: `${Math.floor(rnd(6, 60))} failed SSH logins from ${ip}`, data: { ip } };
      case 'ssh_login': return { type: 'ssh_login', severity: 'info', message: `SSH login: deploy from 10.0.0.${Math.floor(rnd(2, 40))} (publickey)`, data: {} };
      case 'sudo': return { type: 'sudo', severity: 'info', message: 'sudo by deploy: /usr/bin/systemctl restart nginx', data: {} };
      case 'port_opened': return { type: 'port_opened', severity: 'medium', message: `New listening port tcp/${Math.floor(rnd(3000, 9000))}`, data: {} };
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
      return { findings: h.findings, ports: h.ports };
    },
    drainEvents: () => events.splice(0),
    async command(action, args) {
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
