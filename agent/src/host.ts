import { readFileSync, readdirSync, statfsSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { cpus, hostname, totalmem, freemem, arch, release, platform, uptime, loadavg } from 'node:os';
import { join } from 'node:path';
import type { HostInfo, MetricsSample } from './protocol.ts';
import { netstatBytes } from './windows.ts';

export const VERSION = '0.1.0';
/** Fingerprint of this agent's source files; the server computes the same over what it would hand out, to spot outdated agents. */
export const BUILD: string = (() => {
  try {
    const h = createHash('sha1');
    for (const f of readdirSync(import.meta.dirname).filter((x) => x.endsWith('.ts') && x !== 'sim.ts').sort()) h.update(f).update('\0').update(readFileSync(join(import.meta.dirname, f))).update('\0');
    return h.digest('hex').slice(0, 12);
  } catch {
    return '';
  }
})();
/** Prefix under which the host's filesystem is mounted when the agent runs in a container (e.g. /host). */
export const HOST_ROOT = process.env.HOST_ROOT ?? '';
export const hp = (p: string) => join(HOST_ROOT || '/', p);
export const isLinux = platform() === 'linux';

export const readText = (p: string): string | null => {
  try {
    return readFileSync(p, 'utf8');
  } catch {
    return null;
  }
};

function osName(): string {
  const rel = readText(hp('etc/os-release'));
  const m = rel?.match(/^PRETTY_NAME="?([^"\n]+)"?/m);
  return m?.[1] ?? `${platform()} ${release()}`;
}

export function hostInfo(dockerAvailable: boolean): HostInfo {
  return {
    hostname: (isLinux && readText(hp('etc/hostname'))?.trim()) || hostname(),
    os: osName(),
    kernel: (isLinux && readText(hp('proc/sys/kernel/osrelease'))?.trim()) || release(),
    arch: arch(),
    cpus: cpus().length,
    cpuModel: cpus()[0]?.model?.trim() ?? '',
    memTotal: totalmem(),
    docker: dockerAvailable,
    agentVersion: VERSION,
    build: BUILD,
    platform: platform(),
  };
}

// ---- CPU / network deltas ----
let lastCpu: { busy: number; total: number } | null = null;
let lastNet: { rx: number; tx: number; at: number } | null = null;

function cpuTimes(): { busy: number; total: number } {
  if (isLinux) {
    const line = readText(hp('proc/stat'))?.split('\n')[0];
    if (line) {
      const v = line.trim().split(/\s+/).slice(1).map(Number);
      const idle = (v[3] ?? 0) + (v[4] ?? 0);
      const total = v.slice(0, 8).reduce((a, b) => a + b, 0);
      return { busy: total - idle, total };
    }
  }
  let busy = 0;
  let total = 0;
  for (const c of cpus()) {
    const t = c.times;
    total += t.user + t.nice + t.sys + t.idle + t.irq;
    busy += t.user + t.nice + t.sys + t.irq;
  }
  return { busy, total };
}

function netTotals(): { rx: number; tx: number } {
  const txt = isLinux ? readText(hp('proc/net/dev')) : null;
  let rx = 0;
  let tx = 0;
  for (const l of txt?.split('\n').slice(2) ?? []) {
    const [name, rest] = l.split(':');
    const iface = name?.trim();
    if (!iface || !rest || iface === 'lo' || /^(veth|br-|docker)/.test(iface)) continue;
    const f = rest.trim().split(/\s+/).map(Number);
    rx += f[0] ?? 0;
    tx += f[8] ?? 0;
  }
  return { rx, tx };
}

function memory(): { used: number; total: number } {
  const txt = isLinux ? readText(hp('proc/meminfo')) : null;
  if (txt) {
    const kb = (k: string) => Number(txt.match(new RegExp(`^${k}:\\s+(\\d+)`, 'm'))?.[1] ?? 0) * 1024;
    const total = kb('MemTotal');
    if (total) return { used: total - kb('MemAvailable'), total };
  }
  return { used: totalmem() - freemem(), total: totalmem() };
}

function disk(): { used: number; total: number } {
  try {
    const s = statfsSync(HOST_ROOT || (isLinux ? '/' : `${process.env.SystemDrive ?? 'C:'}\\`));
    const total = (s.blocks - s.bfree + s.bavail) * s.bsize;
    return { used: (s.blocks - s.bfree) * s.bsize, total };
  } catch {
    return { used: 0, total: 0 };
  }
}

export async function collectMetrics(): Promise<MetricsSample> {
  const now = cpuTimes();
  let cpu = 0;
  if (lastCpu && now.total > lastCpu.total) cpu = ((now.busy - lastCpu.busy) / (now.total - lastCpu.total)) * 100;
  lastCpu = now;

  const n = (platform() === 'win32' ? await netstatBytes() : null) ?? netTotals();
  const at = Date.now();
  let rx = 0;
  let tx = 0;
  if (lastNet && at > lastNet.at) {
    const dt = (at - lastNet.at) / 1000;
    rx = Math.max(0, (n.rx - lastNet.rx) / dt);
    tx = Math.max(0, (n.tx - lastNet.tx) / dt);
  }
  lastNet = { ...n, at };

  const m = memory();
  const d = disk();
  const up = isLinux ? Number(readText(hp('proc/uptime'))?.split(' ')[0]) || uptime() : uptime();
  const load1 = isLinux ? Number(readText(hp('proc/loadavg'))?.split(' ')[0]) || 0 : loadavg()[0];
  return { cpu: Math.min(100, Math.max(0, cpu)), memUsed: m.used, memTotal: m.total, diskUsed: d.used, diskTotal: d.total, rx, tx, load1, uptime: up };
}

export const fileExists = (p: string) => existsSync(p);
