import http from 'node:http';
import type { ContainerInfo } from './protocol.ts';

const SOCKET = process.env.DOCKER_SOCKET ?? '/var/run/docker.sock';

/** Minimal Docker Engine API client over the unix socket (no dependencies). */
function request(method: string, path: string, timeout = 8000): Promise<{ status: number; body: Buffer }> {
  return new Promise((resolve, reject) => {
    const req = http.request({ socketPath: SOCKET, path, method, timeout }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks) }));
    });
    req.on('timeout', () => req.destroy(new Error('docker timeout')));
    req.on('error', reject);
    req.end();
  });
}

const json = async (path: string) => {
  const r = await request('GET', path);
  if (r.status >= 300) throw new Error(`docker ${r.status}`);
  return JSON.parse(r.body.toString());
};

export async function dockerAvailable(): Promise<boolean> {
  try {
    return (await request('GET', '/_ping', 2000)).status === 200;
  } catch {
    return false;
  }
}

function cpuPercent(s: any): number {
  const cpuDelta = s.cpu_stats?.cpu_usage?.total_usage - s.precpu_stats?.cpu_usage?.total_usage;
  const sysDelta = s.cpu_stats?.system_cpu_usage - s.precpu_stats?.system_cpu_usage;
  const n = s.cpu_stats?.online_cpus ?? 1;
  return sysDelta > 0 && cpuDelta >= 0 ? (cpuDelta / sysDelta) * n * 100 : 0;
}

export async function listContainers(): Promise<ContainerInfo[]> {
  const list: any[] = await json('/containers/json?all=1');
  const out: ContainerInfo[] = list.map((c) => ({
    id: c.Id,
    name: String(c.Names?.[0] ?? c.Id).replace(/^\//, ''),
    image: c.Image,
    state: c.State,
    status: c.Status,
    created: c.Created * 1000,
    ports: (c.Ports ?? []).filter((p: any) => p.PublicPort).map((p: any) => `${p.IP ?? ''}:${p.PublicPort}->${p.PrivatePort}/${p.Type}`),
  }));
  await Promise.all(
    out
      .filter((c) => c.state === 'running')
      .slice(0, 40)
      .map(async (c) => {
        try {
          const s = await json(`/containers/${c.id}/stats?stream=false&one-shot=true`);
          c.cpu = cpuPercent(s);
          const cache = s.memory_stats?.stats?.inactive_file ?? s.memory_stats?.stats?.cache ?? 0;
          c.mem = (s.memory_stats?.usage ?? 0) - cache;
          c.memLimit = s.memory_stats?.limit;
        } catch {
          /* container may have just stopped */
        }
      }),
  );
  await Promise.all(
    out
      .filter((c) => c.state === 'exited')
      .map(async (c) => {
        try {
          c.exitCode = (await json(`/containers/${c.id}/json`)).State?.ExitCode;
        } catch {
          /* ignore */
        }
      }),
  );
  return out;
}

export const inspect = (id: string) => json(`/containers/${encodeURIComponent(id)}/json`);

const ID_RE = /^[a-f0-9]{12,64}$/;
export async function containerAction(action: 'start' | 'stop' | 'restart', id: string) {
  if (!ID_RE.test(id)) throw new Error('bad container id');
  const r = await request('POST', `/containers/${id}/${action}`, 30_000);
  if (r.status >= 300 && r.status !== 304) throw new Error(`docker ${r.status}: ${r.body.toString().slice(0, 200)}`);
  return { ok: true };
}

/** Docker multiplexes stdout/stderr in 8-byte-framed chunks when no TTY is attached; strip the frames. */
function demux(buf: Buffer): string {
  let out = '';
  let i = 0;
  while (i + 8 <= buf.length) {
    const size = buf.readUInt32BE(i + 4);
    if (buf[i] > 2 || size > buf.length) return buf.toString('utf8');
    out += buf.subarray(i + 8, i + 8 + size).toString('utf8');
    i += 8 + size;
  }
  return out || buf.toString('utf8');
}

export async function containerLogs(id: string, tail = 200): Promise<string> {
  if (!ID_RE.test(id)) throw new Error('bad container id');
  const r = await request('GET', `/containers/${id}/logs?stdout=1&stderr=1&timestamps=1&tail=${Math.min(tail, 1000)}`, 10_000);
  if (r.status >= 300) throw new Error(`docker ${r.status}`);
  return demux(r.body).slice(-100_000);
}
