import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync } from 'node:fs';
import type { Db } from './db.ts';

const CANDIDATES = [process.env.OCULYX_CLOUDFLARED, '/opt/cloudflared/cloudflared', '/usr/local/bin/cloudflared', '/usr/bin/cloudflared'];
const HOSTNAME_RE = /^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

export type TunnelState = 'off' | 'starting' | 'connected' | 'error';

/** A Cloudflare Tunnel token is base64 JSON: {"a": account, "t": tunnel id, "s": secret}. */
export function validTunnelToken(token: string): boolean {
  if (!/^[A-Za-z0-9+/_-]{40,2000}={0,2}$/.test(token)) return false;
  try {
    const j = JSON.parse(Buffer.from(token, 'base64').toString('utf8'));
    return typeof j.a === 'string' && typeof j.t === 'string' && typeof j.s === 'string';
  } catch {
    return false;
  }
}

export function validHostname(h: string): boolean {
  return HOSTNAME_RE.test(h);
}

/**
 * Runs `cloudflared` as a child of the server so a domain can be set up from the web UI. The token lives in
 * the settings table and is handed to the process through the environment (never on the command line).
 */
export class Tunnel {
  private child: ChildProcess | null = null;
  private timer: NodeJS.Timeout | null = null;
  private failures = 0;
  private stopping = false;
  state: TunnelState = 'off';
  lines: string[] = [];

  private db: Db;

  constructor(db: Db) {
    this.db = db;
  }

  binary(): string | null {
    return CANDIDATES.find((c) => c && existsSync(c)) ?? null;
  }

  private log(line: string) {
    const clean = line.replace(/\x1b\[[0-9;]*m/g, '').trim();
    if (!clean) return;
    this.lines.push(clean);
    if (this.lines.length > 40) this.lines.shift();
    if (/Registered tunnel connection|Connection .* registered/i.test(clean)) {
      this.state = 'connected';
      this.failures = 0;
    }
  }

  /** (Re)starts or stops the tunnel to match the saved settings. */
  apply() {
    this.stop();
    const token = this.db.setting('cloudflare.token');
    const bin = this.binary();
    if (this.db.setting('cloudflare.enabled') !== '1' || !token || !bin) {
      this.state = 'off';
      return;
    }
    this.stopping = false;
    this.state = 'starting';
    const child = spawn(bin, ['tunnel', '--no-autoupdate', '--metrics', '127.0.0.1:0', 'run'], {
      env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '/tmp', TUNNEL_TOKEN: token },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    this.child = child;
    const feed = (b: Buffer) => b.toString().split('\n').forEach((l) => this.log(l));
    child.stdout?.on('data', feed);
    child.stderr?.on('data', feed);
    child.on('error', (e) => {
      this.log(`cannot start cloudflared: ${e.message}`);
      this.state = 'error';
    });
    child.on('exit', (code) => {
      if (this.child !== child) return;
      this.child = null;
      if (this.stopping) return;
      this.state = 'error';
      this.log(`cloudflared exited (code ${code})`);
      this.failures++;
      this.timer = setTimeout(() => this.apply(), Math.min(60_000, 2000 * 2 ** this.failures));
    });
  }

  stop() {
    this.stopping = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    const c = this.child;
    this.child = null;
    if (c && !c.killed) c.kill('SIGTERM');
    this.lines = [];
  }
}
