import WebSocket from 'ws';
import { mkdirSync, readFileSync, writeFileSync, existsSync, renameSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import type { Provider } from './protocol.ts';

export interface ConnOptions {
  server: string; // http(s)://host:port
  name: string;
  enrollToken?: string;
  stateDir: string;
  metricsEvery?: number;
  dockerEvery?: number;
  securityEvery?: number;
  /** If set, a small JSON status file (connected, server, name, ...) is kept up to date for local UIs such as the Windows tray icon. */
  statusFile?: string;
  log?: (msg: string) => void;
}

interface Creds {
  agentId: number;
  secret: string;
}

/** Enrolls once, then keeps an outbound WebSocket to the server and pushes telemetry. Reconnects forever. */
export class Connection {
  private ws?: WebSocket;
  private timers: NodeJS.Timeout[] = [];
  private log: (m: string) => void;
  private o: ConnOptions;
  private p: Provider;
  private connectedSince = 0;
  constructor(o: ConnOptions, p: Provider) {
    this.o = o;
    this.p = p;
    this.log = o.log ?? ((m) => console.log(`[agent:${o.name}] ${m}`));
  }

  private writeStatus(connected: boolean) {
    const f = this.o.statusFile;
    if (!f) return;
    try {
      const body = JSON.stringify({ connected, server: this.o.server, name: this.o.name, since: this.connectedSince, updated: Date.now() });
      writeFileSync(`${f}.tmp`, body);
      renameSync(`${f}.tmp`, f);
    } catch {
      /* the status file is a convenience; never let it break monitoring */
    }
  }

  private credsFile() {
    return join(this.o.stateDir, 'credentials.json');
  }

  private async credentials(): Promise<Creds> {
    if (existsSync(this.credsFile())) return JSON.parse(readFileSync(this.credsFile(), 'utf8'));
    if (!this.o.enrollToken) throw new Error('not enrolled: set OCULYX_ENROLL_TOKEN');
    const res = await fetch(`${this.o.server}/api/agent/enroll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: this.o.enrollToken, name: this.o.name, info: await this.p.info() }),
    });
    if (!res.ok) throw new Error(`enrollment rejected (${res.status})`);
    const c = (await res.json()) as Creds;
    mkdirSync(this.o.stateDir, { recursive: true });
    writeFileSync(this.credsFile(), JSON.stringify(c), { mode: 0o600 });
    this.log(`enrolled as agent #${c.agentId}`);
    return c;
  }

  async run(): Promise<never> {
    let backoff = 1000;
    for (;;) {
      try {
        const creds = await this.credentials();
        await this.session(creds);
        backoff = 1000;
      } catch (e) {
        const msg = (e as Error).message;
        // the server no longer knows this agent (it was removed): enroll again if we were given a token
        if (/401/.test(msg) && this.o.enrollToken && existsSync(this.credsFile())) {
          this.log('credentials rejected; enrolling again with the token');
          unlinkSync(this.credsFile());
        }
        this.log(`${msg}; retrying in ${backoff / 1000}s`);
      }
      await new Promise((r) => setTimeout(r, backoff));
      backoff = Math.min(backoff * 2, 30_000);
    }
  }

  private send(msg: unknown) {
    if (this.ws?.readyState === WebSocket.OPEN) this.ws.send(JSON.stringify(msg));
  }

  private session(creds: Creds): Promise<void> {
    const url = this.o.server.replace(/^http/, 'ws') + '/ws/agent';
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url, { headers: { authorization: `Bearer ${creds.agentId}.${creds.secret}` } });
      this.ws = ws;
      let opened = false;
      const stop = () => {
        this.timers.forEach(clearInterval);
        this.timers = [];
      };
      const every = (ms: number, fn: () => Promise<void> | void) => {
        const tick = () => Promise.resolve(fn()).catch((e) => this.log(`collector error: ${(e as Error).message}`));
        void tick();
        this.timers.push(setInterval(tick, ms));
      };
      ws.on('open', async () => {
        opened = true;
        this.connectedSince = Date.now();
        this.log('connected');
        this.writeStatus(true);
        this.send({ t: 'hello', info: await this.p.info() });
        every(this.o.metricsEvery ?? 10_000, async () => {
          this.send({ t: 'metrics', ...(await this.p.metrics()) });
          this.writeStatus(true);
        });
        every(this.o.dockerEvery ?? 15_000, async () => {
          const containers = await this.p.docker();
          if (containers) this.send({ t: 'docker', containers });
        });
        every(this.o.securityEvery ?? 300_000, async () => {
          this.send({ t: 'security', ...(await this.p.security()) });
          const events = this.p.drainEvents();
          if (events.length) this.send({ t: 'events', events });
        });
        every(15_000, () => {
          this.p.tick?.();
          const events = this.p.drainEvents();
          if (events.length) this.send({ t: 'events', events });
          for (const m of this.p.drainMessages?.() ?? []) this.send(m);
        });
      });
      ws.on('message', async (raw) => {
        const m = JSON.parse(raw.toString());
        if (m.t === 'config') {
          this.p.configure?.(m.checks);
          return;
        }
        if (m.t !== 'cmd') return;
        try {
          this.send({ t: 'result', id: m.id, ok: true, data: await this.p.command(m.action, m.args ?? {}) });
          if (m.action === 'checks.run') setTimeout(() => { for (const x of this.p.drainMessages?.() ?? []) this.send(x); const events = this.p.drainEvents(); if (events.length) this.send({ t: 'events', events }); }, 300);
          if (m.action.startsWith('docker.') || m.action.startsWith('fim.') || m.action.startsWith('harden.') || m.action.startsWith('ssh.')) setTimeout(() => this.refreshSoon(), 500);
        } catch (e) {
          this.send({ t: 'result', id: m.id, ok: false, error: (e as Error).message });
        }
      });
      ws.on('close', (code) => {
        stop();
        this.writeStatus(false);
        if (!opened) return reject(new Error(`connection failed (${code})`));
        this.log(`disconnected (${code})`);
        resolve();
      });
      ws.on('error', (e) => {
        if (!opened) {
          stop();
          reject(new Error(e.message));
        }
      });
    });
  }

  private async refreshSoon() {
    const containers = await this.p.docker().catch(() => null);
    if (containers) this.send({ t: 'docker', containers });
    this.send({ t: 'security', ...(await this.p.security()) });
  }
}
