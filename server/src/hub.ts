import type { WebSocket } from 'ws';
import type { Db } from './db.ts';
import type { Alerts } from './alerts.ts';
import { RuleEngine } from './rules.ts';

interface Pending {
  resolve: (v: any) => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
}

/** Tracks live agent sockets, ingests what they send, and relays commands to them. */
export class Hub {
  private sockets = new Map<number, WebSocket>();
  private pending = new Map<string, Pending>();
  private seq = 0;
  private db: Db;
  private alerts: Alerts;
  private rules: RuleEngine;
  constructor(db: Db, alerts: Alerts) {
    this.db = db;
    this.alerts = alerts;
    this.rules = new RuleEngine(db, alerts);
  }

  /** Drops a live connection (used when the host is removed so it cannot keep reporting). */
  disconnect(id: number) {
    this.sockets.get(id)?.close(4001, 'removed');
    this.sockets.delete(id);
  }

  isOnline(id: number) {
    return this.sockets.has(id);
  }

  attach(agentId: number, ws: WebSocket, ip: string) {
    this.sockets.get(agentId)?.close(4000, 'replaced');
    this.sockets.set(agentId, ws);
    this.db.run('UPDATE agents SET last_seen=?, ip=? WHERE id=?', Date.now(), ip, agentId);
    ws.on('message', (raw) => {
      try {
        this.ingest(agentId, JSON.parse(raw.toString()));
      } catch (e) {
        console.error('bad agent message', agentId, (e as Error).message);
      }
    });
    ws.on('close', () => {
      if (this.sockets.get(agentId) === ws) this.sockets.delete(agentId);
    });
  }

  command(agentId: number, action: string, args: Record<string, unknown> = {}, timeoutMs = 20_000): Promise<any> {
    const ws = this.sockets.get(agentId);
    if (!ws) return Promise.reject(new Error('agent offline'));
    const id = `c${++this.seq}`;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error('timeout'));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      ws.send(JSON.stringify({ t: 'cmd', id, action, args }));
    });
  }

  private ingest(agentId: number, m: any) {
    const now = Date.now();
    switch (m.t) {
      case 'hello':
        this.db.run('UPDATE agents SET info=?, last_seen=? WHERE id=?', JSON.stringify(m.info), now, agentId);
        break;
      case 'metrics': {
        const pct = (a: number, b: number) => (b > 0 ? (a / b) * 100 : 0);
        const mem = pct(m.memUsed, m.memTotal);
        const disk = pct(m.diskUsed, m.diskTotal);
        this.db.run('INSERT INTO metrics(agent_id,ts,cpu,mem,disk,rx,tx,load1) VALUES(?,?,?,?,?,?,?,?)', agentId, now, m.cpu, mem, disk, m.rx, m.tx, m.load1);
        this.db.run('UPDATE agents SET last_seen=?, last_metrics=? WHERE id=?', now, JSON.stringify({ ...m, ts: now, mem, disk }), agentId);
        this.alerts.onMetrics(agentId, { cpu: m.cpu, mem, disk });
        break;
      }
      case 'docker':
        this.db.run('UPDATE agents SET docker=?, last_seen=? WHERE id=?', JSON.stringify(m.containers ?? null), now, agentId);
        if (m.containers) this.alerts.onDocker(agentId, m.containers);
        break;
      case 'security':
        this.ingestSecurity(agentId, m);
        break;
      case 'events':
        for (const e of m.events ?? []) {
          this.db.run('INSERT INTO events(agent_id,ts,type,severity,message,data) VALUES(?,?,?,?,?,?)', agentId, e.ts ?? now, e.type, e.severity ?? 'info', e.message, JSON.stringify(e.data ?? {}));
          this.rules.onEvent(agentId, { type: String(e.type), severity: String(e.severity ?? 'info'), message: String(e.message), data: e.data ?? {} });
        }
        break;
      case 'result': {
        const p = this.pending.get(m.id);
        if (!p) break;
        clearTimeout(p.timer);
        this.pending.delete(m.id);
        if (m.ok) p.resolve(m.data);
        else p.reject(new Error(m.error ?? 'command failed'));
        break;
      }
    }
  }

  private ingestSecurity(agentId: number, m: any) {
    const now = Date.now();
    const list: { checkId: string; severity: string; title: string; detail?: string; fix?: string }[] = m.findings ?? [];
    this.db.tx(() => {
      for (const f of list) {
        const prev = this.db.get('SELECT id,status FROM findings WHERE agent_id=? AND check_id=?', agentId, f.checkId);
        if (!prev) {
          this.db.run('INSERT INTO findings(agent_id,check_id,severity,title,detail,first_seen,last_seen,fix) VALUES(?,?,?,?,?,?,?,?)', agentId, f.checkId, f.severity, f.title, f.detail ?? '', now, now, f.fix ?? null);
          this.alerts.onFinding(agentId, f.severity, f.title);
        } else {
          const status = prev.status === 'resolved' ? 'open' : prev.status;
          this.db.run('UPDATE findings SET severity=?, title=?, detail=?, status=?, last_seen=?, fix=? WHERE id=?', f.severity, f.title, f.detail ?? '', status, now, f.fix ?? null, prev.id);
        }
      }
      const keep = new Set(list.map((f) => f.checkId));
      for (const r of this.db.all("SELECT id,check_id FROM findings WHERE agent_id=? AND status!='resolved'", agentId)) {
        if (!keep.has(r.check_id)) this.db.run("UPDATE findings SET status='resolved', last_seen=? WHERE id=?", now, r.id);
      }
      this.db.run('UPDATE agents SET ports=?, last_seen=? WHERE id=?', JSON.stringify(m.ports ?? []), now, agentId);
    });
  }
}
