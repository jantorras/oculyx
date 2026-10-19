import type { Db } from './db.ts';
import { notify } from './notify.ts';

export const OFFLINE_AFTER_MS = 45_000;

export const DEFAULT_THRESHOLDS = { cpu: 90, mem: 90, disk: 90 };

export function thresholds(db: Db) {
  const out = { ...DEFAULT_THRESHOLDS };
  for (const k of Object.keys(out) as (keyof typeof out)[]) {
    const v = Number(db.setting(`threshold.${k}`));
    if (v > 0 && v <= 100) out[k] = v;
  }
  return out;
}

export class Alerts {
  /** consecutive samples above threshold, per agent+rule, to avoid flapping on spikes */
  private streak = new Map<string, number>();
  private db: Db;
  constructor(db: Db) {
    this.db = db;
  }

  private agentName(id: number): string {
    return this.db.get('SELECT name FROM agents WHERE id=?', id)?.name ?? `#${id}`;
  }

  raise(agentId: number, rule: string, severity: string, message: string) {
    const open = this.db.get("SELECT id FROM alerts WHERE agent_id=? AND rule=? AND state!='closed'", agentId, rule);
    if (open) return;
    this.db.run('INSERT INTO alerts(agent_id,rule,severity,message,opened) VALUES(?,?,?,?,?)', agentId, rule, severity, message, Date.now());
    void notify(this.db, { severity, title: `${this.agentName(agentId)}: ${rule}`, body: message });
  }

  resolve(agentId: number, rule: string) {
    const r = this.db.run("UPDATE alerts SET state='closed', closed=? WHERE agent_id=? AND rule=? AND state!='closed'", Date.now(), agentId, rule);
    if (r.changes) void notify(this.db, { severity: 'ok', title: `${this.agentName(agentId)}: ${rule}`, body: 'resolved' });
  }

  private check(agentId: number, rule: string, value: number, limit: number, severity: string, label: string) {
    const key = `${agentId}:${rule}`;
    if (value >= limit) {
      const n = (this.streak.get(key) ?? 0) + 1;
      this.streak.set(key, n);
      if (n >= 3) this.raise(agentId, rule, severity, `${label} ${value.toFixed(0)}% ≥ ${limit}%`);
    } else {
      this.streak.set(key, 0);
      if (value < limit - 5) this.resolve(agentId, rule);
    }
  }

  onMetrics(agentId: number, m: { cpu: number; mem: number; disk: number }) {
    const t = thresholds(this.db);
    this.check(agentId, 'cpu_high', m.cpu, t.cpu, 'medium', 'CPU');
    this.check(agentId, 'mem_high', m.mem, t.mem, 'medium', 'Memory');
    this.check(agentId, 'disk_high', m.disk, t.disk, 'high', 'Disk');
    this.resolve(agentId, 'offline');
  }

  onDocker(agentId: number, containers: { name: string; state: string; exitCode?: number }[]) {
    const crashed = containers.filter((c) => c.state === 'exited' && (c.exitCode ?? 0) !== 0);
    if (crashed.length) this.raise(agentId, 'container_crashed', 'high', crashed.map((c) => `${c.name} (exit ${c.exitCode})`).join(', '));
    else this.resolve(agentId, 'container_crashed');
  }

  onFinding(agentId: number, severity: string, title: string) {
    if (severity === 'critical') this.raise(agentId, `finding:${title}`.slice(0, 80), 'critical', title);
  }

  sweepOffline() {
    const cutoff = Date.now() - OFFLINE_AFTER_MS;
    for (const a of this.db.all('SELECT id,last_seen FROM agents')) {
      if (a.last_seen < cutoff) this.raise(a.id, 'offline', 'high', 'No heartbeat from agent');
    }
  }
}
