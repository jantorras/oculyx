import type { Db } from './db.ts';
import { createHash } from 'node:crypto';
import { notify } from './notify.ts';
import { sevRank } from './rules.ts';
import { alertInfo } from './alertinfo.ts';
import type { Policies } from './policy.ts';

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
  policies: Policies;
  constructor(db: Db, policies: Policies) {
    this.db = db;
    this.policies = policies;
  }

  private agentName(id: number): string {
    return this.db.get('SELECT name FROM agents WHERE id=?', id)?.name ?? `#${id}`;
  }

  raise(agentId: number, rule: string, severity: string, message: string) {
    const open = this.db.get("SELECT id FROM alerts WHERE agent_id=? AND rule=? AND state!='closed'", agentId, rule);
    if (open) return;
    this.db.run('INSERT INTO alerts(agent_id,rule,severity,message,opened) VALUES(?,?,?,?,?)', agentId, rule, severity, message, Date.now());
    this.send(agentId, rule, severity, message);
  }

  /** set by main: adds a short AI explanation to important alerts */
  explain?: (a: { agentId: number; host: string; rule: string; severity: string; message: string }) => Promise<string>;

  private send(agentId: number, rule: string, severity: string, message: string) {
    const pol = this.policies.of(agentId);
    if (sevRank(severity) < sevRank(pol.effective.minSeverity)) return;
    // maintenance window: stay quiet, except critical unless the admin chose otherwise
    if (pol.mutedUntil > Date.now() && !(severity === 'critical' && this.db.setting('maintenance.critical_breaks', '1') === '1')) return;
    const host = this.agentName(agentId);
    void (async () => {
      const why = this.explain ? await this.explain({ agentId, host, rule, severity, message }) : '';
      const lang = this.db.setting('notify.language') || this.db.setting('ai.language') || 'en';
      const info = alertInfo(rule, lang);
      const body = [message, info && `${info.meaning}\n\u2192 ${info.todo}`, why].filter(Boolean).join('\n\n');
      await notify(this.db, { severity, title: `${host}: ${rule.split(':')[0].replaceAll('_', ' ')}`, body,
        alert: { severity, host, rule, message, why, guidance: info ? `${info.meaning}\n→ ${info.todo}` : undefined },
      });
    })();
  }

  /** Alert for a one-off security event. One open alert per rule+key, so repeated noise does not pile up. */
  raiseEvent(agentId: number, ruleId: string, severity: string, message: string, key: string) {
    const rule = `${ruleId}:${createHash('sha1').update(key).digest('hex').slice(0, 8)}`;
    const open = this.db.get("SELECT id FROM alerts WHERE agent_id=? AND rule=? AND state!='closed'", agentId, rule);
    if (open) return;
    this.db.run('INSERT INTO alerts(agent_id,rule,severity,message,opened) VALUES(?,?,?,?,?)', agentId, rule, severity, message, Date.now());
    this.send(agentId, rule, severity, message);
  }

  resolve(agentId: number, rule: string) {
    const r = this.db.run("UPDATE alerts SET state='closed', closed=? WHERE agent_id=? AND rule=? AND state!='closed'", Date.now(), agentId, rule);
    if (r.changes) void notify(this.db, { severity: 'ok', title: `${this.agentName(agentId)}: ${rule}`, body: 'resolved',
      alert: { severity: 'ok', host: this.agentName(agentId), rule, message: 'resolved' },
    });
  }

  private check(agentId: number, rule: 'cpu_high' | 'mem_high' | 'disk_high', value: number, label: string) {
    const key = `${agentId}:${rule}`;
    const p = this.policies.of(agentId).effective;
    const limit = p.thresholds[rule.slice(0, -5) as 'cpu' | 'mem' | 'disk'];
    if (!p.rules[rule].enabled) {
      this.streak.set(key, 0);
      return;
    }
    if (value >= limit) {
      const n = (this.streak.get(key) ?? 0) + 1;
      this.streak.set(key, n);
      if (n >= p.samples) this.raise(agentId, rule, p.rules[rule].severity, `${label} ${value.toFixed(0)}% ≥ ${limit}%`);
    } else {
      this.streak.set(key, 0);
      if (value < limit - 5) this.resolve(agentId, rule);
    }
  }

  onMetrics(agentId: number, m: { cpu: number; mem: number; disk: number }) {
    this.check(agentId, 'cpu_high', m.cpu, 'CPU');
    this.check(agentId, 'mem_high', m.mem, 'Memory');
    this.check(agentId, 'disk_high', m.disk, 'Disk');
    this.resolve(agentId, 'offline');
  }

  onDocker(agentId: number, containers: { name: string; state: string; exitCode?: number }[]) {
    const crashed = containers.filter((c) => c.state === 'exited' && (c.exitCode ?? 0) !== 0);
    const rule = this.policies.of(agentId).effective.rules.container_crashed;
    if (crashed.length && rule.enabled) this.raise(agentId, 'container_crashed', rule.severity, crashed.map((c) => `${c.name} (exit ${c.exitCode})`).join(', '));
    else this.resolve(agentId, 'container_crashed');
  }

  onFinding(agentId: number, severity: string, title: string) {
    const rule = this.policies.of(agentId).effective.rules.finding;
    if (rule.enabled && sevRank(severity) >= sevRank(rule.severity)) this.raise(agentId, `finding:${title}`.slice(0, 80), severity, title);
  }

  sweepOffline() {
    const cutoff = Date.now() - OFFLINE_AFTER_MS;
    for (const a of this.db.all('SELECT id,last_seen FROM agents')) {
      const rule = this.policies.of(a.id).effective.rules.offline;
      if (a.last_seen < cutoff && rule.enabled) this.raise(a.id, 'offline', rule.severity, 'No heartbeat from agent');
    }
  }
}
