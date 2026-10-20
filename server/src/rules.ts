import type { Db } from './db.ts';
import type { Alerts } from './alerts.ts';

export type Sev = 'critical' | 'high' | 'medium' | 'low' | 'info';
const ORDER: Sev[] = ['info', 'low', 'medium', 'high', 'critical'];
export const sevRank = (s: string) => Math.max(0, ORDER.indexOf(s as Sev));

export interface RuleDef {
  id: string;
  /** which agent event type feeds this rule */
  event: string;
  group: 'access' | 'accounts' | 'persistence' | 'processes' | 'system';
  severity: Sev;
  /** on unless the admin turns it off */
  enabled: boolean;
  /** extra condition on the event; return false to ignore it */
  when?: (e: AgentEventRow, ctx: Ctx) => boolean;
}

export interface AgentEventRow {
  type: string;
  severity: string;
  message: string;
  data: Record<string, any>;
}

interface Ctx {
  db: Db;
  agentId: number;
  now: number;
}

/** What each detection rule watches. Admins can switch rules off and change their severity under Settings. */
export const RULES: RuleDef[] = [
  { id: 'ssh_login_after_failures', event: 'ssh_login_after_failures', group: 'access', severity: 'critical', enabled: true },
  { id: 'ssh_root_login', event: 'ssh_login', group: 'access', severity: 'high', enabled: true, when: (e) => e.data.user === 'root' },
  { id: 'ssh_new_source', event: 'ssh_login', group: 'access', severity: 'medium', enabled: true, when: (e, c) => newSource(e, c) },
  { id: 'ssh_off_hours', event: 'ssh_login', group: 'access', severity: 'medium', enabled: false, when: (_e, c) => offHours(c) },
  { id: 'ssh_password_login', event: 'ssh_login', group: 'access', severity: 'low', enabled: false, when: (e) => e.data.method === 'password' },
  { id: 'ssh_bruteforce', event: 'ssh_failed', group: 'access', severity: 'medium', enabled: true },
  { id: 'su_to_root', event: 'su', group: 'access', severity: 'low', enabled: false, when: (e) => e.data.to === 'root' },
  { id: 'sudo_suspicious', event: 'sudo_suspicious', group: 'access', severity: 'high', enabled: true },
  { id: 'user_created', event: 'user_created', group: 'accounts', severity: 'high', enabled: true },
  { id: 'user_removed', event: 'user_removed', group: 'accounts', severity: 'medium', enabled: true },
  { id: 'privileged_group_added', event: 'privileged_group_added', group: 'accounts', severity: 'high', enabled: true },
  { id: 'ssh_key_added', event: 'ssh_key_added', group: 'accounts', severity: 'high', enabled: true },
  { id: 'persistence_changed', event: 'persistence_changed', group: 'persistence', severity: 'high', enabled: true },
  { id: 'suid_added', event: 'suid_added', group: 'persistence', severity: 'high', enabled: true },
  { id: 'fim_changed', event: 'fim', group: 'persistence', severity: 'high', enabled: true },
  { id: 'reverse_shell', event: 'reverse_shell', group: 'processes', severity: 'critical', enabled: true },
  { id: 'cryptominer', event: 'cryptominer', group: 'processes', severity: 'critical', enabled: true },
  { id: 'suspicious_process', event: 'suspicious_process', group: 'processes', severity: 'high', enabled: true },
  { id: 'unknown_kernel_module', event: 'unknown_kernel_module', group: 'processes', severity: 'high', enabled: true },
  { id: 'port_opened', event: 'port_opened', group: 'system', severity: 'medium', enabled: true },
  { id: 'rdp_failed', event: 'rdp_failed', group: 'access', severity: 'medium', enabled: true },
  { id: 'win_admin_change', event: 'win_admin_change', group: 'accounts', severity: 'high', enabled: true },
];

const LEARN_MS = 24 * 3600_000;

/** A (user, address) pair never seen before. During the first day it only learns, so a fresh install is not noisy. */
function newSource(e: AgentEventRow, c: Ctx): boolean {
  const user = String(e.data.user ?? ''), ip = String(e.data.ip ?? '');
  if (!user || !ip) return false;
  const known = c.db.get('SELECT 1 AS x FROM known_logins WHERE agent_id=? AND user=? AND ip=?', c.agentId, user, ip);
  if (known) {
    c.db.run('UPDATE known_logins SET last=?, n=n+1 WHERE agent_id=? AND user=? AND ip=?', c.now, c.agentId, user, ip);
    return false;
  }
  const first = c.db.get('SELECT MIN(first) AS f FROM known_logins WHERE agent_id=?', c.agentId)?.f as number | null;
  c.db.run('INSERT INTO known_logins(agent_id,user,ip,first,last,n) VALUES(?,?,?,?,?,1)', c.agentId, user, ip, c.now, c.now);
  return first !== null && c.now - first > LEARN_MS;
}

/** Logins outside the working window (setting detect.work_hours, e.g. "07-21", server local time). */
function offHours(c: Ctx): boolean {
  const m = c.db.setting('detect.work_hours', '07-21').match(/^(\d{1,2})-(\d{1,2})$/);
  if (!m) return false;
  const h = new Date(c.now).getHours();
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a <= b ? h < a || h >= b : h >= b && h < a;
}

export function ruleConfig(db: Db, r: RuleDef): { enabled: boolean; severity: Sev; custom: boolean } {
  const en = db.setting(`rule.${r.id}.enabled`);
  const sv = db.setting(`rule.${r.id}.severity`) as Sev;
  return { enabled: en === '' ? r.enabled : en === '1', severity: ORDER.includes(sv) ? sv : r.severity, custom: en !== '' || sv !== ('' as Sev) };
}

/** Turns agent events into alerts according to the detection rules. */
export class RuleEngine {
  private db: Db;
  private alerts: Alerts;
  constructor(db: Db, alerts: Alerts) {
    this.db = db;
    this.alerts = alerts;
  }

  onEvent(agentId: number, ev: AgentEventRow) {
    const now = Date.now();
    for (const r of RULES) {
      if (r.event !== ev.type) continue;
      const cfg = ruleConfig(this.db, r);
      // new_source must keep learning even when its alerts are switched off
      let hit = false;
      try {
        hit = r.when ? r.when(ev, { db: this.db, agentId, now }) : true;
      } catch {
        hit = false;
      }
      if (!cfg.enabled || !hit) continue;
      if (ev.severity === 'info' && ev.type !== 'ssh_login') continue; // e.g. package-managed file changes
      const severity = this.db.setting(`rule.${r.id}.severity`) ? cfg.severity : (ORDER.includes(ev.severity as Sev) && sevRank(ev.severity) > sevRank(cfg.severity) ? (ev.severity as Sev) : cfg.severity);
      this.alerts.raiseEvent(agentId, r.id, severity, ev.message, `${ev.data.user ?? ''}|${ev.data.ip ?? ev.data.file ?? ev.data.pid ?? ev.data.port ?? ev.data.module ?? ev.message}`);
    }
  }
}
