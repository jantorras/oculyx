import type { Db } from './db.ts';
import { RULES, ruleConfig, type Sev } from './rules.ts';

/**
 * Alert policy per host: global defaults, then the host's profile, then the host's own exceptions
 * (the same idea as Zabbix templates with per-host overrides). Every layer is sparse: only what it sets.
 */
export const SEVERITIES: Sev[] = ['critical', 'high', 'medium', 'low'];

/** Alerts that do not come from a detection event: resource limits, availability, containers, findings. */
export interface BuiltinDef { id: string; group: 'resources' | 'availability'; severity: Sev; enabled: boolean }
export const BUILTIN: BuiltinDef[] = [
  { id: 'cpu_high', group: 'resources', severity: 'medium', enabled: true },
  { id: 'mem_high', group: 'resources', severity: 'medium', enabled: true },
  { id: 'disk_high', group: 'resources', severity: 'high', enabled: true },
  { id: 'offline', group: 'availability', severity: 'high', enabled: true },
  { id: 'container_crashed', group: 'availability', severity: 'high', enabled: true },
  { id: 'finding', group: 'availability', severity: 'high', enabled: true },
];

/** Optional security checks the agent runs (Wazuh-style modules). Arrays add up across layers; switches and numbers override. */
export interface ChecksConfig {
  fim: { enabled: boolean; paths: string[]; exclude: string[]; everyMin: number };
  cve: { enabled: boolean };
  sca: { enabled: boolean };
  logs: { enabled: boolean; presets: string[]; custom: { name: string; file: string; pattern: string; severity: string }[] };
  inventory: { enabled: boolean };
}
export type ChecksPatch = { [K in keyof ChecksConfig]?: Partial<ChecksConfig[K]> };
export const DEFAULT_CHECKS: ChecksConfig = {
  fim: { enabled: true, paths: [], exclude: [], everyMin: 10 },
  cve: { enabled: true },
  sca: { enabled: true },
  logs: { enabled: false, presets: [], custom: [] },
  inventory: { enabled: true },
};
export const LOG_PRESET_IDS = ['web_attacks', 'oom', 'disk_errors'];

function cleanChecks(raw: any): ChecksPatch | undefined {
  if (!raw || typeof raw !== 'object') return undefined;
  const out: ChecksPatch = {};
  const bool = (v: unknown) => (typeof v === 'boolean' ? v : undefined);
  const strs = (v: unknown, max: number, len: number, ok: (s: string) => boolean) =>
    Array.isArray(v) ? [...new Set(v.map((x) => String(x).trim()).filter((s) => s && s.length <= len && ok(s)))].slice(0, max) : undefined;
  const set = <K extends keyof ChecksConfig>(k: K, v: Partial<ChecksConfig[K]>) => {
    const clean = Object.fromEntries(Object.entries(v).filter(([, x]) => x !== undefined));
    if (Object.keys(clean).length) out[k] = clean as any;
  };
  set('fim', {
    enabled: bool(raw.fim?.enabled),
    paths: strs(raw.fim?.paths, 50, 200, (s) => s.startsWith('/') && !s.includes('..') && s.length > 1),
    exclude: strs(raw.fim?.exclude, 30, 100, () => true),
    everyMin: num(raw.fim?.everyMin, 1, 1440),
  });
  set('cve', { enabled: bool(raw.cve?.enabled) });
  set('sca', { enabled: bool(raw.sca?.enabled) });
  set('inventory', { enabled: bool(raw.inventory?.enabled) });
  const custom = Array.isArray(raw.logs?.custom)
    ? raw.logs.custom
        .map((c: any) => ({ name: String(c?.name ?? '').trim().slice(0, 60), file: String(c?.file ?? '').trim(), pattern: String(c?.pattern ?? '').trim(), severity: SEVERITIES.includes(c?.severity) ? c.severity : 'medium' }))
        .filter((c: any) => c.name && c.file.startsWith('/') && !c.file.includes('..') && c.file.length <= 200 && c.pattern && c.pattern.length <= 200 && validRegex(c.pattern))
        .slice(0, 20)
    : undefined;
  set('logs', { enabled: bool(raw.logs?.enabled), presets: strs(raw.logs?.presets, 10, 40, (s) => LOG_PRESET_IDS.includes(s)), custom });
  return Object.keys(out).length ? out : undefined;
}
function validRegex(p: string) {
  try {
    new RegExp(p, 'i');
    return true;
  } catch {
    return false;
  }
}
const union = <T>(a: T[], b: T[] | undefined, key: (x: T) => string = String) => {
  const seen = new Set<string>();
  return [...a, ...(b ?? [])].filter((x) => !seen.has(key(x)) && seen.add(key(x)));
};
export function mergeChecks(base: ChecksConfig, p?: ChecksPatch): ChecksConfig {
  if (!p) return base;
  return {
    fim: { enabled: p.fim?.enabled ?? base.fim.enabled, paths: union(base.fim.paths, p.fim?.paths), exclude: union(base.fim.exclude, p.fim?.exclude), everyMin: p.fim?.everyMin ?? base.fim.everyMin },
    cve: { enabled: p.cve?.enabled ?? base.cve.enabled },
    sca: { enabled: p.sca?.enabled ?? base.sca.enabled },
    inventory: { enabled: p.inventory?.enabled ?? base.inventory.enabled },
    logs: { enabled: p.logs?.enabled ?? base.logs.enabled, presets: union(base.logs.presets, p.logs?.presets), custom: union(base.logs.custom, p.logs?.custom, (c) => c.name) },
  };
}

export interface PolicyConfig {
  checks?: ChecksPatch;
  thresholds?: { cpu?: number; mem?: number; disk?: number };
  /** consecutive readings above a limit before alerting */
  samples?: number;
  minSeverity?: string;
  rules?: Record<string, { enabled?: boolean; severity?: Sev }>;
}

export interface Policy {
  thresholds: { cpu: number; mem: number; disk: number };
  samples: number;
  minSeverity: string;
  rules: Record<string, { enabled: boolean; severity: Sev; severitySet: boolean }>;
  checks: ChecksConfig;
}

const num = (v: unknown, lo: number, hi: number) => (Number.isFinite(Number(v)) && Number(v) >= lo && Number(v) <= hi ? Math.round(Number(v)) : undefined);

/** Drops anything invalid so stored configs are always safe to merge. */
export function cleanConfig(raw: any): PolicyConfig {
  const out: PolicyConfig = {};
  const t: NonNullable<PolicyConfig['thresholds']> = {};
  for (const k of ['cpu', 'mem', 'disk'] as const) {
    const v = num(raw?.thresholds?.[k], 1, 100);
    if (v !== undefined) t[k] = v;
  }
  if (Object.keys(t).length) out.thresholds = t;
  const s = num(raw?.samples, 1, 20);
  if (s !== undefined) out.samples = s;
  if (['info', 'low', 'medium', 'high', 'critical'].includes(raw?.minSeverity)) out.minSeverity = raw.minSeverity;
  const known = new Set([...RULES.map((r) => r.id), ...BUILTIN.map((b) => b.id)]);
  const rules: NonNullable<PolicyConfig['rules']> = {};
  for (const [id, v] of Object.entries<any>(raw?.rules ?? {})) {
    if (!known.has(id)) continue;
    const r: { enabled?: boolean; severity?: Sev } = {};
    if (typeof v?.enabled === 'boolean') r.enabled = v.enabled;
    if (SEVERITIES.includes(v?.severity)) r.severity = v.severity;
    if (Object.keys(r).length) rules[id] = r;
  }
  if (Object.keys(rules).length) out.rules = rules;
  const checks = cleanChecks(raw?.checks);
  if (checks) out.checks = checks;
  return out;
}

function globalPolicy(db: Db): Policy {
  const th = { cpu: 90, mem: 90, disk: 90 };
  for (const k of ['cpu', 'mem', 'disk'] as const) {
    const v = Number(db.setting(`threshold.${k}`));
    if (v > 0 && v <= 100) th[k] = v;
  }
  const rules: Policy['rules'] = {};
  for (const r of RULES) {
    const c = ruleConfig(db, r);
    rules[r.id] = { enabled: c.enabled, severity: c.severity, severitySet: db.setting(`rule.${r.id}.severity`) !== '' };
  }
  for (const b of BUILTIN) {
    const en = db.setting(`rule.${b.id}.enabled`);
    const sv = db.setting(`rule.${b.id}.severity`) as Sev;
    rules[b.id] = { enabled: en === '' ? b.enabled : en === '1', severity: SEVERITIES.includes(sv) ? sv : b.severity, severitySet: SEVERITIES.includes(sv) };
  }
  return { thresholds: th, samples: 3, minSeverity: db.setting('notify.min_severity', 'low'), rules, checks: DEFAULT_CHECKS };
}

export function applyConfig(base: Policy, cfg: PolicyConfig): Policy {
  const rules = { ...base.rules };
  for (const [id, v] of Object.entries(cfg.rules ?? {})) {
    const cur = rules[id];
    if (!cur) continue;
    rules[id] = { enabled: v.enabled ?? cur.enabled, severity: v.severity ?? cur.severity, severitySet: cur.severitySet || v.severity !== undefined };
  }
  return { thresholds: { ...base.thresholds, ...cfg.thresholds }, samples: cfg.samples ?? base.samples, minSeverity: cfg.minSeverity ?? base.minSeverity, rules, checks: mergeChecks(base.checks, cfg.checks) };
}

const parse = (s: unknown): PolicyConfig => {
  try {
    return cleanConfig(JSON.parse(String(s ?? '{}')));
  } catch {
    return {};
  }
};

export interface HostPolicy {
  profileId: number | null;
  profileName: string | null;
  overrides: PolicyConfig;
  /** global defaults */
  base: Policy;
  /** base plus the profile: what the host inherits */
  inherited: Policy;
  /** what actually applies */
  effective: Policy;
  mutedUntil: number;
}

export class Policies {
  private db: Db;
  private cache = new Map<number, { at: number; p: HostPolicy }>();
  constructor(db: Db) {
    this.db = db;
    this.seed();
  }

  invalidate() {
    this.cache.clear();
  }

  /** Reusable starting points, created once so the screen is not empty. Editable and removable. */
  private seed() {
    if (this.db.setting('profiles.seeded') === '1') return;
    const mk = (name: string, description: string, config: PolicyConfig) => this.db.run('INSERT INTO profiles(name,description,config,created) VALUES(?,?,?,?)', name, description, JSON.stringify(config), Date.now());
    mk('Production (strict)', 'Tighter limits and extra access alerts for servers that matter.', {
      thresholds: { cpu: 85, mem: 85, disk: 85 },
      rules: { ssh_off_hours: { enabled: true }, ssh_password_login: { enabled: true, severity: 'medium' }, su_to_root: { enabled: true } },
    });
    mk('Bastion / SSH gateway', 'Everyone comes in here, so every unusual login counts.', {
      rules: { ssh_new_source: { severity: 'high' }, ssh_root_login: { severity: 'critical' }, ssh_password_login: { enabled: true, severity: 'high' }, ssh_off_hours: { enabled: true }, su_to_root: { enabled: true } },
    });
    mk('Database', 'Disk and memory matter most; new listening ports are suspicious.', {
      thresholds: { cpu: 85, mem: 92, disk: 80 },
      rules: { port_opened: { severity: 'high' } },
    });
    mk('Docker host', 'Containers open ports and restart often, so fewer port alerts and more room on CPU.', {
      thresholds: { cpu: 95, mem: 90, disk: 85 },
      rules: { port_opened: { enabled: false }, container_crashed: { severity: 'high' } },
    });
    mk('Dev and test (quiet)', 'Only what is serious: high limits, longer confirmation, fewer low-value alerts.', {
      thresholds: { cpu: 95, mem: 95, disk: 92 },
      samples: 6,
      minSeverity: 'high',
      rules: { offline: { severity: 'medium' }, ssh_new_source: { enabled: false }, port_opened: { enabled: false } },
    });
    this.db.setSetting('profiles.seeded', '1');
  }

  of(agentId: number): HostPolicy {
    const hit = this.cache.get(agentId);
    if (hit && Date.now() - hit.at < 5000) return hit.p;
    const row = this.db.get('SELECT profile_id, overrides, muted_until FROM agents WHERE id=?', agentId);
    const base = globalPolicy(this.db);
    const prof = row?.profile_id ? this.db.get('SELECT id,name,config FROM profiles WHERE id=?', row.profile_id) : undefined;
    const inherited = prof ? applyConfig(base, parse(prof.config)) : base;
    const overrides = parse(row?.overrides);
    const p: HostPolicy = {
      profileId: prof?.id ?? null,
      profileName: prof?.name ?? null,
      overrides,
      base,
      inherited,
      effective: applyConfig(inherited, overrides),
      mutedUntil: Number(row?.muted_until ?? 0),
    };
    this.cache.set(agentId, { at: Date.now(), p });
    return p;
  }

  muted(agentId: number): boolean {
    return this.of(agentId).mutedUntil > Date.now();
  }
}
