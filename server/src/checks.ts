import { createHash } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import type { Db } from './db.ts';
import type { Hub } from './hub.ts';
import type { Policies } from './policy.ts';

/** Results of the optional security checks (configuration audit, inventory, vulnerabilities) and their panel API. */

interface Emit {
  (agentId: number, type: string, severity: string, message: string, data: Record<string, unknown>): void;
}

const OSV = 'https://api.osv.dev/v1';
const sha = (s: string) => createHash('sha1').update(s).digest('hex').slice(0, 10);

/** CVSS v3 base score from a vector string, or null if it cannot be read. */
export function cvss3(vector: string): number | null {
  const m = Object.fromEntries(vector.split('/').slice(1).map((p) => p.split(':')));
  const AV = ({ N: 0.85, A: 0.62, L: 0.55, P: 0.2 } as any)[m.AV];
  const AC = ({ L: 0.77, H: 0.44 } as any)[m.AC];
  const UI = ({ N: 0.85, R: 0.62 } as any)[m.UI];
  const changed = m.S === 'C';
  const PR = (changed ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 } as any)[m.PR];
  const cia = (k: string) => ({ H: 0.56, L: 0.22, N: 0 } as any)[m[k]];
  const [C, I, A] = [cia('C'), cia('I'), cia('A')];
  if ([AV, AC, UI, PR, C, I, A].some((x) => x === undefined)) return null;
  const iss = 1 - (1 - C) * (1 - I) * (1 - A);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  if (impact <= 0) return 0;
  const expl = 8.22 * AV * AC * PR * UI;
  const raw = Math.min(changed ? 1.08 * (impact + expl) : impact + expl, 10);
  return Math.ceil(raw * 10) / 10;
}
const band = (score: number) => (score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : score > 0 ? 'low' : 'unknown');

/** The OSV database groups packages by ecosystem; map the host's OS to its name there. */
export function ecosystem(os: { id: string; version: string }): string | null {
  const major = os.version.split('.')[0];
  switch (os.id) {
    case 'debian': return major ? `Debian:${major}` : null;
    case 'ubuntu': return /^\d\d\.04$/.test(os.version) && Number(major) % 2 === 0 ? `Ubuntu:${os.version}:LTS` : `Ubuntu:${os.version}`;
    case 'alpine': return `Alpine:v${os.version.split('.').slice(0, 2).join('.')}`;
    case 'rocky': return `Rocky Linux:${major}`;
    case 'almalinux': return `AlmaLinux:${major}`;
    default: return null;
  }
}

export class Checks {
  private db: Db;
  private hub: Hub;
  private emit: Emit;
  private scanning = new Set<number>();
  constructor(db: Db, hub: Hub, emit: Emit) {
    this.db = db;
    this.hub = hub;
    this.emit = emit;
    db.raw.exec(`
      CREATE TABLE IF NOT EXISTS sca (agent_id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, score INTEGER NOT NULL, data TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS inventory (agent_id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, data TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS vulns (agent_id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, status TEXT NOT NULL, data TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS vuln_cache (id TEXT PRIMARY KEY, ts INTEGER NOT NULL, data TEXT NOT NULL);
    `);
  }

  ingestSca(agentId: number, m: any) {
    if (!Array.isArray(m.controls)) return;
    const controls = m.controls.slice(0, 200).map((c: any) => ({
      id: String(c.id), group: String(c.group), severity: String(c.severity), title: String(c.title).slice(0, 200), why: String(c.why ?? '').slice(0, 300),
      fix: String(c.fix ?? '').slice(0, 300), status: ['pass', 'fail', 'na'].includes(c.status) ? c.status : 'na', detail: c.detail ? String(c.detail).slice(0, 200) : undefined,
    }));
    const ts = Date.now();
    this.db.run('INSERT INTO sca(agent_id,ts,score,data) VALUES(?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET ts=excluded.ts, score=excluded.score, data=excluded.data', agentId, ts, Math.round(Number(m.score) || 0), JSON.stringify(controls));
  }

  ingestInventory(agentId: number, m: any) {
    const packages: [string, string, string][] = (Array.isArray(m.packages) ? m.packages : []).slice(0, 20000).map((p: any) => [String(p[0]).slice(0, 120), String(p[1]).slice(0, 120), String(p[2] ?? p[0]).slice(0, 120)]);
    const services: string[] = (Array.isArray(m.services) ? m.services : []).slice(0, 500).map((s: any) => String(s).slice(0, 80));
    const os = { id: String(m.os?.id ?? '').slice(0, 40), version: String(m.os?.version ?? '').slice(0, 40), name: String(m.os?.name ?? '').slice(0, 100) };
    const prev = this.db.get('SELECT data FROM inventory WHERE agent_id=?', agentId);
    this.db.run('INSERT INTO inventory(agent_id,ts,data) VALUES(?,?,?) ON CONFLICT(agent_id) DO UPDATE SET ts=excluded.ts, data=excluded.data', agentId, Date.now(), JSON.stringify({ os, packages, services }));
    if (prev) {
      try {
        const old = JSON.parse(prev.data) as { packages: [string, string, string][]; services: string[] };
        const oldNames = new Set(old.packages.map((p) => p[0]));
        const newNames = new Set(packages.map((p) => p[0]));
        const added = [...newNames].filter((n) => !oldNames.has(n));
        const removed = [...oldNames].filter((n) => !newNames.has(n));
        const svcAdded = services.filter((s) => !old.services.includes(s));
        const svcRemoved = old.services.filter((s) => !services.includes(s));
        const parts: string[] = [];
        if (added.length) parts.push(`installed: ${added.slice(0, 4).join(', ')}${added.length > 4 ? ` (+${added.length - 4})` : ''}`);
        if (removed.length) parts.push(`removed: ${removed.slice(0, 4).join(', ')}${removed.length > 4 ? ` (+${removed.length - 4})` : ''}`);
        if (svcAdded.length) parts.push(`services enabled: ${svcAdded.join(', ')}`);
        if (svcRemoved.length) parts.push(`services disabled: ${svcRemoved.join(', ')}`);
        if (parts.length && added.length + removed.length < 400) this.emit(agentId, 'inventory_changed', 'low', parts.join('; '), { added, removed, svcAdded, svcRemoved, key: sha(parts.join('|')) });
      } catch {
        /* unreadable previous snapshot: just keep the new one */
      }
    }
    if (this.hub.policies.of(agentId).effective.checks.cve.enabled) void this.scanCves(agentId).catch(() => {});
  }

  /** Looks the installed packages up in osv.dev. Only package names and versions leave the server. */
  async scanCves(agentId: number): Promise<void> {
    if (this.scanning.has(agentId)) return;
    this.scanning.add(agentId);
    try {
      const row = this.db.get('SELECT data FROM inventory WHERE agent_id=?', agentId);
      if (!row) return;
      const inv = JSON.parse(row.data) as { os: { id: string; version: string }; packages: [string, string, string][] };
      const eco = ecosystem(inv.os);
      const save = (status: string, data: object): void => {
        this.db.run('INSERT INTO vulns(agent_id,ts,status,data) VALUES(?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET ts=excluded.ts, status=excluded.status, data=excluded.data', agentId, Date.now(), status, JSON.stringify(data));
      };
      if (!eco) return save('unsupported', { os: inv.os, items: [] });

      // one query per distinct source package and version
      const uniq = new Map<string, { name: string; version: string; pkgs: string[] }>();
      for (const [name, version, src] of inv.packages) {
        const k = `${src}@${version}`;
        const e = uniq.get(k) ?? { name: src, version, pkgs: [] };
        e.pkgs.push(name);
        uniq.set(k, e);
      }
      const queries = [...uniq.values()];
      const found: { q: (typeof queries)[number]; ids: string[] }[] = [];
      for (let i = 0; i < queries.length; i += 800) {
        const chunk = queries.slice(i, i + 800);
        const r = await fetch(`${OSV}/querybatch`, {
          method: 'POST', headers: { 'content-type': 'application/json' }, signal: AbortSignal.timeout(30_000),
          body: JSON.stringify({ queries: chunk.map((q) => ({ package: { name: q.name, ecosystem: eco }, version: q.version })) }),
        });
        if (!r.ok) return save('error', { eco, error: `osv.dev answered ${r.status}`, items: [] });
        const j = (await r.json()) as { results: { vulns?: { id: string }[] }[] };
        j.results.forEach((res, k) => res.vulns?.length && found.push({ q: chunk[k], ids: res.vulns.map((v) => v.id) }));
      }

      // severity and summary of each distinct vulnerability, cached for a week
      const ids = [...new Set(found.flatMap((f) => f.ids))];
      const details = new Map<string, any>();
      const need: string[] = [];
      for (const id of ids) {
        const c = this.db.get('SELECT ts,data FROM vuln_cache WHERE id=?', id);
        if (c && Date.now() - c.ts < 7 * 86400_000) details.set(id, JSON.parse(c.data));
        else need.push(id);
      }
      let fetched = 0;
      const worker = async () => {
        for (;;) {
          const id = need.shift();
          if (!id || fetched >= 250) return;
          fetched++;
          try {
            const r = await fetch(`${OSV}/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(15_000) });
            if (!r.ok) continue;
            const d = summarize(await r.json());
            details.set(id, d);
            this.db.run('INSERT INTO vuln_cache(id,ts,data) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET ts=excluded.ts, data=excluded.data', id, Date.now(), JSON.stringify(d));
          } catch {
            /* retry next scan */
          }
        }
      };
      await Promise.all([worker(), worker(), worker(), worker()]);

      const items = found.flatMap((f) => f.ids.map((id) => {
        const d = details.get(id) ?? { severity: 'unknown', summary: '', aliases: [], fixed: {} };
        return { id, aliases: d.aliases, pkg: f.q.pkgs[0], version: f.q.version, severity: d.severity, summary: d.summary, fixed: d.fixed[f.q.name] ?? d.fixed[''] ?? '' };
      }));
      const rank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
      items.sort((a, b) => rank[b.severity] - rank[a.severity] || a.pkg.localeCompare(b.pkg));
      const old = this.db.get('SELECT data FROM vulns WHERE agent_id=?', agentId);
      const seen = new Set<string>((old ? (JSON.parse(old.data).items ?? []) : []).map((i: any) => i.id));
      save('ok', { eco, os: inv.os, items: items.slice(0, 1500), packages: inv.packages.length });
      const fresh = items.filter((i) => (i.severity === 'critical' || i.severity === 'high') && !seen.has(i.id));
      if (fresh.length) {
        const top = fresh[0];
        this.emit(agentId, 'vuln', top.severity, `${fresh.length} new high-severity vulnerabilit${fresh.length === 1 ? 'y' : 'ies'}, e.g. ${top.aliases[0] ?? top.id} in ${top.pkg}${top.fixed ? ` (fixed in ${top.fixed})` : ''}`, { count: fresh.length, ids: fresh.slice(0, 20).map((i) => i.id), key: sha(fresh.map((i) => i.id).sort().join(',')) });
      }
    } catch (e) {
      this.db.run('INSERT INTO vulns(agent_id,ts,status,data) VALUES(?,?,?,?) ON CONFLICT(agent_id) DO UPDATE SET ts=excluded.ts, status=excluded.status, data=excluded.data', agentId, Date.now(), 'error', JSON.stringify({ error: (e as Error).message, items: [] }));
    } finally {
      this.scanning.delete(agentId);
    }
  }
}

/** The few fields of an OSV record the panel needs. */
function summarize(v: any) {
  let severity = 'unknown';
  const db = String(v.database_specific?.severity ?? '').toLowerCase();
  if (['critical', 'high', 'medium', 'low'].includes(db)) severity = db;
  else if (db === 'moderate') severity = 'medium';
  else {
    for (const s of v.severity ?? []) {
      if (String(s.type).startsWith('CVSS_V3') && typeof s.score === 'string') {
        const n = cvss3(s.score);
        if (n !== null) severity = band(n);
      }
    }
  }
  const fixed: Record<string, string> = {};
  for (const a of v.affected ?? []) {
    for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) fixed[a.package?.name ?? ''] ??= String(e.fixed);
  }
  return {
    severity,
    summary: String(v.summary ?? v.details ?? '').split('\n')[0].slice(0, 200),
    aliases: (v.aliases ?? []).filter((a: string) => /^CVE-/.test(a)).slice(0, 4),
    fixed,
  };
}

interface Deps {
  db: Db;
  hub: Hub;
  checks: Checks;
  policies: Policies;
  viewer: { preHandler: any };
  admin: { preHandler: any };
  audit: (user: string | undefined, action: string, target: string | number | undefined, ip: string) => void;
}

const parse = (s: unknown, def: any) => {
  try {
    return JSON.parse(String(s));
  } catch {
    return def;
  }
};

export function registerChecksRoutes(app: FastifyInstance, { db, hub, checks, policies, viewer, admin, audit }: Deps) {
  app.get('/api/checks', viewer, async () => ({
    hosts: db.all('SELECT id,name,last_seen FROM agents ORDER BY name').map((a) => {
      const sca = db.get('SELECT ts,score,data FROM sca WHERE agent_id=?', a.id);
      const inv = db.get('SELECT ts,data FROM inventory WHERE agent_id=?', a.id);
      const vul = db.get('SELECT ts,status,data FROM vulns WHERE agent_id=?', a.id);
      const controls: any[] = sca ? parse(sca.data, []) : [];
      const items: any[] = vul ? parse(vul.data, {}).items ?? [] : [];
      const count = (s: string) => items.filter((i) => i.severity === s).length;
      const p = policies.of(a.id);
      return {
        id: a.id, name: a.name, online: hub.isOnline(a.id), profile: p.profileName, checks: p.effective.checks,
        sca: sca ? { ts: sca.ts, score: sca.score, fail: controls.filter((c) => c.status === 'fail').length, pass: controls.filter((c) => c.status === 'pass').length } : null,
        inventory: inv ? { ts: inv.ts, packages: (parse(inv.data, {}).packages ?? []).length, services: (parse(inv.data, {}).services ?? []).length } : null,
        vulns: vul ? { ts: vul.ts, status: vul.status, critical: count('critical'), high: count('high'), medium: count('medium'), low: count('low'), unknown: count('unknown'), error: parse(vul.data, {}).error ?? '' } : null,
      };
    }),
  }));

  app.get('/api/agents/:id/checks', viewer, async (req, reply) => {
    const id = Number((req.params as any).id);
    if (!db.get('SELECT 1 AS x FROM agents WHERE id=?', id)) return reply.code(404).send({ error: 'not_found' });
    const sca = db.get('SELECT ts,score,data FROM sca WHERE agent_id=?', id);
    const inv = db.get('SELECT ts,data FROM inventory WHERE agent_id=?', id);
    const vul = db.get('SELECT ts,status,data FROM vulns WHERE agent_id=?', id);
    const i = inv ? parse(inv.data, {}) : null;
    return {
      config: policies.of(id).effective.checks,
      sca: sca ? { ts: sca.ts, score: sca.score, controls: parse(sca.data, []) } : null,
      inventory: i ? { ts: inv!.ts, os: i.os, packages: i.packages.length, services: i.services } : null,
      vulns: vul ? { ts: vul.ts, status: vul.status, ...parse(vul.data, {}) } : null,
    };
  });

  app.post('/api/agents/:id/checks/run', admin, async (req, reply) => {
    const id = Number((req.params as any).id);
    const which = String((req.body as any)?.which ?? '');
    if (!['fim', 'sca', 'inventory', 'cve'].includes(which)) return reply.code(400).send({ error: 'bad_check' });
    if (!hub.isOnline(id)) return reply.code(409).send({ error: 'agent_offline' });
    if (which === 'cve') void checks.scanCves(id).catch(() => {});
    else await hub.command(id, 'checks.run', { which });
    audit(req.user?.username, 'checks.run', `${id}:${which}`, req.ip);
    return { ok: true };
  });
}
