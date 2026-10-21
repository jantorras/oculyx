import type { FastifyInstance } from 'fastify';
import type { Db } from './db.ts';
import { RULES } from './rules.ts';
import { BUILTIN, cleanConfig, type Policies } from './policy.ts';

interface Deps {
  db: Db;
  policies: Policies;
  admin: { preHandler: any };
  audit: (user: string | undefined, action: string, target: string | number | undefined, ip: string) => void;
}

const ids = (v: unknown): number[] => (Array.isArray(v) ? v.map(Number).filter((n) => Number.isInteger(n) && n > 0).slice(0, 500) : []);

/** Alert profiles, per-host exceptions and maintenance windows. */
export function registerPolicyRoutes(app: FastifyInstance, { db, policies, admin, audit }: Deps) {
  const who = (req: any) => req.user?.username as string | undefined;

  app.get('/api/policies', admin, async () => {
    const base = policies.of(-1).base;
    const hosts = db.all('SELECT id,name,profile_id,overrides,muted_until,muted_reason,last_seen FROM agents ORDER BY name');
    return {
      profiles: db.all('SELECT id,name,description,config FROM profiles ORDER BY name').map((p) => ({
        id: p.id, name: p.name, description: p.description, config: cleanConfig(JSON.parse(p.config)),
        hosts: hosts.filter((h) => h.profile_id === p.id).map((h) => h.id),
      })),
      rules: [
        ...BUILTIN.map((b) => ({ id: b.id, group: b.group, defaultSeverity: b.severity })),
        ...RULES.map((r) => ({ id: r.id, group: r.group, defaultSeverity: r.severity })),
      ].map((r) => ({ ...r, global: { enabled: base.rules[r.id].enabled, severity: base.rules[r.id].severity } })),
      base: { thresholds: base.thresholds, samples: base.samples, minSeverity: base.minSeverity },
      hosts: hosts.map((h) => ({
        id: h.id, name: h.name, profileId: h.profile_id ?? null, overrides: Object.keys(cleanConfig(safe(h.overrides))).length,
        mutedUntil: h.muted_until && h.muted_until > Date.now() ? h.muted_until : 0, mutedReason: h.muted_reason ?? '',
      })),
      criticalBreaks: db.setting('maintenance.critical_breaks', '1') === '1',
    };
  });

  const saveProfile = (req: any, reply: any, id?: number) => {
    const b = (req.body ?? {}) as { name?: string; description?: string; config?: unknown };
    const name = String(b.name ?? '').trim().slice(0, 60);
    if (!name) return reply.code(400).send({ error: 'name_required' });
    const cfg = JSON.stringify(cleanConfig(b.config));
    try {
      if (id) db.run('UPDATE profiles SET name=?, description=?, config=? WHERE id=?', name, String(b.description ?? '').slice(0, 200), cfg, id);
      else id = db.run('INSERT INTO profiles(name,description,config,created) VALUES(?,?,?,?)', name, String(b.description ?? '').slice(0, 200), cfg, Date.now()).id;
    } catch {
      return reply.code(409).send({ error: 'name_taken' });
    }
    policies.invalidate();
    audit(who(req), id ? 'profile.save' : 'profile.create', name, req.ip);
    return { id };
  };
  app.post('/api/profiles', admin, async (req, reply) => saveProfile(req, reply));
  app.put('/api/profiles/:id', admin, async (req, reply) => {
    const id = Number((req.params as any).id);
    if (!db.get('SELECT 1 AS x FROM profiles WHERE id=?', id)) return reply.code(404).send({ error: 'not_found' });
    return saveProfile(req, reply, id);
  });
  app.delete('/api/profiles/:id', admin, async (req, reply) => {
    const id = Number((req.params as any).id);
    const p = db.get('SELECT name FROM profiles WHERE id=?', id);
    if (!p) return reply.code(404).send({ error: 'not_found' });
    db.tx(() => {
      db.run('UPDATE agents SET profile_id=NULL WHERE profile_id=?', id);
      db.run('DELETE FROM profiles WHERE id=?', id);
    });
    policies.invalidate();
    audit(who(req), 'profile.delete', p.name, req.ip);
    return { ok: true };
  });

  /** The hosts listed get this profile; hosts that had it and are not listed lose it. */
  app.put('/api/profiles/:id/hosts', admin, async (req, reply) => {
    const id = Number((req.params as any).id);
    const p = db.get('SELECT name FROM profiles WHERE id=?', id);
    if (!p) return reply.code(404).send({ error: 'not_found' });
    const list = ids((req.body as any)?.agentIds);
    db.tx(() => {
      db.run('UPDATE agents SET profile_id=NULL WHERE profile_id=?', id);
      for (const a of list) db.run('UPDATE agents SET profile_id=? WHERE id=?', id, a);
    });
    policies.invalidate();
    audit(who(req), 'profile.assign', `${p.name} (${list.length})`, req.ip);
    return { ok: true };
  });

  app.get('/api/agents/:id/policy', admin, async (req, reply) => {
    const id = Number((req.params as any).id);
    if (!db.get('SELECT 1 AS x FROM agents WHERE id=?', id)) return reply.code(404).send({ error: 'not_found' });
    const { profileId, profileName, overrides, inherited, effective, mutedUntil } = policies.of(id);
    return { profileId, profileName, overrides, inherited, effective, mutedUntil };
  });
  app.put('/api/agents/:id/policy', admin, async (req, reply) => {
    const id = Number((req.params as any).id);
    const a = db.get('SELECT name FROM agents WHERE id=?', id);
    if (!a) return reply.code(404).send({ error: 'not_found' });
    const b = (req.body ?? {}) as { profileId?: number | null; overrides?: unknown };
    if (b.profileId !== undefined) {
      if (b.profileId !== null && !db.get('SELECT 1 AS x FROM profiles WHERE id=?', Number(b.profileId))) return reply.code(400).send({ error: 'bad_profile' });
      db.run('UPDATE agents SET profile_id=? WHERE id=?', b.profileId === null ? null : Number(b.profileId), id);
    }
    if (b.overrides !== undefined) db.run('UPDATE agents SET overrides=? WHERE id=?', JSON.stringify(cleanConfig(b.overrides)), id);
    policies.invalidate();
    audit(who(req), 'host.policy', a.name, req.ip);
    return { ok: true };
  });

  /** Maintenance window: notifications stay quiet for these hosts. `minutes: null` ends it. */
  app.post('/api/maintenance', admin, async (req, reply) => {
    const b = (req.body ?? {}) as { agentIds?: unknown; minutes?: number | null; reason?: string };
    const list = ids(b.agentIds);
    if (!list.length) return reply.code(400).send({ error: 'no_hosts' });
    const mins = b.minutes === null || b.minutes === undefined ? 0 : Math.min(60 * 24 * 14, Math.max(1, Math.round(Number(b.minutes))));
    if (b.minutes !== null && b.minutes !== undefined && !Number.isFinite(Number(b.minutes))) return reply.code(400).send({ error: 'bad_minutes' });
    const until = mins ? Date.now() + mins * 60_000 : null;
    for (const a of list) db.run('UPDATE agents SET muted_until=?, muted_reason=? WHERE id=?', until, mins ? String(b.reason ?? '').slice(0, 120) : null, a);
    policies.invalidate();
    audit(who(req), mins ? 'maintenance.start' : 'maintenance.end', `${list.length} host(s)${mins ? `, ${mins} min` : ''}`, req.ip);
    return { ok: true, until };
  });
  app.put('/api/maintenance/settings', admin, async (req) => {
    db.setSetting('maintenance.critical_breaks', (req.body as any)?.criticalBreaks === false ? '0' : '1');
    return { ok: true };
  });
}

function safe(s: unknown) {
  try {
    return JSON.parse(String(s ?? '{}'));
  } catch {
    return {};
  }
}
