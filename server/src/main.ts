import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import { WebSocketServer } from 'ws';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Db } from './db.ts';
import { Alerts, OFFLINE_AFTER_MS, thresholds, DEFAULT_THRESHOLDS } from './alerts.ts';
import { Hub } from './hub.ts';
import { notify } from './notify.ts';
import { agentBundle, renderInstallScript, safeServerUrl, stampExe } from './installer.ts';
import { hashPassword, verifyPassword, loadSecret, signToken, verifyToken, randomToken, sha256, hasRole, LoginLimiter, type Role } from './auth.ts';

const here = fileURLToPath(new URL('.', import.meta.url));
const PORT = Number(process.env.PORT ?? 8080);
const DATA_DIR = resolve(process.env.OCULYX_DATA ?? join(here, '../../data'));
const AGENT_DIR = resolve(process.env.OCULYX_AGENT_DIR ?? join(here, '../../agent'));
const TOKEN_TTL_MS = 24 * 3600_000;
const WIN_EXE = resolve(join(here, '../assets/OculyxSetup.exe'));
const WEB_DIR = resolve(process.env.OCULYX_WEB ?? join(here, '../../web/dist'));
const RETENTION_DAYS = Number(process.env.OCULYX_RETENTION_DAYS ?? 14);
const SESSION_MS = 12 * 3600_000;

const db = new Db(join(DATA_DIR, 'oculyx.db'));
const secret = loadSecret(DATA_DIR);
const alerts = new Alerts(db);
const hub = new Hub(db, alerts);
const limiter = new LoginLimiter();

const app = Fastify({ logger: { level: process.env.LOG_LEVEL ?? 'info' }, trustProxy: process.env.OCULYX_TRUST_PROXY === '1', bodyLimit: 1_000_000 });

// ---------- bootstrap admin ----------
if (!db.get('SELECT 1 AS x FROM users LIMIT 1')) {
  const pw = process.env.OCULYX_ADMIN_PASSWORD ?? randomToken(12);
  db.run('INSERT INTO users(username,pass_hash,role,created) VALUES(?,?,?,?)', 'admin', hashPassword(pw), 'admin', Date.now());
  console.log(`\n  First run: created user "admin" with password: ${pw}\n  Change it after signing in.\n`);
}

// ---------- helpers ----------
type User = { id: number; username: string; role: Role; lang: string };
declare module 'fastify' {
  interface FastifyRequest {
    user?: User;
  }
}

const audit = (user: string | undefined, action: string, target: string | number | undefined, ip: string) =>
  db.run('INSERT INTO audit(ts,user,action,target,ip) VALUES(?,?,?,?,?)', Date.now(), user ?? null, action, target === undefined ? null : String(target), ip);

function guard(role: Role) {
  return async (req: any, reply: any) => {
    const h = String(req.headers.authorization ?? '');
    const p = h.startsWith('Bearer ') ? verifyToken(secret, h.slice(7)) : null;
    const u = p && (db.get('SELECT id,username,role,lang FROM users WHERE id=?', p.uid) as User | undefined);
    if (!u) return reply.code(401).send({ error: 'unauthorized' });
    if (!hasRole(u.role, role)) return reply.code(403).send({ error: 'forbidden' });
    req.user = u;
  };
}
const viewer = { preHandler: guard('viewer') };
const operator = { preHandler: guard('operator') };
const admin = { preHandler: guard('admin') };

const SEV_WEIGHT: Record<string, number> = { critical: 25, high: 12, medium: 5, low: 2, info: 0 };
function score(agentId: number): number | null {
  if (db.get('SELECT ports FROM agents WHERE id=?', agentId)?.ports == null) return null;
  const rows = db.all("SELECT severity FROM findings WHERE agent_id=? AND status='open'", agentId);
  return Math.max(0, 100 - rows.reduce((s, r) => s + (SEV_WEIGHT[r.severity] ?? 0), 0));
}
const parse = (s: string | null | undefined) => {
  try {
    return s ? JSON.parse(s) : null;
  } catch {
    return null;
  }
};

function agentView(a: any, full = false) {
  const online = Date.now() - a.last_seen < OFFLINE_AFTER_MS;
  const containers = parse(a.docker) as any[] | null;
  const base = {
    id: a.id,
    name: a.name,
    ip: a.ip,
    online,
    lastSeen: a.last_seen,
    firstSeen: a.first_seen,
    info: parse(a.info),
    metrics: parse(a.last_metrics),
    score: score(a.id),
    docker: containers ? { total: containers.length, running: containers.filter((c) => c.state === 'running').length } : null,
    openFindings: db.get("SELECT COUNT(*) AS n FROM findings WHERE agent_id=? AND status='open'", a.id)?.n ?? 0,
    openAlerts: db.get("SELECT COUNT(*) AS n FROM alerts WHERE agent_id=? AND state!='closed'", a.id)?.n ?? 0,
    spark: full ? undefined : db.all('SELECT cpu FROM (SELECT cpu,ts FROM metrics WHERE agent_id=? ORDER BY ts DESC LIMIT 40) ORDER BY ts', a.id).map((r) => r.cpu),
  };
  return full ? { ...base, containers, ports: parse(a.ports) ?? [] } : base;
}

// ---------- security headers ----------
app.addHook('onSend', async (_req, reply) => {
  reply.header('X-Content-Type-Options', 'nosniff');
  reply.header('X-Frame-Options', 'DENY');
  reply.header('Referrer-Policy', 'no-referrer');
  reply.header('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'");
});

// ---------- auth ----------
app.post('/api/auth/login', async (req, reply) => {
  const { username, password } = (req.body ?? {}) as { username?: string; password?: string };
  if (limiter.blocked(req.ip)) return reply.code(429).send({ error: 'too_many_attempts' });
  const u = db.get('SELECT * FROM users WHERE username=?', String(username ?? ''));
  if (!u || !verifyPassword(String(password ?? ''), u.pass_hash)) {
    limiter.fail(req.ip);
    audit(String(username ?? ''), 'login.failed', undefined, req.ip);
    return reply.code(401).send({ error: 'invalid_credentials' });
  }
  db.run('UPDATE users SET last_login=? WHERE id=?', Date.now(), u.id);
  audit(u.username, 'login', undefined, req.ip);
  return { token: signToken(secret, { uid: u.id, exp: Date.now() + SESSION_MS }), user: { id: u.id, username: u.username, role: u.role, lang: u.lang } };
});

app.get('/api/me', viewer, async (req) => req.user);

app.patch('/api/me', viewer, async (req) => {
  const { lang } = req.body as { lang?: string };
  if (lang && ['en', 'es', 'ca'].includes(lang)) db.run('UPDATE users SET lang=? WHERE id=?', lang, req.user!.id);
  return { ok: true };
});

app.post('/api/me/password', viewer, async (req, reply) => {
  const { current, next } = req.body as { current?: string; next?: string };
  const u = db.get('SELECT pass_hash FROM users WHERE id=?', req.user!.id)!;
  if (!verifyPassword(String(current ?? ''), u.pass_hash)) return reply.code(400).send({ error: 'wrong_password' });
  if (String(next ?? '').length < 10) return reply.code(400).send({ error: 'password_too_short' });
  db.run('UPDATE users SET pass_hash=? WHERE id=?', hashPassword(next!), req.user!.id);
  audit(req.user!.username, 'password.change', undefined, req.ip);
  return { ok: true };
});

// ---------- fleet ----------
app.get('/api/overview', viewer, async () => {
  const agents = db.all('SELECT * FROM agents ORDER BY name').map((a) => agentView(a));
  const sev = db.all("SELECT severity, COUNT(*) AS n FROM findings WHERE status='open' GROUP BY severity");
  return {
    agents,
    findingsBySeverity: Object.fromEntries(sev.map((r) => [r.severity, r.n])),
    alerts: db.all("SELECT a.*, g.name AS agent FROM alerts a JOIN agents g ON g.id=a.agent_id WHERE a.state!='closed' ORDER BY a.opened DESC LIMIT 20"),
    events: db.all('SELECT e.*, g.name AS agent FROM events e JOIN agents g ON g.id=e.agent_id ORDER BY e.ts DESC LIMIT 15'),
  };
});

app.get('/api/agents/:id', viewer, async (req, reply) => {
  const a = db.get('SELECT * FROM agents WHERE id=?', Number((req.params as any).id));
  if (!a) return reply.code(404).send({ error: 'not_found' });
  const id = a.id;
  return {
    ...agentView(a, true),
    findings: db.all("SELECT * FROM findings WHERE agent_id=? AND status!='resolved' ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, first_seen DESC", id),
    alerts: db.all('SELECT * FROM alerts WHERE agent_id=? ORDER BY opened DESC LIMIT 30', id),
    events: db.all('SELECT * FROM events WHERE agent_id=? ORDER BY ts DESC LIMIT 50', id),
    canAct: hub.isOnline(id),
  };
});

const RANGES: Record<string, { ms: number; bucket: number }> = {
  '1h': { ms: 3600_000, bucket: 30_000 },
  '6h': { ms: 6 * 3600_000, bucket: 120_000 },
  '24h': { ms: 24 * 3600_000, bucket: 300_000 },
  '7d': { ms: 7 * 24 * 3600_000, bucket: 1800_000 },
};
app.get('/api/agents/:id/metrics', viewer, async (req) => {
  const { range = '1h' } = req.query as { range?: string };
  const r = RANGES[range] ?? RANGES['1h'];
  const since = Date.now() - r.ms;
  return db.all(
    `SELECT CAST(ts/? AS INTEGER)*? AS ts, AVG(cpu) AS cpu, AVG(mem) AS mem, AVG(disk) AS disk, AVG(rx) AS rx, AVG(tx) AS tx, AVG(load1) AS load1
     FROM metrics WHERE agent_id=? AND ts>=? GROUP BY CAST(ts/? AS INTEGER) ORDER BY ts`,
    r.bucket, r.bucket, Number((req.params as any).id), since, r.bucket,
  );
});

app.get('/api/fleet/metrics', viewer, async (req) => {
  const { range = '6h' } = req.query as { range?: string };
  const r = RANGES[range] ?? RANGES['6h'];
  return db.all(
    `SELECT CAST(ts/? AS INTEGER)*? AS ts, AVG(cpu) AS cpu, AVG(mem) AS mem, AVG(disk) AS disk,
            SUM(rx)*1.0/(COUNT(*)*1.0/COUNT(DISTINCT agent_id)) AS rx, SUM(tx)*1.0/(COUNT(*)*1.0/COUNT(DISTINCT agent_id)) AS tx
     FROM metrics WHERE ts>=? GROUP BY CAST(ts/? AS INTEGER) ORDER BY ts`,
    r.bucket, r.bucket, Date.now() - r.ms, r.bucket,
  );
});

/** Events per hour for the last 24h, split by severity class (for the activity column chart). */
app.get('/api/stats/timeline', viewer, async () => {
  const hour = 3600_000;
  const end = Math.ceil(Date.now() / hour) * hour;
  const rows = db.all(
    `SELECT CAST(ts/? AS INTEGER)*? AS h,
            SUM(CASE WHEN severity IN ('critical','high') THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END) AS medium,
            SUM(CASE WHEN severity IN ('low','info') THEN 1 ELSE 0 END) AS low
     FROM events WHERE ts>=? GROUP BY h`,
    hour, hour, end - 24 * hour,
  );
  const byH = new Map(rows.map((r) => [r.h, r]));
  return Array.from({ length: 24 }, (_, i) => {
    const ts = end - (24 - i) * hour;
    const r = byH.get(ts);
    return { ts, high: r?.high ?? 0, medium: r?.medium ?? 0, low: r?.low ?? 0 };
  });
});

app.delete('/api/agents/:id', admin, async (req) => {
  const id = Number((req.params as any).id);
  const a = db.get('SELECT name FROM agents WHERE id=?', id);
  db.tx(() => {
    for (const t of ['metrics', 'findings', 'alerts', 'events']) db.run(`DELETE FROM ${t} WHERE agent_id=?`, id);
    db.run('DELETE FROM agents WHERE id=?', id);
  });
  audit(req.user!.username, 'agent.delete', a?.name, req.ip);
  return { ok: true };
});

// ---------- docker (fleet-wide listing + actions relayed to the agent) ----------
app.get('/api/containers', viewer, async () => {
  const out: any[] = [];
  for (const a of db.all('SELECT id,name,docker,last_seen FROM agents ORDER BY name')) {
    for (const c of (parse(a.docker) as any[]) ?? []) out.push({ ...c, agentId: a.id, agent: a.name, online: Date.now() - a.last_seen < OFFLINE_AFTER_MS });
  }
  return out;
});

const ACTIONS = new Set(['start', 'stop', 'restart']);
app.post('/api/agents/:id/containers/:cid/:action', operator, async (req, reply) => {
  const { id, cid, action } = req.params as { id: string; cid: string; action: string };
  if (!ACTIONS.has(action)) return reply.code(400).send({ error: 'bad_action' });
  try {
    const data = await hub.command(Number(id), `docker.${action}`, { id: cid });
    audit(req.user!.username, `docker.${action}`, `${id}/${cid}`, req.ip);
    return { ok: true, data };
  } catch (e) {
    return reply.code(502).send({ error: (e as Error).message });
  }
});

app.get('/api/agents/:id/containers/:cid/logs', viewer, async (req, reply) => {
  const { id, cid } = req.params as { id: string; cid: string };
  try {
    return { logs: await hub.command(Number(id), 'docker.logs', { id: cid, tail: 200 }) };
  } catch (e) {
    return reply.code(502).send({ error: (e as Error).message });
  }
});

// ---------- findings / alerts / events ----------
app.get('/api/findings', viewer, async (req) => {
  const { status = 'open' } = req.query as { status?: string };
  return db.all(
    `SELECT f.*, g.name AS agent FROM findings f JOIN agents g ON g.id=f.agent_id WHERE f.status=?
     ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.first_seen DESC LIMIT 500`,
    status,
  );
});

app.get('/api/stats/security', viewer, async () => ({
  byHost: db.all("SELECT g.id, g.name, f.severity, COUNT(*) AS n FROM findings f JOIN agents g ON g.id=f.agent_id WHERE f.status='open' GROUP BY g.id, f.severity"),
  byCategory: db.all("SELECT substr(check_id,1,instr(check_id||':',':')-1) AS cat, severity, COUNT(*) AS n FROM findings WHERE status='open' GROUP BY cat, severity"),
}));

app.post('/api/findings/:id/:action', operator, async (req, reply) => {
  const { id, action } = req.params as { id: string; action: string };
  const status = action === 'ignore' ? 'ignored' : action === 'reopen' ? 'open' : null;
  if (!status) return reply.code(400).send({ error: 'bad_action' });
  db.run('UPDATE findings SET status=? WHERE id=?', status, Number(id));
  audit(req.user!.username, `finding.${action}`, id, req.ip);
  return { ok: true };
});

app.post('/api/agents/:id/fim/accept', operator, async (req, reply) => {
  try {
    await hub.command(Number((req.params as any).id), 'fim.rebaseline');
    audit(req.user!.username, 'fim.accept', (req.params as any).id, req.ip);
    return { ok: true };
  } catch (e) {
    return reply.code(502).send({ error: (e as Error).message });
  }
});

app.get('/api/alerts', viewer, async (req) => {
  const { state } = req.query as { state?: string };
  return db.all(
    `SELECT a.*, g.name AS agent FROM alerts a JOIN agents g ON g.id=a.agent_id ${state === 'open' ? "WHERE a.state!='closed'" : ''} ORDER BY a.opened DESC LIMIT 200`,
  );
});

app.get('/api/stats/alerts', viewer, async () => {
  const hour = 3600_000;
  const now = Date.now();
  const end = Math.ceil(now / hour) * hour;
  const c = (state: string) => db.get('SELECT COUNT(*) AS n FROM alerts WHERE state=?', state)?.n ?? 0;
  const bySev = Object.fromEntries(db.all("SELECT severity, COUNT(*) AS n FROM alerts WHERE state!='closed' GROUP BY severity").map((r) => [r.severity, r.n]));
  const mttr = db.get('SELECT AVG(closed-opened) AS ms FROM alerts WHERE closed IS NOT NULL AND opened>=?', now - 7 * 24 * hour)?.ms ?? null;
  const rows = db.all(
    `SELECT CAST(opened/? AS INTEGER)*? AS h,
            SUM(CASE WHEN severity IN ('critical','high') THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN severity='medium' THEN 1 ELSE 0 END) AS medium,
            SUM(CASE WHEN severity IN ('low','info') THEN 1 ELSE 0 END) AS low
     FROM alerts WHERE opened>=? GROUP BY h`,
    hour, hour, end - 24 * hour,
  );
  const byH = new Map(rows.map((r) => [r.h, r]));
  return {
    open: c('open'),
    ack: c('ack'),
    resolved24h: db.get("SELECT COUNT(*) AS n FROM alerts WHERE state='closed' AND closed>=?", now - 24 * hour)?.n ?? 0,
    mttrMs: mttr,
    bySeverity: bySev,
    timeline: Array.from({ length: 24 }, (_, i) => {
      const ts = end - (24 - i) * hour;
      const r = byH.get(ts);
      return { ts, high: r?.high ?? 0, medium: r?.medium ?? 0, low: r?.low ?? 0 };
    }),
  };
});

app.post('/api/alerts/ack-all', operator, async (req) => {
  const r = db.run("UPDATE alerts SET state='ack' WHERE state='open'");
  audit(req.user!.username, 'alert.ack_all', r.changes, req.ip);
  return { ok: true, changed: r.changes };
});

app.post('/api/alerts/:id/ack', operator, async (req) => {
  db.run("UPDATE alerts SET state='ack' WHERE id=? AND state='open'", Number((req.params as any).id));
  audit(req.user!.username, 'alert.ack', (req.params as any).id, req.ip);
  return { ok: true };
});

app.get('/api/events', viewer, async (req) => {
  const { type } = req.query as { type?: string };
  return db.all(
    `SELECT e.*, g.name AS agent FROM events e JOIN agents g ON g.id=e.agent_id ${type ? 'WHERE e.type=?' : ''} ORDER BY e.ts DESC LIMIT 300`,
    ...(type ? [type] : []),
  );
});

// ---------- admin: enrollment, users, settings, audit ----------
app.get('/api/enroll', admin, async () => db.all('SELECT token,label,created,created_by,used_by,expires FROM enroll_tokens ORDER BY created DESC'));

/** Progress of one enrollment, polled by the "add host" wizard. */
app.get('/api/enroll/:token/status', admin, async (req, reply) => {
  const t = db.get('SELECT * FROM enroll_tokens WHERE token=?', (req.params as any).token);
  if (!t) return reply.code(404).send({ error: 'not_found' });
  if (t.used_by == null) return { state: t.expires && t.expires < Date.now() ? 'expired' : 'pending', expires: t.expires };
  const a = db.get('SELECT * FROM agents WHERE id=?', t.used_by);
  if (!a) return { state: 'pending', expires: t.expires };
  return { state: 'enrolled', agent: { id: a.id, name: a.name, info: parse(a.info), online: Date.now() - a.last_seen < OFFLINE_AFTER_MS, hasData: !!a.last_metrics } };
});

app.post('/api/enroll', admin, async (req) => {
  const { label } = (req.body ?? {}) as { label?: string };
  const token = `ocx_${randomToken(18)}`;
  const expires = Date.now() + TOKEN_TTL_MS;
  db.run('INSERT INTO enroll_tokens(token,label,created,created_by,expires) VALUES(?,?,?,?,?)', token, String(label ?? '').slice(0, 60) || 'agent', Date.now(), req.user!.username, expires);
  audit(req.user!.username, 'enroll.create', label, req.ip);
  return { token, expires };
});

/** Windows app, pre-configured for this server and one enrollment token. */
app.post('/api/enroll/:token/windows-installer', admin, async (req, reply) => {
  const token = String((req.params as any).token);
  const t = db.get('SELECT * FROM enroll_tokens WHERE token=? AND used_by IS NULL AND (expires IS NULL OR expires>?)', token, Date.now());
  if (!t) return reply.code(404).send({ error: 'not_found' });
  if (!existsSync(WIN_EXE)) return reply.code(404).send({ error: 'installer_unavailable' });
  const body = (req.body ?? {}) as { name?: string; allow?: boolean };
  const okName = (n: unknown) => typeof n === 'string' && /^[A-Za-z0-9._ -]{1,60}$/.test(n);
  const name = okName(body.name) ? (body.name as string) : okName(t.label) && t.label !== 'agent' ? t.label : '';
  const server = safeServerUrl(db.setting('server.public_url'), safeServerUrl(originOf(req), 'http://localhost:' + PORT));
  audit(req.user!.username, 'enroll.windows_installer', name || t.label, req.ip);
  return reply
    .type('application/octet-stream')
    .header('content-disposition', 'attachment; filename="OculyxSetup.exe"')
    .header('cache-control', 'no-store')
    .send(stampExe(readFileSync(WIN_EXE), { server, token, name, allow: !!body.allow }));
});

app.delete('/api/enroll/:token', admin, async (req) => {
  db.run('DELETE FROM enroll_tokens WHERE token=? AND used_by IS NULL', (req.params as any).token);
  return { ok: true };
});

app.get('/api/users', admin, async () => db.all('SELECT id,username,role,lang,created,last_login FROM users ORDER BY username'));

app.post('/api/users', admin, async (req, reply) => {
  const { username, password, role } = (req.body ?? {}) as { username?: string; password?: string; role?: Role };
  if (!/^[a-z0-9._-]{3,32}$/i.test(String(username ?? ''))) return reply.code(400).send({ error: 'bad_username' });
  if (String(password ?? '').length < 10) return reply.code(400).send({ error: 'password_too_short' });
  if (!['admin', 'operator', 'viewer'].includes(String(role))) return reply.code(400).send({ error: 'bad_role' });
  if (db.get('SELECT 1 AS x FROM users WHERE username=?', username)) return reply.code(409).send({ error: 'exists' });
  db.run('INSERT INTO users(username,pass_hash,role,created) VALUES(?,?,?,?)', username, hashPassword(password!), role, Date.now());
  audit(req.user!.username, 'user.create', username, req.ip);
  return { ok: true };
});

app.patch('/api/users/:id', admin, async (req, reply) => {
  const id = Number((req.params as any).id);
  const { role, password } = (req.body ?? {}) as { role?: Role; password?: string };
  const target = db.get('SELECT username,role FROM users WHERE id=?', id);
  if (!target) return reply.code(404).send({ error: 'not_found' });
  if (role) {
    if (!['admin', 'operator', 'viewer'].includes(role)) return reply.code(400).send({ error: 'bad_role' });
    if (target.role === 'admin' && role !== 'admin' && (db.get("SELECT COUNT(*) AS n FROM users WHERE role='admin'")!.n as number) <= 1)
      return reply.code(400).send({ error: 'last_admin' });
    db.run('UPDATE users SET role=? WHERE id=?', role, id);
  }
  if (password) {
    if (password.length < 10) return reply.code(400).send({ error: 'password_too_short' });
    db.run('UPDATE users SET pass_hash=? WHERE id=?', hashPassword(password), id);
  }
  audit(req.user!.username, 'user.update', target.username, req.ip);
  return { ok: true };
});

app.delete('/api/users/:id', admin, async (req, reply) => {
  const id = Number((req.params as any).id);
  const target = db.get('SELECT username,role FROM users WHERE id=?', id);
  if (!target) return reply.code(404).send({ error: 'not_found' });
  if (id === req.user!.id) return reply.code(400).send({ error: 'cannot_delete_self' });
  db.run('DELETE FROM users WHERE id=?', id);
  audit(req.user!.username, 'user.delete', target.username, req.ip);
  return { ok: true };
});

const SETTING_KEYS = ['server.public_url', 'notify.webhook', 'notify.telegram_token', 'notify.telegram_chat', 'threshold.cpu', 'threshold.mem', 'threshold.disk'];
app.get('/api/settings', admin, async () => ({
  ...Object.fromEntries(SETTING_KEYS.map((k) => [k, db.setting(k)])),
  defaults: DEFAULT_THRESHOLDS,
  windowsInstaller: existsSync(WIN_EXE),
  effective: thresholds(db),
}));

app.put('/api/settings', admin, async (req) => {
  const body = (req.body ?? {}) as Record<string, string>;
  for (const k of SETTING_KEYS) if (k in body) db.setSetting(k, String(body[k] ?? '').trim());
  audit(req.user!.username, 'settings.update', undefined, req.ip);
  return { ok: true };
});

app.post('/api/settings/test-notify', admin, async () => {
  await notify(db, { severity: 'info', title: 'Oculyx', body: 'Test notification' });
  return { ok: true };
});

app.get('/api/audit', admin, async () => db.all('SELECT * FROM audit ORDER BY ts DESC LIMIT 300'));

// ---------- agent enrollment (public, token-gated) ----------
app.post('/api/agent/enroll', async (req, reply) => {
  const { token, name, info } = (req.body ?? {}) as { token?: string; name?: string; info?: unknown };
  if (limiter.blocked('enroll:' + req.ip)) return reply.code(429).send({ error: 'too_many_attempts' });
  const t = db.get('SELECT * FROM enroll_tokens WHERE token=? AND used_by IS NULL AND (expires IS NULL OR expires>?)', String(token ?? ''), Date.now());
  if (!t) {
    limiter.fail('enroll:' + req.ip);
    return reply.code(403).send({ error: 'invalid_token' });
  }
  const agentSecret = randomToken(32);
  const now = Date.now();
  const r = db.run('INSERT INTO agents(name,secret_hash,info,first_seen,last_seen,ip) VALUES(?,?,?,?,?,?)', String(name || t.label).slice(0, 60), sha256(agentSecret), JSON.stringify(info ?? {}), now, now, req.ip);
  db.run('UPDATE enroll_tokens SET used_by=? WHERE token=?', r.id, t.token);
  audit('agent', 'agent.enroll', name ?? t.label, req.ip);
  return { agentId: r.id, secret: agentSecret };
});

app.get('/healthz', async () => ({ ok: true }));

// ---------- one-line installer + agent bundle (public: a fresh machine fetches them with plain curl) ----------
const installTemplate = readFileSync(join(here, 'install.sh'), 'utf8');
const installTemplatePs = readFileSync(join(here, 'install.ps1'), 'utf8');
const bundle = agentBundle(AGENT_DIR);
const originOf = (req: any) => {
  const proto = String(req.headers['x-forwarded-proto'] ?? req.protocol).split(',')[0].trim();
  const host = String(req.headers['x-forwarded-host'] ?? req.headers.host ?? '').split(',')[0].trim();
  return `${proto}://${host}`;
};
app.get('/install.ps1', async (req, reply) => {
  const url = safeServerUrl(db.setting('server.public_url'), safeServerUrl(originOf(req), 'http://localhost:' + PORT));
  return reply.type('text/plain; charset=utf-8').header('cache-control', 'no-store').send(renderInstallScript(installTemplatePs, url));
});
app.get('/install.sh', async (req, reply) => {
  const url = safeServerUrl(db.setting('server.public_url'), safeServerUrl(originOf(req), 'http://localhost:' + PORT));
  return reply.type('text/x-shellscript; charset=utf-8').header('cache-control', 'no-store').send(renderInstallScript(installTemplate, url));
});
app.get('/agent/manifest.txt', async (_req, reply) => reply.type('text/plain; charset=utf-8').send([...bundle.keys()].join('\n') + '\n'));
app.get('/agent/files/*', async (req, reply) => {
  const name = String((req.params as any)['*']);
  const body = bundle.get(name);
  if (body == null) return reply.code(404).send({ error: 'not_found' });
  return reply.type('text/plain; charset=utf-8').send(body);
});

// ---------- static web UI ----------
if (existsSync(WEB_DIR)) {
  await app.register(fastifyStatic, { root: WEB_DIR });
  app.setNotFoundHandler((req, reply) => (req.url.startsWith('/api/') ? reply.code(404).send({ error: 'not_found' }) : reply.sendFile('index.html')));
} else {
  console.warn(`Web UI not built (${WEB_DIR} missing) - run: npm run build:web`);
}

// ---------- agent websocket ----------
const wss = new WebSocketServer({ noServer: true, maxPayload: 4 * 1024 * 1024 });
app.server.on('upgrade', (req, socket, head) => {
  if (!req.url?.startsWith('/ws/agent')) return socket.destroy();
  const auth = String(req.headers.authorization ?? '');
  const [idStr, sec] = auth.startsWith('Bearer ') ? auth.slice(7).split('.') : [];
  const agent = idStr && sec ? db.get('SELECT id,secret_hash FROM agents WHERE id=?', Number(idStr)) : undefined;
  if (!agent || agent.secret_hash !== sha256(sec ?? '')) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    return socket.destroy();
  }
  wss.handleUpgrade(req, socket, head, (ws) => hub.attach(agent.id, ws, String(req.socket.remoteAddress ?? '')));
});

// ---------- housekeeping ----------
setInterval(() => alerts.sweepOffline(), 15_000);
setInterval(() => {
  db.run('DELETE FROM metrics WHERE ts<?', Date.now() - RETENTION_DAYS * 86400_000);
  db.run('DELETE FROM events WHERE ts<?', Date.now() - 30 * 86400_000);
  db.run('DELETE FROM audit WHERE ts<?', Date.now() - 180 * 86400_000);
}, 3600_000);

await app.listen({ port: PORT, host: process.env.HOST ?? '0.0.0.0' });
