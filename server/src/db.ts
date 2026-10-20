import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pass_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'viewer', lang TEXT NOT NULL DEFAULT 'en', created INTEGER NOT NULL, last_login INTEGER
);
CREATE TABLE IF NOT EXISTS enroll_tokens (
  token TEXT PRIMARY KEY, label TEXT NOT NULL, created INTEGER NOT NULL, created_by TEXT, used_by INTEGER
);
CREATE TABLE IF NOT EXISTS agents (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, secret_hash TEXT NOT NULL, info TEXT, docker TEXT, ports TEXT,
  ip TEXT, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL, last_metrics TEXT
);
CREATE TABLE IF NOT EXISTS metrics (
  agent_id INTEGER NOT NULL, ts INTEGER NOT NULL, cpu REAL, mem REAL, disk REAL, rx REAL, tx REAL, load1 REAL
);
CREATE INDEX IF NOT EXISTS metrics_idx ON metrics(agent_id, ts);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL, check_id TEXT NOT NULL, severity TEXT NOT NULL,
  title TEXT NOT NULL, detail TEXT, status TEXT NOT NULL DEFAULT 'open', first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
  UNIQUE(agent_id, check_id)
);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL, rule TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'open', opened INTEGER NOT NULL, closed INTEGER
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL, ts INTEGER NOT NULL, type TEXT NOT NULL, severity TEXT NOT NULL,
  message TEXT NOT NULL, data TEXT
);
CREATE INDEX IF NOT EXISTS events_idx ON events(agent_id, ts);
CREATE TABLE IF NOT EXISTS ai_usage (month TEXT PRIMARY KEY, in_tokens INTEGER NOT NULL DEFAULT 0, out_tokens INTEGER NOT NULL DEFAULT 0, cost REAL NOT NULL DEFAULT 0, calls INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, user TEXT, action TEXT NOT NULL, target TEXT, ip TEXT
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ssh_keys (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, public TEXT NOT NULL, fingerprint TEXT NOT NULL, private_enc TEXT NOT NULL,
  created INTEGER NOT NULL, created_by TEXT
);
CREATE TABLE IF NOT EXISTS ssh_access (
  agent_id INTEGER PRIMARY KEY, host TEXT NOT NULL, port INTEGER NOT NULL DEFAULT 22, user TEXT NOT NULL DEFAULT 'root',
  key_id INTEGER, hostkey TEXT, tested INTEGER
);
CREATE TABLE IF NOT EXISTS known_logins (
  agent_id INTEGER NOT NULL, user TEXT NOT NULL, ip TEXT NOT NULL, first INTEGER NOT NULL, last INTEGER NOT NULL, n INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (agent_id, user, ip)
);
`;

export type Row = Record<string, any>;

export class Db {
  raw: DatabaseSync;
  constructor(path: string) {
    mkdirSync(dirname(path), { recursive: true });
    this.raw = new DatabaseSync(path);
    this.raw.exec('PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;');
    this.raw.exec(SCHEMA);
    for (const alter of ['ALTER TABLE enroll_tokens ADD COLUMN expires INTEGER', 'ALTER TABLE findings ADD COLUMN fix TEXT']) {
      try {
        this.raw.exec(alter);
      } catch {
        /* column already exists */
      }
    }
  }
  all(sql: string, ...p: any[]): Row[] {
    return this.raw.prepare(sql).all(...p) as Row[];
  }
  get(sql: string, ...p: any[]): Row | undefined {
    return this.raw.prepare(sql).get(...p) as Row | undefined;
  }
  run(sql: string, ...p: any[]) {
    const r = this.raw.prepare(sql).run(...p);
    return { changes: Number(r.changes), id: Number(r.lastInsertRowid) };
  }
  tx<T>(fn: () => T): T {
    this.raw.exec('BEGIN');
    try {
      const v = fn();
      this.raw.exec('COMMIT');
      return v;
    } catch (e) {
      this.raw.exec('ROLLBACK');
      throw e;
    }
  }
  setting(key: string, def = ''): string {
    return this.get('SELECT value FROM settings WHERE key=?', key)?.value ?? def;
  }
  setSetting(key: string, value: string) {
    this.run('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', key, value);
  }
}
