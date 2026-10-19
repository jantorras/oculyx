import { createHmac, randomBytes, scryptSync, timingSafeEqual, createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export type Role = 'admin' | 'operator' | 'viewer';
const RANK: Record<Role, number> = { viewer: 1, operator: 2, admin: 3 };
export const hasRole = (have: Role, need: Role) => RANK[have] >= RANK[need];

export function hashPassword(pw: string): string {
  const salt = randomBytes(16);
  const h = scryptSync(pw, salt, 64);
  return `scrypt$${salt.toString('hex')}$${h.toString('hex')}`;
}

export function verifyPassword(pw: string, stored: string): boolean {
  const [alg, saltHex, hashHex] = stored.split('$');
  if (alg !== 'scrypt' || !saltHex || !hashHex) return false;
  const expect = Buffer.from(hashHex, 'hex');
  const got = scryptSync(pw, Buffer.from(saltHex, 'hex'), expect.length);
  return timingSafeEqual(got, expect);
}

export const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');
export const randomToken = (bytes = 24) => randomBytes(bytes).toString('base64url');

/** Load (or create) the HMAC secret used to sign session tokens. */
export function loadSecret(dataDir: string): Buffer {
  mkdirSync(dataDir, { recursive: true });
  const f = join(dataDir, 'secret.key');
  if (existsSync(f)) return Buffer.from(readFileSync(f, 'utf8').trim(), 'hex');
  const s = randomBytes(32);
  writeFileSync(f, s.toString('hex'), { mode: 0o600 });
  return s;
}

export function signToken(secret: Buffer, payload: { uid: number; exp: number }): string {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = createHmac('sha256', secret).update(body).digest('base64url');
  return `${body}.${sig}`;
}

export function verifyToken(secret: Buffer, token: string): { uid: number; exp: number } | null {
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const expect = createHmac('sha256', secret).update(body).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expect);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    return p.exp > Date.now() ? p : null;
  } catch {
    return null;
  }
}

/** Sliding-window limiter for login attempts, keyed by IP. */
export class LoginLimiter {
  private hits = new Map<string, number[]>();
  private max: number;
  private windowMs: number;
  constructor(max = 8, windowMs = 60_000) {
    this.max = max;
    this.windowMs = windowMs;
  }
  blocked(key: string): boolean {
    const now = Date.now();
    const list = (this.hits.get(key) ?? []).filter((t) => now - t < this.windowMs);
    this.hits.set(key, list);
    return list.length >= this.max;
  }
  fail(key: string) {
    this.hits.set(key, [...(this.hits.get(key) ?? []), Date.now()]);
  }
}
