import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync, chmodSync, chownSync, copyFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { hp, readText } from './host.ts';
import { authorizedKeyUsers, isNativeRoot, sshdConfig } from './hardening.ts';

const KEY_RE = /^((?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)) ([A-Za-z0-9+/]+={0,2})(?: ([\x20-\x7e]{0,120}))?$/;
const USER_RE = /^[a-z_][a-z0-9_-]{0,31}$/;

export interface HostKey {
  user: string;
  type: string;
  fingerprint: string;
  comment: string;
}

const fingerprint = (b64: string) => 'SHA256:' + createHash('sha256').update(Buffer.from(b64, 'base64')).digest('base64').replace(/=+$/, '');

function accounts(): { user: string; uid: number; gid: number; home: string }[] {
  const out: { user: string; uid: number; gid: number; home: string }[] = [];
  for (const l of (readText(hp('etc/passwd')) ?? '').split('\n')) {
    const f = l.split(':');
    if (f.length >= 7 && USER_RE.test(f[0]) && !/(nologin|false)$/.test(f[6])) out.push({ user: f[0], uid: Number(f[2]), gid: Number(f[3]), home: f[5] });
  }
  return out;
}

/** Every authorized key on the host, per account. Read-only. */
export function listHostKeys(): { keys: HostKey[]; users: string[]; passwordAuth: string | null } {
  const keys: HostKey[] = [];
  const acc = accounts().filter((a) => a.uid === 0 || a.uid >= 1000);
  for (const a of acc) {
    for (const name of ['authorized_keys', 'authorized_keys2']) {
      for (const line of (readText(hp(join(a.home, '.ssh', name))) ?? '').split('\n')) {
        const m = line.match(/(?:^|\s)((?:ssh-|ecdsa-|sk-)[\w@.-]+)\s+([A-Za-z0-9+/=]+)(?:\s+(.*))?$/);
        if (m) keys.push({ user: a.user, type: m[1], fingerprint: fingerprint(m[2]), comment: (m[3] ?? '').trim() });
      }
    }
  }
  return { keys, users: acc.map((a) => a.user), passwordAuth: sshdConfig()?.['passwordauthentication'] ?? null };
}

export function authorizeKey(user: string, publicKey: string): { steps: string[] } {
  if (!isNativeRoot) throw new Error('This agent cannot change the system: it must run natively as root with actions enabled.');
  const line = publicKey.trim();
  const m = line.match(KEY_RE);
  if (!m || line.includes('\n')) throw new Error('That is not a valid single-line SSH public key.');
  const acc = accounts().find((a) => a.user === user);
  if (!acc) throw new Error(`No login account named "${user}" on this host.`);
  const dir = join(acc.home, '.ssh');
  const file = join(dir, 'authorized_keys');
  if (!existsSync(dir)) {
    mkdirSync(dir, { mode: 0o700, recursive: true });
    chownSync(dir, acc.uid, acc.gid);
  }
  chmodSync(dir, 0o700);
  const current = existsSync(file) ? readFileSync(file, 'utf8') : '';
  const fp = fingerprint(m[2]);
  if (current.split('\n').some((l) => l.includes(m[2]))) return { steps: [`key ${fp} was already authorized for ${user}`] };
  writeFileSync(file, current.replace(/\n?$/, current ? '\n' : '') + line + '\n', { mode: 0o600 });
  chownSync(file, acc.uid, acc.gid);
  chmodSync(file, 0o600);
  return { steps: [`authorized ${fp} for ${user} (${file})`] };
}

export function revokeKey(user: string, fp: string): { steps: string[] } {
  if (!isNativeRoot) throw new Error('This agent cannot change the system: it must run natively as root with actions enabled.');
  if (!/^SHA256:[A-Za-z0-9+/]{43}$/.test(fp)) throw new Error('Bad fingerprint.');
  const acc = accounts().find((a) => a.user === user);
  if (!acc) throw new Error(`No login account named "${user}".`);
  const file = join(acc.home, '.ssh', 'authorized_keys');
  if (!existsSync(file)) throw new Error('That account has no authorized_keys file.');
  const lines = readFileSync(file, 'utf8').split('\n');
  const keep = lines.filter((l) => {
    const m = l.match(/(?:^|\s)((?:ssh-|ecdsa-|sk-)[\w@.-]+)\s+([A-Za-z0-9+/=]+)/);
    return !(m && fingerprint(m[2]) === fp);
  });
  if (keep.length === lines.length) throw new Error('That key is not in the file.');
  // never remove the way in when passwords are off
  const total = authorizedKeyUsers().reduce((n, u) => n + u.keys, 0);
  if (sshdConfig()?.['passwordauthentication'] === 'no' && total <= 1) throw new Error('Refusing to remove the last authorized key while SSH passwords are disabled: you would be locked out.');
  copyFileSync(file, `${file}.oculyx-backup`);
  writeFileSync(file, keep.join('\n'), { mode: statSync(file).mode & 0o777 });
  return { steps: [`removed ${fp} from ${user}`] };
}
