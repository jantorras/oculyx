import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from 'node:crypto';
import ssh2 from 'ssh2';
import type { Client as SshClient, ClientChannel } from 'ssh2';

const { Client, utils } = ssh2;
import type { Db } from './db.ts';

export const sha256fp = (b: Buffer) => 'SHA256:' + createHash('sha256').update(b).digest('base64').replace(/=+$/, '');

/** Private keys are stored AES-256-GCM encrypted with a key derived from the server secret. */
export class KeyVault {
  private key: Buffer;
  constructor(secret: Buffer) {
    this.key = Buffer.from(hkdfSync('sha256', secret, Buffer.alloc(0), 'oculyx-ssh-keys', 32));
  }
  seal(plain: string): string {
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', this.key, iv);
    const enc = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
    return [iv, c.getAuthTag(), enc].map((b) => b.toString('base64')).join('.');
  }
  open(sealed: string): string {
    const [iv, tag, enc] = sealed.split('.').map((s) => Buffer.from(s, 'base64'));
    const d = createDecipheriv('aes-256-gcm', this.key, iv);
    d.setAuthTag(tag);
    return Buffer.concat([d.update(enc), d.final()]).toString('utf8');
  }
}

export interface KeyRow {
  id: number;
  name: string;
  public: string;
  fingerprint: string;
  created: number;
  created_by: string | null;
}

export function generateKey(comment: string): { private: string; public: string; fingerprint: string } {
  const pair = utils.generateKeyPairSync('ed25519', { comment });
  const parsed = utils.parseKey(pair.public) as any;
  return { private: pair.private, public: pair.public.trim(), fingerprint: sha256fp(parsed.getPublicSSH()) };
}

export function importKey(privateKey: string, comment: string): { private: string; public: string; fingerprint: string } {
  const parsed = utils.parseKey(privateKey) as any;
  if (parsed instanceof Error) throw new Error(parsed.message.includes('passphrase') ? 'encrypted_key' : 'bad_key');
  const k = Array.isArray(parsed) ? parsed[0] : parsed;
  if (!k || !k.isPrivateKey?.()) throw new Error('bad_key');
  const pub = k.getPublicSSH() as Buffer;
  return { private: privateKey.trim() + '\n', public: `${k.type} ${pub.toString('base64')} ${comment}`.trim(), fingerprint: sha256fp(pub) };
}

export interface Access {
  host: string;
  port: number;
  user: string;
  hostkey: string | null;
}

export class SshError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

/** Opens an SSH connection with host-key pinning (trust on first use). Resolves with the client and the host key seen. */
export function connect(access: Access, privateKey: string, timeoutMs = 10_000): Promise<{ client: SshClient; hostkey: string; firstUse: boolean }> {
  return new Promise((resolve, reject) => {
    const client = new Client();
    let seen = '';
    let mismatch = false;
    const fail = (e: SshError) => {
      client.end();
      reject(e);
    };
    client
      .on('ready', () => resolve({ client, hostkey: seen, firstUse: !access.hostkey }))
      .on('error', (e) => {
        if (mismatch) return fail(new SshError('hostkey_changed', `The host key of ${access.host} changed (was ${access.hostkey}, now ${seen}). Someone may be impersonating the server. Reset the pinned key if this is expected.`));
        const m = e.message;
        if (/All configured authentication methods failed/.test(m)) return fail(new SshError('auth_failed', 'The server rejected the key. Deploy the public key to that account first.'));
        if (/ECONNREFUSED|EHOSTUNREACH|ENETUNREACH|ENOTFOUND|ETIMEDOUT|Timed out/.test(m)) return fail(new SshError('unreachable', `Cannot reach ${access.host}:${access.port}. ${m}`));
        fail(new SshError('ssh_error', m));
      })
      .connect({
        host: access.host,
        port: access.port,
        username: access.user,
        privateKey,
        readyTimeout: timeoutMs,
        keepaliveInterval: 20_000,
        hostHash: 'sha256',
        hostVerifier: (hash: string) => {
          seen = 'SHA256:' + Buffer.from(hash, 'hex').toString('base64').replace(/=+$/, '');
          if (access.hostkey && access.hostkey !== seen) {
            mismatch = true;
            return false;
          }
          return true;
        },
      });
  });
}

export function exec(client: SshClient, cmd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    client.exec(cmd, (err, stream) => {
      if (err) return reject(err);
      let out = '';
      stream.on('data', (d: Buffer) => (out += d.toString()));
      stream.stderr.on('data', (d: Buffer) => (out += d.toString()));
      stream.on('close', () => resolve(out.trim()));
    });
  });
}

export function shell(client: SshClient, cols: number, rows: number): Promise<ClientChannel> {
  return new Promise((resolve, reject) => {
    client.shell({ term: 'xterm-256color', cols, rows }, (err, stream) => (err ? reject(err) : resolve(stream)));
  });
}

export function loadAccess(db: Db, agentId: number): (Access & { key_id: number | null; tested: number | null }) | null {
  const a = db.get('SELECT * FROM ssh_access WHERE agent_id=?', agentId);
  if (a) return { host: a.host, port: a.port, user: a.user, hostkey: a.hostkey, key_id: a.key_id, tested: a.tested };
  const agent = db.get('SELECT ip FROM agents WHERE id=?', agentId);
  if (!agent) return null;
  const ip = String(agent.ip ?? '').replace(/^::ffff:/, '');
  return { host: ip, port: 22, user: 'root', hostkey: null, key_id: null, tested: null };
}
