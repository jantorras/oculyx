import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync, lstatSync, readlinkSync } from 'node:fs';
import { join } from 'node:path';
import { hp, readText, isLinux } from './host.ts';
import type { AgentEvent } from './protocol.ts';

/**
 * Host intrusion signals that do not come from the auth log: new accounts, privileged group changes, new SSH keys,
 * persistence mechanisms (cron, systemd, profile scripts, ld.so.preload), new SUID files, reverse shells,
 * processes running from world-writable directories, crypto miners and out-of-tree kernel modules.
 * Everything is diffed against a baseline stored in the state dir; the first run only records it.
 */

interface State {
  users?: Record<string, string>;
  priv?: Record<string, string[]>;
  keys?: Record<string, string>;
  persist?: Record<string, string>;
  suid?: string[];
}

const PRIV_GROUPS = ['sudo', 'wheel', 'admin', 'root', 'docker', 'lxd'];
const PERSIST_FILES = ['etc/crontab', 'etc/rc.local', 'etc/ld.so.preload', 'etc/ssh/sshrc', 'etc/environment', 'etc/profile', 'etc/bash.bashrc'];
const PERSIST_DIRS = ['etc/cron.d', 'etc/cron.hourly', 'etc/cron.daily', 'etc/cron.weekly', 'etc/cron.monthly', 'var/spool/cron/crontabs', 'var/spool/cron', 'etc/systemd/system', 'etc/profile.d', 'etc/init.d', 'etc/pam.d', 'etc/sudoers.d', 'etc/update-motd.d'];
const SUID_DIRS = ['usr/bin', 'usr/sbin', 'bin', 'sbin', 'usr/local/bin', 'usr/local/sbin', 'usr/lib/openssh', 'usr/libexec', 'usr/lib/policykit-1', 'usr/lib/dbus-1.0'];
const WORLD_WRITABLE = ['tmp', 'var/tmp', 'dev/shm'];
const SHELLS = new Set(['sh', 'bash', 'dash', 'zsh', 'ash', 'ksh', 'csh', 'tcsh', 'fish']);
const MINER_NAME = /^(xmrig|minerd|cpuminer|ethminer|nbminer|t-rex|kdevtmpfsi|kinsing|xmr-stak|cgminer|bfgminer)/i;
const MINER_ARGS = /(stratum\+tcp:\/\/|stratum\+ssl:\/\/|--donate-level|cryptonight|--algo[= ]randomx)/i;

const sha = (b: Buffer | string) => createHash('sha256').update(b).digest('hex');

export class IntrusionWatcher {
  private state: State = {};
  private file: string;
  private emit: (e: AgentEvent) => void;
  private lastSuid = 0;
  private seenProc = new Set<string>();
  private ownPid = process.pid;
  private tickN = 0;
  private seenMods = new Set<string>();

  constructor(stateDir: string, emit: (e: AgentEvent) => void) {
    this.file = join(stateDir, 'intrusion.json');
    this.emit = emit;
    try {
      this.state = JSON.parse(readFileSync(this.file, 'utf8'));
    } catch {
      /* first run */
    }
    mkdirSync(stateDir, { recursive: true });
  }

  private save() {
    try {
      writeFileSync(this.file, JSON.stringify(this.state));
    } catch {
      /* never break monitoring over a state file */
    }
  }

  /** Called every ~15 s. Cheap checks run each time, heavier ones every few ticks. */
  tick() {
    if (!isLinux) return;
    this.tickN++;
    const safe = (fn: () => void) => {
      try {
        fn();
      } catch {
        /* a collector must never take the agent down */
      }
    };
    safe(() => this.accounts());
    safe(() => this.sshKeys());
    if (this.tickN % 2 === 0) safe(() => this.processes());
    if (this.tickN % 4 === 1) safe(() => this.persistence());
    if (this.tickN % 4 === 3) safe(() => this.modules());
    if (Date.now() - this.lastSuid > 6 * 3600_000) safe(() => this.suid());
    this.save();
  }

  /** Re-record the SSH keys as they are now (the panel itself just changed them, so that is not an intrusion). */
  acceptKeys() {
    this.state.keys = this.collectKeys();
    this.save();
  }

  // ---- accounts and privileged groups ----
  private accounts() {
    const users: Record<string, string> = {};
    for (const l of (readText(hp('etc/passwd')) ?? '').split('\n')) {
      const f = l.split(':');
      if (f.length >= 7 && f[0]) users[f[0]] = `${f[2]}:${f[6]}`;
    }
    const priv: Record<string, string[]> = {};
    for (const l of (readText(hp('etc/group')) ?? '').split('\n')) {
      const f = l.split(':');
      if (f.length >= 4 && PRIV_GROUPS.includes(f[0])) priv[f[0]] = f[3].split(',').filter(Boolean).sort();
    }
    const prev = this.state.users;
    if (prev) {
      for (const [u, v] of Object.entries(users)) {
        if (!(u in prev)) this.emit({ type: 'user_created', severity: v.startsWith('0:') ? 'critical' : 'high', message: `New local account: ${u} (uid ${v.split(':')[0]}, shell ${v.split(':')[1]})`, data: { user: u } });
      }
      for (const u of Object.keys(prev)) if (!(u in users)) this.emit({ type: 'user_removed', severity: 'medium', message: `Local account removed: ${u}`, data: { user: u } });
    }
    const pp = this.state.priv;
    if (pp) {
      for (const [g, members] of Object.entries(priv)) {
        for (const m of members) if (!(pp[g] ?? []).includes(m)) this.emit({ type: 'privileged_group_added', severity: 'high', message: `${m} was added to the privileged group "${g}"`, data: { user: m, group: g } });
      }
    }
    this.state.users = users;
    this.state.priv = priv;
  }

  // ---- ssh authorized keys ----
  private collectKeys(): Record<string, string> {
    const out: Record<string, string> = {};
    const homes: [string, string][] = [['root', '/root']];
    for (const l of (readText(hp('etc/passwd')) ?? '').split('\n')) {
      const f = l.split(':');
      if (f.length >= 6 && Number(f[2]) >= 1000 && f[0] !== 'nobody') homes.push([f[0], f[5]]);
    }
    for (const [user, home] of homes) {
      for (const name of ['authorized_keys', 'authorized_keys2']) {
        for (const line of (readText(hp(join(home, '.ssh', name))) ?? '').split('\n')) {
          const m = line.match(/(?:^|\s)((?:ssh-|ecdsa-|sk-)[\w@.-]+)\s+([A-Za-z0-9+/=]+)(?:\s+(.*))?$/);
          if (!m) continue;
          const fp = 'SHA256:' + createHash('sha256').update(Buffer.from(m[2], 'base64')).digest('base64').replace(/=+$/, '');
          out[`${user}|${fp}`] = (m[3] ?? '').trim();
        }
      }
    }
    return out;
  }

  private sshKeys() {
    const keys = this.collectKeys();
    const prev = this.state.keys;
    if (prev) {
      for (const [k, comment] of Object.entries(keys)) {
        if (k in prev) continue;
        const [user, fp] = k.split('|');
        this.emit({ type: 'ssh_key_added', severity: 'high', message: `New SSH key authorized for ${user}: ${fp}${comment ? ` (${comment})` : ''}`, data: { user, fingerprint: fp, comment } });
      }
      for (const k of Object.keys(prev)) {
        if (!(k in keys)) {
          const [user, fp] = k.split('|');
          this.emit({ type: 'ssh_key_removed', severity: 'info', message: `SSH key removed for ${user}: ${fp}`, data: { user, fingerprint: fp } });
        }
      }
    }
    this.state.keys = keys;
  }

  // ---- persistence ----
  private ownedByPackage(path: string): boolean {
    try {
      const dir = hp('var/lib/dpkg/info');
      const needle = `\n${path}\n`;
      for (const n of readdirSync(dir)) {
        if (n.endsWith('.list') && ('\n' + readFileSync(join(dir, n), 'utf8')).includes(needle)) return true;
      }
    } catch {
      /* not a dpkg system */
    }
    return false;
  }

  private persistence() {
    const cur: Record<string, string> = {};
    const add = (rel: string) => {
      try {
        const st = statSync(hp(rel));
        if (st.isFile() && st.size < 512 * 1024) cur[rel] = sha(readFileSync(hp(rel)));
      } catch {
        /* missing or unreadable */
      }
    };
    PERSIST_FILES.forEach(add);
    for (const d of PERSIST_DIRS) {
      try {
        for (const n of readdirSync(hp(d))) add(`${d}/${n}`);
      } catch {
        /* directory missing */
      }
    }
    // user crontabs and shell startup files
    try {
      for (const u of readdirSync(hp('home'))) for (const f of ['.bashrc', '.profile', '.bash_profile', '.bash_login']) add(`home/${u}/${f}`);
    } catch {
      /* no /home */
    }
    for (const f of ['.bashrc', '.profile', '.bash_profile']) add(`root/${f}`);
    const prev = this.state.persist;
    if (prev) {
      for (const [p, h] of Object.entries(cur)) {
        const what = !(p in prev) ? 'created' : prev[p] !== h ? 'modified' : null;
        if (!what) continue;
        const pkg = this.ownedByPackage('/' + p);
        const critical = p === 'etc/ld.so.preload';
        this.emit({
          type: 'persistence_changed',
          severity: critical ? 'critical' : pkg && what === 'modified' ? 'info' : what === 'created' ? 'high' : 'medium',
          message: `/${p} ${what}${pkg ? ' (package-managed)' : ''}`,
          data: { file: p, change: what, package: pkg },
        });
      }
      for (const p of Object.keys(prev)) if (!(p in cur)) this.emit({ type: 'persistence_changed', severity: 'low', message: `/${p} deleted`, data: { file: p, change: 'deleted' } });
    }
    this.state.persist = cur;
  }

  // ---- SUID / SGID ----
  private suid() {
    this.lastSuid = Date.now();
    const found: string[] = [];
    for (const d of SUID_DIRS) {
      try {
        for (const n of readdirSync(hp(d))) {
          try {
            const st = lstatSync(hp(`${d}/${n}`));
            if (st.isFile() && st.mode & 0o6000) found.push(`${d}/${n}`);
          } catch {
            /* vanished */
          }
        }
      } catch {
        /* missing */
      }
    }
    const walk = (rel: string, depth: number) => {
      if (depth > 3) return;
      try {
        for (const n of readdirSync(hp(rel))) {
          try {
            const st = lstatSync(hp(`${rel}/${n}`));
            if (st.isDirectory()) walk(`${rel}/${n}`, depth + 1);
            else if (st.isFile() && st.mode & 0o6000) found.push(`${rel}/${n}`);
          } catch {
            /* vanished */
          }
        }
      } catch {
        /* unreadable */
      }
    };
    for (const d of [...WORLD_WRITABLE, 'home']) walk(d, 0);
    const prev = this.state.suid;
    if (prev) {
      for (const p of found) {
        if (prev.includes(p)) continue;
        const risky = WORLD_WRITABLE.some((w) => p.startsWith(w + '/')) || p.startsWith('home/');
        const pkg = !risky && this.ownedByPackage('/' + p);
        this.emit({ type: 'suid_added', severity: risky ? 'critical' : pkg ? 'info' : 'high', message: `New SUID/SGID file: /${p}${pkg ? ' (package-managed)' : ''}`, data: { file: p, package: pkg } });
      }
    }
    this.state.suid = found;
  }

  // ---- kernel modules ----
  private modules() {
    const bad = unknownKernelModules();
    if (!this.seenMods.size && this.state.persist === undefined) {
      bad.forEach((m) => this.seenMods.add(m)); // first run: record, do not alert
      return;
    }
    for (const m of bad) {
      if (this.seenMods.has(m)) continue;
      this.seenMods.add(m);
      this.emit({ type: 'unknown_kernel_module', severity: 'high', message: `Kernel module "${m}" is loaded but is not part of the installed kernel: possible rootkit`, data: { module: m } });
    }
  }

  // ---- running processes ----
  private processes() {
    let pids: string[];
    try {
      pids = readdirSync(hp('proc')).filter((n) => /^\d+$/.test(n));
    } catch {
      return;
    }
    for (const pid of pids) {
      if (Number(pid) === this.ownPid) continue;
      const base = hp(`proc/${pid}`);
      let comm: string;
      try {
        comm = readFileSync(`${base}/comm`, 'utf8').trim();
      } catch {
        continue;
      }
      const startKey = (extra: string) => `${pid}:${extra}`;
      const flag = (key: string, ev: AgentEvent) => {
        if (this.seenProc.has(key)) return;
        if (this.seenProc.size > 5000) this.seenProc.clear();
        this.seenProc.add(key);
        this.emit(ev);
      };
      let exe = '';
      try {
        exe = readlinkSync(`${base}/exe`);
      } catch {
        /* kernel thread or no permission */
      }

      if (SHELLS.has(comm)) {
        try {
          if (readlinkSync(`${base}/fd/0`).startsWith('socket:') && readlinkSync(`${base}/fd/1`).startsWith('socket:')) {
            flag(startKey('rs'), { type: 'reverse_shell', severity: 'critical', message: `A shell (pid ${pid}) has its input and output wired to a network socket: likely a reverse shell`, data: { pid: Number(pid), exe } });
          }
        } catch {
          /* fds not readable */
        }
      }
      if (exe && (/^\/(tmp|var\/tmp|dev\/shm)\//.test(exe) || exe.startsWith('/memfd:'))) {
        flag(startKey('tmp'), { type: 'suspicious_process', severity: 'high', message: `Process ${comm} (pid ${pid}) runs from ${exe}`, data: { pid: Number(pid), exe } });
      }
      let cmd = '';
      if (MINER_NAME.test(comm) || MINER_NAME.test(exe.split('/').pop() ?? '')) cmd = comm;
      else {
        try {
          const args = readFileSync(`${base}/cmdline`, 'utf8').replaceAll('\0', ' ').slice(0, 600);
          if (MINER_ARGS.test(args) && !/(grep|rg|oculyx|journalctl|less|vim?|nano)/.test(comm)) cmd = args.slice(0, 100);
        } catch {
          /* gone */
        }
      }
      if (cmd) flag(startKey('miner'), { type: 'cryptominer', severity: 'critical', message: `Crypto-miner suspected: ${comm} (pid ${pid}) ${cmd}`.slice(0, 200), data: { pid: Number(pid), exe } });
    }
  }
}

/** Out-of-tree kernel modules: loaded but not part of the installed kernel's module set. */
export function unknownKernelModules(): string[] {
  const rel = readText(hp('proc/sys/kernel/osrelease'))?.trim();
  if (!rel) return [];
  const dep = readText(hp(`lib/modules/${rel}/modules.dep`));
  if (!dep) return [];
  const known = new Set([...dep.matchAll(/\/([\w.+-]+?)\.ko(?:\.\w+)?:/g)].map((m) => m[1].replaceAll('-', '_')));
  const loaded = (readText(hp('proc/modules')) ?? '').split('\n').map((l) => l.split(' ')[0]).filter(Boolean);
  return loaded.filter((m) => !known.has(m.replaceAll('-', '_')));
}

