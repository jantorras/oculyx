import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { closeSync, existsSync, openSync, readFileSync, readdirSync, readSync, statSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { hp, isLinux, readText, HOST_ROOT } from './host.ts';
import { runControls, score } from './sca.ts';
import type { AgentEvent } from './protocol.ts';

/** What the server tells this agent to check. Sent whole on connect and whenever it changes. */
export interface ChecksConfig {
  fim: { enabled: boolean; paths: string[]; exclude: string[]; everyMin: number };
  cve: { enabled: boolean };
  sca: { enabled: boolean };
  logs: { enabled: boolean; presets: string[]; custom: { name: string; file: string; pattern: string; severity: string }[] };
  inventory: { enabled: boolean };
}
export const DEFAULT_CHECKS: ChecksConfig = {
  fim: { enabled: true, paths: [], exclude: [], everyMin: 10 },
  cve: { enabled: true },
  sca: { enabled: true },
  logs: { enabled: false, presets: [], custom: [] },
  inventory: { enabled: true },
};

const LOG_PRESETS: Record<string, { name: string; files: string[]; pattern: string; severity: string }> = {
  web_attacks: {
    name: 'Web attack patterns',
    files: ['var/log/nginx/access.log', 'var/log/apache2/access.log', 'var/log/httpd/access_log'],
    pattern: '(union(\\s|%20|\\+)+select|\\.\\./\\.\\./|<script|/etc/passwd|/\\.env|/\\.git/|phpmyadmin|wp-config|\\$\\{jndi:)',
    severity: 'medium',
  },
  oom: { name: 'Out of memory kills', files: ['var/log/syslog', 'var/log/messages', 'var/log/kern.log'], pattern: 'Out of memory|oom-kill|Killed process \\d+', severity: 'high' },
  disk_errors: { name: 'Disk errors', files: ['var/log/syslog', 'var/log/messages', 'var/log/kern.log'], pattern: 'I/O error|EXT4-fs error|XFS \\(.*\\) .*error|Buffer I/O error|blk_update_request', severity: 'high' },
};

const MAX_FILES = 5000;
const MAX_HASH_BYTES = 8 * 1024 * 1024;

const sha = (b: Buffer | string) => createHash('sha256').update(b).digest('hex');

/** Runs the optional checks (custom FIM, log rules, configuration audit, inventory) on a schedule. */
export class ChecksRunner {
  private cfg: ChecksConfig = DEFAULT_CHECKS;
  private events: AgentEvent[] = [];
  private messages: unknown[] = [];
  private last: Record<string, number> = {};
  private fimBase: Record<string, Record<string, string>> = {};
  private fimFile: string;
  private cfgFile: string;
  private offsets = new Map<string, number>();
  private invHash = '';
  private scaPrev = new Map<string, string>();
  private stateDir: string;

  constructor(stateDir: string) {
    this.stateDir = stateDir;
    this.fimFile = join(stateDir, 'fim-custom.json');
    this.cfgFile = join(stateDir, 'checks-config.json');
    try {
      if (existsSync(this.fimFile)) this.fimBase = JSON.parse(readFileSync(this.fimFile, 'utf8'));
      if (existsSync(this.cfgFile)) this.cfg = { ...DEFAULT_CHECKS, ...JSON.parse(readFileSync(this.cfgFile, 'utf8')) };
    } catch {
      /* start from defaults */
    }
  }

  configure(c: ChecksConfig) {
    this.cfg = { ...DEFAULT_CHECKS, ...c };
    try {
      mkdirSync(this.stateDir, { recursive: true });
      writeFileSync(this.cfgFile, JSON.stringify(this.cfg));
    } catch {
      /* not fatal */
    }
    // new settings: look again soon
    this.last.sca = 0;
    this.last.fim = 0;
    this.last.inv = 0;
  }

  drainEvents(): AgentEvent[] {
    return this.events.splice(0);
  }
  drainMessages(): unknown[] {
    return this.messages.splice(0);
  }

  /** Called every few seconds. */
  tick() {
    if (!isLinux) return;
    const now = Date.now();
    const due = (k: string, ms: number) => now - (this.last[k] ?? 0) >= ms && ((this.last[k] = now), true);
    if (this.cfg.logs.enabled) this.safe(() => this.logs());
    if (this.cfg.fim.enabled && this.cfg.fim.paths.length && due('fim', Math.max(1, this.cfg.fim.everyMin) * 60_000)) this.safe(() => this.fim());
    if (this.cfg.sca.enabled && due('sca', 6 * 3600_000)) this.safe(() => this.sca());
    if ((this.cfg.inventory.enabled || this.cfg.cve.enabled) && due('inv', 3600_000)) this.safe(() => this.inventory(false));
  }

  /** "Run now" from the panel. */
  runNow(which: string) {
    if (!isLinux) return { ok: false };
    if (which === 'fim') this.fim();
    else if (which === 'sca') this.sca();
    else if (which === 'inventory' || which === 'cve') this.inventory(true);
    return { ok: true };
  }

  private safe(fn: () => void) {
    try {
      fn();
    } catch {
      /* a failing check must never stop the others */
    }
  }

  // ---- custom file integrity monitoring ----
  private walk(root: string, exclude: string[], out: string[]) {
    const skip = (p: string) => exclude.some((x) => (x.startsWith('*') ? p.endsWith(x.slice(1)) : p.includes(x)));
    const visit = (p: string, depth: number) => {
      if (out.length >= MAX_FILES || depth > 8 || skip(p)) return;
      let st;
      try {
        st = statSync(hp(p));
      } catch {
        return;
      }
      if (st.isDirectory()) {
        let names: string[] = [];
        try {
          names = readdirSync(hp(p));
        } catch {
          return;
        }
        for (const n of names.sort()) visit(`${p.replace(/\/$/, '')}/${n}`, depth + 1);
      } else if (st.isFile()) out.push(p);
    };
    visit(root, 0);
  }

  private signature(p: string): string | null {
    try {
      const st = statSync(hp(p));
      const meta = `${(st.mode & 0o7777).toString(8)}:${st.uid}:${st.size}`;
      if (st.size > MAX_HASH_BYTES) return `big:${meta}:${Math.floor(st.mtimeMs)}`;
      return `${sha(readFileSync(hp(p)))}:${meta}`;
    } catch {
      return null;
    }
  }

  private fim() {
    const { paths, exclude } = this.cfg.fim;
    let dirty = false;
    for (const root of paths) {
      const files: string[] = [];
      this.walk(root, exclude, files);
      const cur: Record<string, string> = {};
      for (const f of files) {
        const s = this.signature(f);
        if (s) cur[f] = s;
      }
      const prev = this.fimBase[root];
      this.fimBase[root] = cur;
      dirty = true;
      if (!prev) continue; // first look at this path: learn, do not alert
      const added = Object.keys(cur).filter((f) => !(f in prev));
      const removed = Object.keys(prev).filter((f) => !(f in cur));
      const changed = Object.keys(cur).filter((f) => f in prev && prev[f] !== cur[f]);
      const total = added.length + removed.length + changed.length;
      if (!total) continue;
      const names = [...changed.map((f) => `~ ${f}`), ...added.map((f) => `+ ${f}`), ...removed.map((f) => `- ${f}`)];
      this.events.push({
        type: 'fim_custom',
        severity: 'high',
        message: `${total} change(s) in ${root}: ${names.slice(0, 3).join(', ')}${total > 3 ? ', …' : ''}`,
        data: { path: root, count: total, changed: changed.length, added: added.length, removed: removed.length, files: names.slice(0, 20), key: `${root}:${sha(names.join('|')).slice(0, 10)}` },
      });
    }
    for (const k of Object.keys(this.fimBase)) if (!paths.includes(k)) delete this.fimBase[k];
    if (dirty) {
      try {
        writeFileSync(this.fimFile, JSON.stringify(this.fimBase));
      } catch {
        /* keep going in memory */
      }
    }
  }

  // ---- log rules ----
  private rules(): { name: string; files: string[]; re: RegExp; severity: string }[] {
    const out: { name: string; files: string[]; re: RegExp; severity: string }[] = [];
    for (const id of this.cfg.logs.presets) {
      const p = LOG_PRESETS[id];
      if (p) out.push({ name: p.name, files: p.files, re: new RegExp(p.pattern, 'i'), severity: p.severity });
    }
    for (const c of this.cfg.logs.custom.slice(0, 20)) {
      try {
        if (c.pattern.length <= 200 && c.file.startsWith('/')) out.push({ name: c.name.slice(0, 60), files: [c.file.slice(1)], re: new RegExp(c.pattern, 'i'), severity: c.severity });
      } catch {
        /* invalid pattern: skip */
      }
    }
    return out;
  }

  private logs() {
    const byFile = new Map<string, { name: string; re: RegExp; severity: string }[]>();
    for (const r of this.rules()) for (const f of r.files) byFile.set(f, [...(byFile.get(f) ?? []), r]);
    const hits = new Map<string, { file: string; severity: string; n: number; sample: string[] }>();
    for (const [file, rules] of byFile) {
      const p = hp(file);
      let size: number;
      try {
        size = statSync(p).size;
      } catch {
        continue;
      }
      const prev = this.offsets.get(file);
      this.offsets.set(file, size);
      if (prev === undefined) continue; // start at the end: only new lines count
      const from = size < prev ? 0 : prev;
      const len = Math.min(size - from, 512 * 1024);
      if (len <= 0) continue;
      const buf = Buffer.alloc(len);
      const fd = openSync(p, 'r');
      try {
        readSync(fd, buf, 0, len, size - len);
      } finally {
        closeSync(fd);
      }
      for (const line of buf.toString('utf8').split('\n')) {
        if (!line || line.length > 2000) continue;
        for (const r of rules) {
          if (!r.re.test(line)) continue;
          const h = hits.get(r.name) ?? { file, severity: r.severity, n: 0, sample: [] };
          h.n++;
          if (h.sample.length < 3) h.sample.push(line.slice(0, 200));
          hits.set(r.name, h);
        }
      }
    }
    for (const [name, h] of hits) {
      this.events.push({
        type: 'log_match',
        severity: (['critical', 'high', 'medium', 'low'].includes(h.severity) ? h.severity : 'medium') as AgentEvent['severity'],
        message: `${name}: ${h.n} match(es) in /${h.file}`,
        data: { rule: name, file: `/${h.file}`, count: h.n, sample: h.sample, key: name },
      });
    }
  }

  // ---- configuration audit ----
  private sca() {
    const controls = runControls();
    for (const c of controls) {
      const was = this.scaPrev.get(c.id);
      if (was === 'pass' && c.status === 'fail') {
        this.events.push({ type: 'sca_regression', severity: c.severity === 'high' ? 'high' : 'medium', message: `Configuration check failed: ${c.title}`, data: { id: c.id, key: c.id, detail: c.detail ?? '' } });
      }
      this.scaPrev.set(c.id, c.status);
    }
    this.messages.push({ t: 'sca', ts: Date.now(), score: score(controls), controls });
  }

  // ---- inventory (packages and enabled services), also feeds the vulnerability scan ----
  private inventory(force: boolean) {
    const os = osRelease();
    const packages = listPackages();
    const services = enabledServices();
    const h = sha(JSON.stringify([os.id, os.version, packages, services]));
    if (!force && h === this.invHash) return;
    this.invHash = h;
    this.messages.push({ t: 'inventory', ts: Date.now(), os, packages, services });
  }
}

export function osRelease(): { id: string; version: string; name: string } {
  const t = readText(hp('etc/os-release')) ?? '';
  const get = (k: string) => t.match(new RegExp(`^${k}=("?)(.*)\\1$`, 'm'))?.[2] ?? '';
  return { id: get('ID').toLowerCase(), version: get('VERSION_ID'), name: get('PRETTY_NAME') };
}

/** [name, version, source package] triples, from the package databases (no package manager needed for dpkg and apk). */
export function listPackages(): [string, string, string][] {
  const out: [string, string, string][] = [];
  for (const b of readText(hp('var/lib/dpkg/status'))?.split('\n\n') ?? []) {
    if (!/^Status: .* installed$/m.test(b)) continue;
    const name = b.match(/^Package: (.+)$/m)?.[1];
    const ver = b.match(/^Version: (.+)$/m)?.[1];
    if (!name || !ver) continue;
    const src = b.match(/^Source: (\S+)/m)?.[1] ?? name;
    out.push([name, ver, src]);
  }
  if (!out.length) {
    for (const b of readText(hp('lib/apk/db/installed'))?.split('\n\n') ?? []) {
      const name = b.match(/^P:(.+)$/m)?.[1];
      const ver = b.match(/^V:(.+)$/m)?.[1];
      if (name && ver) out.push([name, ver, b.match(/^o:(.+)$/m)?.[1] ?? name]);
    }
  }
  if (!out.length) {
    try {
      const args = ['-qa', '--qf', '%{NAME}\t%{VERSION}-%{RELEASE}\t%{SOURCERPM}\n', ...(HOST_ROOT ? ['--root', HOST_ROOT] : [])];
      for (const l of execFileSync('rpm', args, { encoding: 'utf8', timeout: 20_000, maxBuffer: 16 * 1024 * 1024 }).split('\n')) {
        const [n, v, s] = l.split('\t');
        if (n && v) out.push([n, v, s ? s.replace(/-[^-]+-[^-]+\.src\.rpm$/, '') : n]);
      }
    } catch {
      /* no rpm */
    }
  }
  return out.sort((a, b) => a[0].localeCompare(b[0]));
}

function enabledServices(): string[] {
  const out = new Set<string>();
  try {
    for (const d of readdirSync(hp('etc/systemd/system'))) {
      if (!d.endsWith('.wants')) continue;
      for (const f of readdirSync(hp(`etc/systemd/system/${d}`))) if (f.endsWith('.service')) out.add(f.slice(0, -8));
    }
  } catch {
    /* not systemd */
  }
  return [...out].sort();
}
