import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, existsSync, statSync, openSync, readSync, closeSync } from 'node:fs';
import { join } from 'node:path';
import { hp, readText, isLinux, HOST_ROOT } from './host.ts';
import { IntrusionWatcher } from './intrusion.ts';
import { inspect, listContainers } from './docker.ts';
import { hardeningChecks } from './hardening.ts';
import type { AgentEvent, Finding, Port, SecuritySnapshot } from './protocol.ts';

const RISKY_PORTS: Record<number, string> = {
  21: 'FTP', 23: 'Telnet', 111: 'rpcbind', 445: 'SMB', 2375: 'Docker API (unencrypted)', 3306: 'MySQL', 5432: 'PostgreSQL',
  5900: 'VNC', 6379: 'Redis', 9200: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB',
};
const FIM_FILES = ['etc/passwd', 'etc/shadow', 'etc/sudoers', 'etc/ssh/sshd_config', 'root/.ssh/authorized_keys', 'etc/crontab', 'etc/hosts'];

const SUSPICIOUS: { re: RegExp; reason: string; severity: AgentEvent['severity'] }[] = [
  { re: /^\S*(ba|da|z|k|a|c)?sh(\s+-\w+)*\s*$/, reason: 'interactive root shell', severity: 'medium' },
  { re: /^\S*\/su(\s+-\w*)?(\s+root)?\s*$/, reason: 'switch to root', severity: 'medium' },
  { re: /\b(chmod|chown)\b.*(\bu\+s\b|\+s\b|\b[2467][0-7]{3}\b)/, reason: 'setting the SUID/SGID bit', severity: 'high' },
  { re: /\b(useradd|adduser|usermod|userdel|chpasswd|visudo)\b/, reason: 'account or sudoers change', severity: 'high' },
  { re: /\bpasswd\b(?!\s+-[lSe])/, reason: 'password change', severity: 'medium' },
  { re: /\b(nc|ncat|netcat|socat)\b.*(\s-e\b|\sexec:|\s-c\b)/, reason: 'network shell tool', severity: 'critical' },
  { re: /\/dev\/(tcp|udp)\//, reason: 'raw network redirection', severity: 'critical' },
  { re: /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|da|z)?sh\b/, reason: 'downloaded script piped to a shell', severity: 'high' },
  { re: /\bbase64\b.*(-d|--decode)/, reason: 'decoding a payload', severity: 'high' },
  { re: /\b(python\d?|perl|ruby|php)\b.*\s-(c|e|r)\s.*(socket|exec|system|subprocess|pty)/, reason: 'scripted network shell', severity: 'critical' },
  { re: /\b(history\s+-c|HISTFILE=|HISTSIZE=0|unset\s+HISTFILE)/, reason: 'clearing command history', severity: 'high' },
  { re: /\b(rm|truncate|shred)\b.*\/var\/log\//, reason: 'deleting logs', severity: 'critical' },
  { re: /\b(iptables|ip6tables|nft)\b.*(-F\b|flush)|\bufw\b.*\b(disable|reset)\b/, reason: 'disabling the firewall', severity: 'high' },
  { re: /\bsystemctl\b.*\b(stop|disable|mask)\b.*\b(auditd|rsyslog|fail2ban|ufw|apparmor|oculyx)/, reason: 'stopping a security service', severity: 'high' },
  { re: /\bcrontab\b|\bat\s+now\b/, reason: 'scheduling a task', severity: 'medium' },
  { re: /\b(chattr)\s+[-+]i\b/, reason: 'making files immutable', severity: 'high' },
];

export function suspiciousCommand(cmd: string): { reason: string; severity: AgentEvent['severity'] } | null {
  const c = cmd.trim();
  for (const r of SUSPICIOUS) if (r.re.test(c)) return { reason: r.reason, severity: r.severity };
  return null;
}

export class SecurityScanner {
  private events: AgentEvent[] = [];
  private knownPorts: Set<string> | null = null;
  private failures = new Map<string, { at: number[]; users: Set<string> }>();
  private authOffset = new Map<string, number>();
  private journalCursor = '';
  private watcher: IntrusionWatcher;
  private fimBaseline: Record<string, string> = {};
  private fimFile: string;

  private stateDir: string;
  private dockerOn: () => boolean;
  constructor(stateDir: string, dockerOn: () => boolean) {
    this.stateDir = stateDir;
    this.dockerOn = dockerOn;
    this.fimFile = join(stateDir, 'fim.json');
    if (existsSync(this.fimFile)) this.fimBaseline = JSON.parse(readFileSync(this.fimFile, 'utf8'));
    this.watcher = new IntrusionWatcher(stateDir, (e) => this.events.push(e));
    this.loadAuthState();
  }

  /** Called every few seconds by the connection loop: log tailing and intrusion collectors. */
  tick() {
    if (!isLinux) return;
    try {
      this.pollAuth();
    } catch {
      /* never break the loop */
    }
    this.watcher.tick();
  }

  /** The panel changed authorized_keys itself; do not report that as an intruder's key. */
  acceptKeys() {
    this.watcher.acceptKeys();
  }

  drainEvents(): AgentEvent[] {
    return this.events.splice(0);
  }

  async scan(): Promise<SecuritySnapshot> {
    if (!isLinux) return { findings: [], ports: [] };
    const findings: Finding[] = [];
    const ports = this.listeningPorts();
    this.diffPorts(ports);
    for (const p of ports.filter((x) => x.exposed && RISKY_PORTS[x.port])) {
      findings.push({ checkId: `port:${p.proto}:${p.port}`, severity: p.port === 2375 ? 'critical' : 'high', title: `${RISKY_PORTS[p.port]} exposed on port ${p.port}`, detail: `Listening on ${p.addr}:${p.port}/${p.proto}. Bind it to localhost or restrict it with a firewall.` });
    }
    findings.push(...hardeningChecks(() => this.exposedTcpPorts()), ...this.accounts(), ...this.fim(), ...this.authLog(), ...this.systemState());
    if (this.dockerOn()) findings.push(...(await this.dockerChecks().catch(() => [])));
    return { findings, ports };
  }

  // ---- listening sockets, straight from /proc ----
  exposedTcpPorts(): number[] {
    return this.listeningPorts().filter((p) => p.exposed && p.proto.startsWith('tcp')).map((p) => p.port);
  }

  listeningPorts(): Port[] {
    const out: Port[] = [];
    for (const [file, proto, v6] of [['proc/net/tcp', 'tcp', false], ['proc/net/tcp6', 'tcp6', true], ['proc/net/udp', 'udp', false]] as const) {
      const txt = readText(hp(file));
      for (const l of txt?.split('\n').slice(1) ?? []) {
        const f = l.trim().split(/\s+/);
        if (f.length < 4) continue;
        const listening = proto === 'udp' ? f[3] === '07' : f[3] === '0A';
        if (!listening) continue;
        const [hexAddr, hexPort] = f[1].split(':');
        const port = parseInt(hexPort, 16);
        const any = /^0+$/.test(hexAddr);
        const loop = v6 ? hexAddr === '00000000000000000000000001000000' : hexAddr.endsWith('7F') && hexAddr.length === 8;
        out.push({ port, proto, addr: any ? (v6 ? '::' : '0.0.0.0') : loop ? 'loopback' : 'iface', exposed: !loop });
      }
    }
    const seen = new Set<string>();
    return out.filter((p) => !seen.has(`${p.proto}${p.port}${p.exposed}`) && seen.add(`${p.proto}${p.port}${p.exposed}`)).sort((a, b) => a.port - b.port);
  }

  private diffPorts(ports: Port[]) {
    const now = new Set(ports.filter((p) => p.exposed && p.proto !== 'udp').map((p) => `${p.proto}/${p.port}`));
    if (this.knownPorts) {
      for (const k of now) if (!this.knownPorts.has(k)) this.events.push({ type: 'port_opened', severity: 'medium', message: `New listening port ${k}`, data: { port: k } });
      for (const k of this.knownPorts) if (!now.has(k)) this.events.push({ type: 'port_closed', severity: 'info', message: `Port ${k} no longer listening`, data: { port: k } });
    }
    this.knownPorts = now;
  }

  // ---- local accounts ----
  private accounts(): Finding[] {
    const out: Finding[] = [];
    const passwd = readText(hp('etc/passwd'));
    const extraRoot = passwd?.split('\n').filter((l) => l.split(':')[2] === '0' && !l.startsWith('root:')).map((l) => l.split(':')[0]) ?? [];
    if (extraRoot.length) out.push({ checkId: 'acct:uid0', severity: 'critical', title: 'Extra accounts with UID 0', detail: extraRoot.join(', ') });
    const shadow = readText(hp('etc/shadow'));
    const empty = shadow?.split('\n').filter((l) => l.split(':')[1] === '').map((l) => l.split(':')[0]).filter(Boolean) ?? [];
    if (empty.length) out.push({ checkId: 'acct:empty-pw', severity: 'critical', title: 'Accounts with empty password', detail: empty.join(', ') });
    return out;
  }

  private systemState(): Finding[] {
    const out: Finding[] = [];
    if (existsSync(hp('var/run/reboot-required'))) out.push({ checkId: 'sys:reboot', severity: 'low', title: 'Reboot required', detail: 'Pending kernel/library updates need a reboot.' });
    const upd = readText(hp('var/lib/update-notifier/updates-available'));
    const m = upd?.match(/(\d+) (?:updates?|paquetes?) can be applied/) ?? upd?.match(/(\d+) update/);
    const sec = upd?.match(/(\d+) of these updates are security/);
    if (sec && Number(sec[1]) > 0) out.push({ checkId: 'sys:sec-updates', severity: 'high', title: `${sec[1]} pending security updates`, detail: 'Run: apt update && apt upgrade' });
    else if (m && Number(m[1]) > 0) out.push({ checkId: 'sys:updates', severity: 'low', title: `${m[1]} pending package updates`, detail: 'Run: apt update && apt upgrade' });
    return out;
  }

  // ---- file integrity monitoring ----
  private fim(): Finding[] {
    const cur: Record<string, string> = {};
    for (const f of FIM_FILES) {
      try {
        cur[f] = createHash('sha256').update(readFileSync(hp(f))).digest('hex');
      } catch {
        /* missing or unreadable */
      }
    }
    if (!Object.keys(this.fimBaseline).length) {
      this.saveBaseline(cur);
      return [];
    }
    const out: Finding[] = [];
    for (const f of Object.keys({ ...cur, ...this.fimBaseline })) {
      if (cur[f] !== this.fimBaseline[f]) {
        const what = !cur[f] ? 'deleted' : !this.fimBaseline[f] ? 'created' : 'modified';
        out.push({ checkId: `fim:${f}`, severity: f.includes('shadow') || f.includes('sudoers') || f.includes('authorized_keys') ? 'high' : 'medium', title: `File ${what}: /${f}`, detail: 'Differs from the recorded baseline. If the change was intentional, accept it as the new baseline.' });
        if (!this.events.some((e) => e.type === 'fim' && e.data?.file === f)) this.events.push({ type: 'fim', severity: 'medium', message: `/${f} ${what}`, data: { file: f } });
      }
    }
    return out;
  }
  private saveBaseline(b: Record<string, string>) {
    this.fimBaseline = b;
    mkdirSync(this.stateDir, { recursive: true });
    writeFileSync(this.fimFile, JSON.stringify(b));
  }
  rebaseline() {
    const cur: Record<string, string> = {};
    for (const f of FIM_FILES) {
      try {
        cur[f] = createHash('sha256').update(readFileSync(hp(f))).digest('hex');
      } catch {
        /* skip */
      }
    }
    this.saveBaseline(cur);
  }

  // ---- auth log: logins, brute force, sudo, su ----
  /** Reads whatever the auth log (or the journal) gained since the last call. Runs every few seconds. */
  pollAuth() {
    const now = Date.now();
    let anyFile = false;
    for (const file of ['var/log/auth.log', 'var/log/secure']) {
      const path = hp(file);
      let size: number;
      try {
        size = statSync(path).size;
      } catch {
        continue;
      }
      anyFile = true;
      let start = this.authOffset.get(file);
      if (start === undefined) start = size; // first run: only look forward
      if (size < start) start = 0; // rotated
      const len = Math.min(size - start, 1024 * 1024);
      if (len > 0) {
        const buf = Buffer.alloc(len);
        const fd = openSync(path, 'r');
        readSync(fd, buf, 0, len, start);
        closeSync(fd);
        this.parseAuth(buf.toString('utf8'), now);
      }
      this.authOffset.set(file, start + len);
      this.saveAuthState();
    }
    if (!anyFile) this.pollJournal(now);
  }

  private authStateFile() {
    return join(this.stateDir, 'auth-state.json');
  }
  private saveAuthState() {
    try {
      writeFileSync(this.authStateFile(), JSON.stringify({ offsets: Object.fromEntries(this.authOffset), cursor: this.journalCursor }));
    } catch {
      /* best effort */
    }
  }
  private loadAuthState() {
    try {
      const j = JSON.parse(readFileSync(this.authStateFile(), 'utf8'));
      for (const [k, v] of Object.entries(j.offsets ?? {})) this.authOffset.set(k, Number(v));
      this.journalCursor = j.cursor ?? '';
    } catch {
      /* first run */
    }
  }

  /** Debian 12+ and other journald-only systems have no /var/log/auth.log. */
  private pollJournal(now: number) {
    if (HOST_ROOT) return; // the container has no journalctl
    const args = ['--no-pager', '-q', '-o', 'short-iso', '--show-cursor', '-t', 'sshd', '-t', 'sshd-session', '-t', 'sudo', '-t', 'su'];
    if (this.journalCursor) args.push('--after-cursor', this.journalCursor);
    else args.push('--since', '-1min');
    let out: string;
    try {
      out = execFileSync('journalctl', args, { encoding: 'utf8', timeout: 10_000, maxBuffer: 8 * 1024 * 1024, stdio: ['ignore', 'pipe', 'ignore'] });
    } catch {
      return;
    }
    const lines = out.split('\n');
    const cur = lines.reverse().find((l) => l.startsWith('-- cursor: '));
    if (cur) this.journalCursor = cur.slice(11).trim();
    this.parseAuth(out.split('\n').filter((l) => !l.startsWith('-- cursor')).join('\n'), now);
    this.saveAuthState();
  }

  private bruteForceFindings(): Finding[] {
    const now = Date.now();
    const out: Finding[] = [];
    for (const [ip, v] of this.failures) {
      v.at = v.at.filter((t) => now - t < 3600_000);
      if (!v.at.length) this.failures.delete(ip);
      else if (v.at.length >= 10) out.push({ checkId: `ssh:bruteforce:${ip}`, severity: 'high', title: `SSH brute-force from ${ip}`, detail: `${v.at.length} failed logins in the last hour (users: ${[...v.users].slice(0, 6).join(', ')}). Install fail2ban from the host's hardening list, or block the address.` });
    }
    return out;
  }

  private authLog(): Finding[] {
    this.pollAuth();
    return this.bruteForceFindings();
  }

  private parseAuth(text: string, now: number) {
    const burst = new Map<string, number>();
    for (const line of text.split('\n')) {
      const f = line.match(/Failed (?:password|publickey|keyboard-interactive\S*) for (?:invalid user )?(\S+) from (\S+)/) ?? line.match(/Invalid user (\S+) from (\S+)/);
      if (f) {
        const rec = this.failures.get(f[2]) ?? { at: [], users: new Set<string>() };
        rec.at.push(now);
        rec.users.add(f[1]);
        this.failures.set(f[2], rec);
        burst.set(f[2], (burst.get(f[2]) ?? 0) + 1);
        continue;
      }
      const ok = line.match(/Accepted (\S+) for (\S+) from (\S+)/);
      if (ok) {
        const method = ok[1].startsWith('keyboard') ? 'password' : ok[1];
        this.events.push({ type: 'ssh_login', severity: method === 'password' ? 'low' : 'info', message: `SSH login: ${ok[2]} from ${ok[3]} (${method})`, data: { user: ok[2], ip: ok[3], method } });
        const rec = this.failures.get(ok[3]);
        const recent = rec ? rec.at.filter((t) => now - t < 3600_000).length : 0;
        if (recent >= 3) this.events.push({ type: 'ssh_login_after_failures', severity: 'critical', message: `${ok[2]} logged in from ${ok[3]} right after ${recent} failed attempts from the same address: the password may have been guessed`, data: { user: ok[2], ip: ok[3], failures: recent } });
        continue;
      }
      const sudo = line.match(/sudo:\s+(\S+) : .*COMMAND=(.+)$/);
      if (sudo) {
        this.events.push({ type: 'sudo', severity: 'info', message: `sudo by ${sudo[1]}: ${sudo[2].slice(0, 120)}`, data: { user: sudo[1] } });
        const why = suspiciousCommand(sudo[2]);
        if (why) this.events.push({ type: 'sudo_suspicious', severity: why.severity, message: `Suspicious sudo by ${sudo[1]} (${why.reason}): ${sudo[2].slice(0, 140)}`, data: { user: sudo[1], reason: why.reason } });
        continue;
      }
      const su = line.match(/su(?:\[\d+\])?: \(to (\S+)\) (\S+) on/) ?? line.match(/su(?:\[\d+\])?: Successful su for (\S+) by (\S+)/);
      if (su) this.events.push({ type: 'su', severity: su[1] === 'root' ? 'low' : 'info', message: `su to ${su[1]} by ${su[2]}`, data: { to: su[1], user: su[2] } });
    }
    for (const [ip, n] of burst) if (n >= 5) this.events.push({ type: 'ssh_failed', severity: 'medium', message: `${n} failed SSH logins from ${ip}`, data: { ip, count: n } });
  }

  // ---- docker posture ----
  private async dockerChecks(): Promise<Finding[]> {
    const out: Finding[] = [];
    for (const c of (await listContainers()).filter((c) => c.state === 'running')) {
      const d = await inspect(c.id);
      const hc = d.HostConfig ?? {};
      const n = c.name;
      if (hc.Privileged) out.push({ checkId: `docker:priv:${n}`, severity: 'high', title: `Container ${n} runs privileged`, detail: 'Privileged containers can escape to the host. Drop --privileged and add only the capabilities it needs.' });
      if ((d.Mounts ?? []).some((m: any) => /docker\.sock$/.test(m.Source ?? ''))) out.push({ checkId: `docker:sock:${n}`, severity: 'high', title: `Container ${n} mounts the Docker socket`, detail: 'Equivalent to root on the host. Use a socket proxy with read-only scope if possible.' });
      if (hc.NetworkMode === 'host') out.push({ checkId: `docker:hostnet:${n}`, severity: 'medium', title: `Container ${n} uses host networking`, detail: 'It bypasses network isolation.' });
      if (hc.PidMode === 'host') out.push({ checkId: `docker:hostpid:${n}`, severity: 'medium', title: `Container ${n} shares the host PID namespace` });
      if (!d.Config?.User || d.Config.User === 'root' || d.Config.User === '0') out.push({ checkId: `docker:root:${n}`, severity: 'low', title: `Container ${n} runs as root`, detail: 'Set a non-root USER in the image or via --user.' });
      if (!hc.Memory) out.push({ checkId: `docker:nomem:${n}`, severity: 'info', title: `Container ${n} has no memory limit` });
      if (/:latest$/.test(c.image) || !c.image.includes(':')) out.push({ checkId: `docker:latest:${n}`, severity: 'low', title: `Container ${n} uses an unpinned image tag`, detail: `${c.image} - pin a version or digest for reproducible, auditable deployments.` });
      for (const p of c.ports) {
        const m = p.match(/^(0\.0\.0\.0|::)?:(\d+)->/);
        if (m && RISKY_PORTS[Number(m[2])]) out.push({ checkId: `docker:port:${n}:${m[2]}`, severity: 'high', title: `${RISKY_PORTS[Number(m[2])]} published to all interfaces by ${n}`, detail: `Bind to 127.0.0.1:${m[2]} instead.` });
      }
    }
    return out;
  }
}
