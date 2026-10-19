import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, existsSync, statSync, openSync, readSync, closeSync } from 'node:fs';
import { join } from 'node:path';
import { hp, readText, isLinux } from './host.ts';
import { inspect, listContainers } from './docker.ts';
import type { AgentEvent, Finding, Port, SecuritySnapshot } from './protocol.ts';

const RISKY_PORTS: Record<number, string> = {
  21: 'FTP', 23: 'Telnet', 111: 'rpcbind', 445: 'SMB', 2375: 'Docker API (unencrypted)', 3306: 'MySQL', 5432: 'PostgreSQL',
  5900: 'VNC', 6379: 'Redis', 9200: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB',
};
const FIM_FILES = ['etc/passwd', 'etc/shadow', 'etc/sudoers', 'etc/ssh/sshd_config', 'root/.ssh/authorized_keys', 'etc/crontab', 'etc/hosts'];

export class SecurityScanner {
  private events: AgentEvent[] = [];
  private knownPorts: Set<string> | null = null;
  private failures = new Map<string, { at: number[]; users: Set<string> }>();
  private authOffset = new Map<string, number>();
  private fimBaseline: Record<string, string> = {};
  private fimFile: string;

  private stateDir: string;
  private dockerOn: () => boolean;
  constructor(stateDir: string, dockerOn: () => boolean) {
    this.stateDir = stateDir;
    this.dockerOn = dockerOn;
    this.fimFile = join(stateDir, 'fim.json');
    if (existsSync(this.fimFile)) this.fimBaseline = JSON.parse(readFileSync(this.fimFile, 'utf8'));
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
    findings.push(...this.sshConfig(), ...this.accounts(), ...this.firewall(), ...this.fim(), ...this.authLog(), ...this.systemState());
    if (this.dockerOn()) findings.push(...(await this.dockerChecks().catch(() => [])));
    return { findings, ports };
  }

  // ---- listening sockets, straight from /proc ----
  private listeningPorts(): Port[] {
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

  // ---- sshd hardening ----
  private sshConfig(): Finding[] {
    const txt = readText(hp('etc/ssh/sshd_config'));
    if (!txt) return [];
    const val = (k: string) => {
      const m = [...txt.matchAll(new RegExp(`^\\s*${k}\\s+(\\S+)`, 'gim'))].pop();
      return m?.[1].toLowerCase();
    };
    const out: Finding[] = [];
    const root = val('PermitRootLogin');
    if (root === 'yes') out.push({ checkId: 'ssh:root-login', severity: 'high', title: 'SSH permits root login', detail: 'Set "PermitRootLogin no" (or prohibit-password) in sshd_config.' });
    if (val('PasswordAuthentication') !== 'no') out.push({ checkId: 'ssh:password-auth', severity: 'medium', title: 'SSH password authentication enabled', detail: 'Prefer key-based auth: "PasswordAuthentication no".' });
    if (val('PermitEmptyPasswords') === 'yes') out.push({ checkId: 'ssh:empty-pw', severity: 'critical', title: 'SSH permits empty passwords', detail: 'Set "PermitEmptyPasswords no".' });
    return out;
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

  private firewall(): Finding[] {
    const ufw = readText(hp('etc/ufw/ufw.conf'));
    const hasFw = (ufw && /ENABLED=yes/i.test(ufw)) || existsSync(hp('etc/nftables.conf')) || existsSync(hp('usr/sbin/firewalld'));
    if (ufw === null && !hasFw) return [];
    return hasFw ? [] : [{ checkId: 'fw:inactive', severity: 'medium', title: 'No active host firewall detected', detail: 'ufw is installed but disabled. Enable it: ufw allow OpenSSH && ufw enable' }];
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

  // ---- auth log: brute force detection ----
  private authLog(): Finding[] {
    const now = Date.now();
    for (const file of ['var/log/auth.log', 'var/log/secure']) {
      const path = hp(file);
      let size: number;
      try {
        size = statSync(path).size;
      } catch {
        continue;
      }
      let start = this.authOffset.get(file) ?? Math.max(0, size - 256 * 1024);
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
    }
    const out: Finding[] = [];
    for (const [ip, v] of this.failures) {
      v.at = v.at.filter((t) => now - t < 3600_000);
      if (!v.at.length) this.failures.delete(ip);
      else if (v.at.length >= 10) out.push({ checkId: `ssh:bruteforce:${ip}`, severity: 'high', title: `SSH brute-force from ${ip}`, detail: `${v.at.length} failed logins in the last hour (users: ${[...v.users].slice(0, 6).join(', ')}). Consider blocking the address or installing fail2ban.` });
    }
    return out;
  }

  private parseAuth(text: string, now: number) {
    const burst = new Map<string, number>();
    for (const line of text.split('\n')) {
      const f = line.match(/Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)/) ?? line.match(/Invalid user (\S+) from (\S+)/);
      if (f) {
        const rec = this.failures.get(f[2]) ?? { at: [], users: new Set<string>() };
        rec.at.push(now);
        rec.users.add(f[1]);
        this.failures.set(f[2], rec);
        burst.set(f[2], (burst.get(f[2]) ?? 0) + 1);
        continue;
      }
      const ok = line.match(/Accepted (password|publickey) for (\S+) from (\S+)/);
      if (ok) this.events.push({ type: 'ssh_login', severity: ok[1] === 'password' ? 'low' : 'info', message: `SSH login: ${ok[2]} from ${ok[3]} (${ok[1]})`, data: { user: ok[2], ip: ok[3], method: ok[1] } });
      const sudo = line.match(/sudo:\s+(\S+) : .*COMMAND=(.+)$/);
      if (sudo) this.events.push({ type: 'sudo', severity: 'info', message: `sudo by ${sudo[1]}: ${sudo[2].slice(0, 120)}`, data: { user: sudo[1] } });
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
