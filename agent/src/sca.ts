import { existsSync, readdirSync, statSync } from 'node:fs';
import { hp, readText } from './host.ts';

/**
 * Configuration assessment: a fixed list of controls inspired by the CIS Linux benchmarks.
 * Read-only. Each control answers pass, fail or na (not applicable here) and says how to fix it.
 */
export interface Control {
  id: string;
  group: 'ssh' | 'accounts' | 'files' | 'network' | 'kernel' | 'services' | 'logging';
  severity: 'high' | 'medium' | 'low';
  title: string;
  /** one sentence: why it matters */
  why: string;
  /** what to do when it fails */
  fix: string;
  status: 'pass' | 'fail' | 'na';
  detail?: string;
}
type Def = Omit<Control, 'status' | 'detail'> & { test: () => boolean | null | { ok: boolean; detail?: string } };

// ---- helpers ----
function sshdConfig(): Record<string, string> {
  const out: Record<string, string> = {};
  const files = ['etc/ssh/sshd_config'];
  try {
    for (const f of readdirSync(hp('etc/ssh/sshd_config.d')).sort()) if (f.endsWith('.conf')) files.push(`etc/ssh/sshd_config.d/${f}`);
  } catch {
    /* no drop-ins */
  }
  // sshd keeps the FIRST value it sees for a keyword; drop-ins are included at the top of the main file in modern distros
  const ordered = files.length > 1 ? [...files.slice(1), files[0]] : files;
  for (const f of ordered) {
    for (const line of readText(hp(f))?.split('\n') ?? []) {
      const m = line.trim().match(/^(\w+)\s+(.+)$/);
      if (m && !m[1].startsWith('#') && !(m[1].toLowerCase() in out)) out[m[1].toLowerCase()] = m[2].trim().toLowerCase();
    }
  }
  return out;
}
const sysctl = (key: string): string | null => readText(hp(`proc/sys/${key.replaceAll('.', '/')}`))?.trim() ?? null;
const modeOf = (f: string): number | null => {
  try {
    return statSync(hp(f)).mode & 0o7777;
  } catch {
    return null;
  }
};
const ownerRoot = (f: string): boolean => {
  try {
    const s = statSync(hp(f));
    return s.uid === 0;
  } catch {
    return false;
  }
};
const loginDefs = (key: string): number | null => {
  const m = readText(hp('etc/login.defs'))?.match(new RegExp(`^\\s*${key}\\s+(\\d+)`, 'm'));
  return m ? Number(m[1]) : null;
};
function installedPackages(): Set<string> {
  const s = new Set<string>();
  for (const b of readText(hp('var/lib/dpkg/status'))?.split('\n\n') ?? []) {
    const n = b.match(/^Package: (.+)$/m)?.[1];
    if (n && /^Status: .* installed$/m.test(b)) s.add(n);
  }
  for (const b of readText(hp('lib/apk/db/installed'))?.split('\n\n') ?? []) {
    const n = b.match(/^P:(.+)$/m)?.[1];
    if (n) s.add(n);
  }
  return s;
}
const isEnabled = (unit: string): boolean => {
  try {
    for (const d of readdirSync(hp('etc/systemd/system'))) if (d.endsWith('.wants') && existsSync(hp(`etc/systemd/system/${d}/${unit}.service`))) return true;
  } catch {
    /* not systemd */
  }
  return false;
};
const hasSystemd = () => existsSync(hp('etc/systemd/system'));

const perm = (file: string, max: number, ownerMustBeRoot = true): Def['test'] => () => {
  const m = modeOf(file);
  if (m === null) return null;
  return { ok: (m & ~max) === 0 && (!ownerMustBeRoot || ownerRoot(file)), detail: `${file}: ${m.toString(8)}` };
};

export function runControls(): Control[] {
  const pk = installedPackages();
  const ssh = sshdConfig();
  const sshOn = existsSync(hp('etc/ssh/sshd_config'));
  const sshVal = (k: string, bad: (v: string) => boolean, def = ''): Def['test'] => () => {
    if (!sshOn) return null;
    const v = ssh[k] ?? def;
    return { ok: !bad(v), detail: `${k} = ${v || '(default)'}` };
  };
  const defs: Def[] = [
    // SSH
    { id: 'ssh.root', group: 'ssh', severity: 'high', title: 'SSH does not allow root login with a password', why: 'Root is the account every attacker tries first.', fix: 'Set PermitRootLogin to prohibit-password or no (SSH tab, step 4).', test: sshVal('permitrootlogin', (v) => v === 'yes', 'prohibit-password') },
    { id: 'ssh.password', group: 'ssh', severity: 'high', title: 'SSH password logins are disabled', why: 'Passwords can be guessed; keys cannot.', fix: 'Set PasswordAuthentication no after installing a key (SSH tab).', test: sshVal('passwordauthentication', (v) => v !== 'no', 'yes') },
    { id: 'ssh.empty', group: 'ssh', severity: 'high', title: 'SSH rejects empty passwords', why: 'An account without a password must never be able to log in.', fix: 'Set PermitEmptyPasswords no.', test: sshVal('permitemptypasswords', (v) => v === 'yes', 'no') },
    { id: 'ssh.tries', group: 'ssh', severity: 'medium', title: 'SSH limits login attempts per connection (4 or fewer)', why: 'Slows down password guessing.', fix: 'Set MaxAuthTries 4.', test: sshVal('maxauthtries', (v) => Number(v || 6) > 4, '6') },
    { id: 'ssh.x11', group: 'ssh', severity: 'low', title: 'SSH X11 forwarding is off', why: 'A rarely needed feature that widens the attack surface.', fix: 'Set X11Forwarding no.', test: sshVal('x11forwarding', (v) => v === 'yes', 'no') },
    { id: 'ssh.grace', group: 'ssh', severity: 'low', title: 'SSH login grace time is 60 seconds or less', why: 'Unauthenticated connections should not linger.', fix: 'Set LoginGraceTime 60.', test: sshVal('logingracetime', (v) => (v ? parseInt(v) > 60 : false), '120') },
    // accounts
    { id: 'acct.uid0', group: 'accounts', severity: 'high', title: 'Only root has UID 0', why: 'Any other UID 0 account is a second root.', fix: 'Remove or change the extra UID 0 accounts.', test: () => {
      const extra = readText(hp('etc/passwd'))?.split('\n').filter((l) => l.split(':')[2] === '0' && !l.startsWith('root:'));
      return extra ? { ok: extra.length === 0, detail: extra.map((l) => l.split(':')[0]).join(', ') } : null;
    } },
    { id: 'acct.empty', group: 'accounts', severity: 'high', title: 'No account has an empty password', why: 'It can be used without knowing anything.', fix: 'Lock or set a password for the listed accounts.', test: () => {
      const bad = readText(hp('etc/shadow'))?.split('\n').filter((l) => l.split(':')[1] === '').map((l) => l.split(':')[0]).filter(Boolean);
      return bad ? { ok: bad.length === 0, detail: bad.join(', ') } : null;
    } },
    { id: 'acct.maxdays', group: 'accounts', severity: 'low', title: 'Passwords expire (PASS_MAX_DAYS 365 or less)', why: 'Limits how long a leaked password stays useful.', fix: 'Set PASS_MAX_DAYS 365 in /etc/login.defs.', test: () => {
      const v = loginDefs('PASS_MAX_DAYS');
      return readText(hp('etc/login.defs')) === null ? null : { ok: v !== null && v <= 365, detail: `PASS_MAX_DAYS = ${v ?? 'unset'}` };
    } },
    { id: 'acct.minlen', group: 'accounts', severity: 'low', title: 'Password quality rules exist (pwquality or cracklib)', why: 'Prevents trivially weak passwords.', fix: 'Install libpam-pwquality and set a minimum length of 12.', test: () => pk.size === 0 ? null : pk.has('libpam-pwquality') || pk.has('libpwquality') || pk.has('libpam-cracklib') },
    // files
    { id: 'file.passwd', group: 'files', severity: 'medium', title: '/etc/passwd is not writable by others', why: 'Anyone who can edit it can create accounts.', fix: 'chmod 644 /etc/passwd && chown root:root /etc/passwd', test: perm('etc/passwd', 0o644) },
    { id: 'file.shadow', group: 'files', severity: 'high', title: '/etc/shadow is readable only by root (and the shadow group)', why: 'It holds the password hashes.', fix: 'chmod 640 /etc/shadow && chown root:shadow /etc/shadow', test: perm('etc/shadow', 0o640) },
    { id: 'file.sshd', group: 'files', severity: 'medium', title: 'sshd_config is only writable by root', why: 'It controls who can log in.', fix: 'chmod 600 /etc/ssh/sshd_config', test: perm('etc/ssh/sshd_config', 0o644) },
    { id: 'file.crontab', group: 'files', severity: 'medium', title: '/etc/crontab is only writable by root', why: 'Scheduled jobs run as root.', fix: 'chmod 600 /etc/crontab && chown root:root /etc/crontab', test: perm('etc/crontab', 0o644) },
    { id: 'file.sudoers', group: 'files', severity: 'high', title: '/etc/sudoers is not writable by others', why: 'It defines who is administrator.', fix: 'chmod 440 /etc/sudoers', test: perm('etc/sudoers', 0o440) },
    { id: 'file.tmp', group: 'files', severity: 'low', title: '/tmp has the sticky bit', why: 'Stops users from deleting each other\'s temporary files.', fix: 'chmod +t /tmp', test: () => {
      const m = modeOf('tmp');
      return m === null ? null : (m & 0o1000) !== 0;
    } },
    // network
    { id: 'net.forward', group: 'network', severity: 'medium', title: 'IP forwarding is off (unless this host is a router or runs Docker)', why: 'A server that forwards packets can be used to pivot.', fix: 'sysctl -w net.ipv4.ip_forward=0', test: () => {
      const v = sysctl('net.ipv4.ip_forward');
      if (v === null) return null;
      if (v === '1' && existsSync(hp('var/run/docker.sock'))) return null; // Docker needs it
      return v === '0';
    } },
    { id: 'net.redirects', group: 'network', severity: 'medium', title: 'ICMP redirects are not accepted', why: 'Redirects can reroute your traffic through an attacker.', fix: 'sysctl -w net.ipv4.conf.all.accept_redirects=0', test: () => { const v = sysctl('net.ipv4.conf.all.accept_redirects'); return v === null ? null : v === '0'; } },
    { id: 'net.sendredirects', group: 'network', severity: 'low', title: 'ICMP redirects are not sent', why: 'Only routers should send them.', fix: 'sysctl -w net.ipv4.conf.all.send_redirects=0', test: () => { const v = sysctl('net.ipv4.conf.all.send_redirects'); return v === null ? null : v === '0'; } },
    { id: 'net.syncookies', group: 'network', severity: 'medium', title: 'SYN cookies are enabled', why: 'Protects against SYN flood attacks.', fix: 'sysctl -w net.ipv4.tcp_syncookies=1', test: () => { const v = sysctl('net.ipv4.tcp_syncookies'); return v === null ? null : v === '1'; } },
    { id: 'net.rp', group: 'network', severity: 'low', title: 'Reverse path filtering is on', why: 'Drops packets with spoofed source addresses.', fix: 'sysctl -w net.ipv4.conf.all.rp_filter=1', test: () => { const v = sysctl('net.ipv4.conf.all.rp_filter'); return v === null ? null : v !== '0'; } },
    { id: 'net.firewall', group: 'network', severity: 'high', title: 'A host firewall is installed', why: 'The last line of defence if a service is exposed by mistake.', fix: 'Install and enable ufw or firewalld (Manage tab, Firewall).', test: () => pk.size === 0 ? null : ['ufw', 'firewalld', 'nftables', 'iptables', 'iptables-persistent'].some((p) => pk.has(p)) },
    // kernel
    { id: 'kern.aslr', group: 'kernel', severity: 'medium', title: 'Address space randomisation is fully on', why: 'Makes memory exploits much harder.', fix: 'sysctl -w kernel.randomize_va_space=2', test: () => { const v = sysctl('kernel.randomize_va_space'); return v === null ? null : v === '2'; } },
    { id: 'kern.coredump', group: 'kernel', severity: 'low', title: 'SUID programs cannot dump core', why: 'Core dumps can leak secrets.', fix: 'sysctl -w fs.suid_dumpable=0', test: () => { const v = sysctl('fs.suid_dumpable'); return v === null ? null : v === '0'; } },
    { id: 'kern.dmesg', group: 'kernel', severity: 'low', title: 'Kernel messages are restricted to root', why: 'They reveal addresses useful to attackers.', fix: 'sysctl -w kernel.dmesg_restrict=1', test: () => { const v = sysctl('kernel.dmesg_restrict'); return v === null ? null : v === '1'; } },
    { id: 'kern.ptrace', group: 'kernel', severity: 'low', title: 'ptrace is restricted (Yama)', why: 'Stops one process from reading another\'s memory.', fix: 'sysctl -w kernel.yama.ptrace_scope=1', test: () => { const v = sysctl('kernel.yama.ptrace_scope'); return v === null ? null : v !== '0'; } },
    // services
    { id: 'svc.legacy', group: 'services', severity: 'high', title: 'No legacy clear-text services installed (telnet, rsh, tftp, talk)', why: 'They send passwords unencrypted.', fix: 'Remove the packages listed (apt remove telnetd rsh-server tftpd).', test: () => {
      if (pk.size === 0) return null;
      const bad = ['telnetd', 'telnet-server', 'rsh-server', 'rsh-redone-server', 'tftpd', 'tftpd-hpa', 'talkd', 'ypserv', 'xinetd', 'inetutils-telnetd'].filter((p) => pk.has(p));
      return { ok: bad.length === 0, detail: bad.join(', ') };
    } },
    { id: 'svc.fail2ban', group: 'services', severity: 'low', title: 'An intrusion blocker is installed (fail2ban or crowdsec)', why: 'Bans addresses that keep failing to log in.', fix: 'apt install fail2ban', test: () => pk.size === 0 ? null : pk.has('fail2ban') || pk.has('crowdsec') },
    { id: 'svc.updates', group: 'services', severity: 'medium', title: 'Automatic security updates are set up', why: 'Patches arrive without waiting for you.', fix: 'apt install unattended-upgrades (Debian, Ubuntu) or dnf-automatic.', test: () => pk.size === 0 ? null : pk.has('unattended-upgrades') || pk.has('dnf-automatic') || pk.has('apt-listchanges') && pk.has('unattended-upgrades') },
    { id: 'svc.time', group: 'services', severity: 'low', title: 'Time is synchronised (chrony, systemd-timesyncd or ntp)', why: 'Logs from different servers only line up with correct clocks.', fix: 'apt install chrony', test: () => {
      if (pk.size === 0) return null;
      return ['chrony', 'ntp', 'ntpsec', 'openntpd'].some((p) => pk.has(p)) || (hasSystemd() && existsSync(hp('lib/systemd/systemd-timesyncd')));
    } },
    { id: 'svc.apparmor', group: 'services', severity: 'low', title: 'A mandatory access control system is active (AppArmor or SELinux)', why: 'Contains a compromised service.', fix: 'Install and enable AppArmor (Debian, Ubuntu) or SELinux (RHEL family).', test: () => existsSync(hp('sys/kernel/security/apparmor')) || existsSync(hp('sys/fs/selinux')) },
    // logging
    { id: 'log.auditd', group: 'logging', severity: 'low', title: 'The audit daemon is installed', why: 'Records who did what, for investigations.', fix: 'apt install auditd', test: () => pk.size === 0 ? null : pk.has('auditd') || pk.has('audit') },
    { id: 'log.syslog', group: 'logging', severity: 'medium', title: 'A system log service is running (rsyslog or journald)', why: 'Without logs there is nothing to investigate.', fix: 'apt install rsyslog, or keep persistent journald storage.', test: () => pk.has('rsyslog') || pk.has('syslog-ng') || existsSync(hp('var/log/journal')) || (hasSystemd() && isEnabled('systemd-journald')) || existsSync(hp('var/log/syslog')) || existsSync(hp('var/log/messages')) },
  ];
  return defs.map(({ test, ...d }) => {
    let r: ReturnType<Def['test']>;
    try {
      r = test();
    } catch {
      r = null;
    }
    if (r === null) return { ...d, status: 'na' as const };
    if (typeof r === 'boolean') return { ...d, status: r ? ('pass' as const) : ('fail' as const) };
    return { ...d, status: r.ok ? ('pass' as const) : ('fail' as const), detail: r.detail };
  });
}

export const score = (c: Control[]): number => {
  const w = { high: 3, medium: 2, low: 1 };
  const applicable = c.filter((x) => x.status !== 'na');
  const total = applicable.reduce((s, x) => s + w[x.severity], 0);
  const ok = applicable.filter((x) => x.status === 'pass').reduce((s, x) => s + w[x.severity], 0);
  return total ? Math.round((ok / total) * 100) : 0;
};
