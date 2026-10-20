import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync, mkdirSync, readdirSync, statSync, chmodSync, copyFileSync, unlinkSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { hp, readText, HOST_ROOT, isLinux } from './host.ts';
import type { Finding } from './protocol.ts';

/**
 * Server hardening, modelled on well-known Linux hardening guidance (see also
 * https://github.com/imthenachoman/How-To-Secure-A-Linux-Server). Checks only read files, so they work in the
 * read-only Docker mode too; fixes need the native agent running as root with actions enabled.
 * Every fix is a named, parameter-checked operation: the agent never runs arbitrary commands from the server.
 */

export const isNativeRoot = isLinux && !HOST_ROOT && typeof process.getuid === 'function' && process.getuid() === 0;
const inContainer = () => readText(hp('run/systemd/container')) !== null || existsSync('/.dockerenv') || existsSync('/run/.containerenv');
const hasApt = () => existsSync('/usr/bin/apt-get');

const ENV = { PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', DEBIAN_FRONTEND: 'noninteractive', LC_ALL: 'C' };
function sh(cmd: string, args: string[], timeout = 60_000): string {
  try {
    return execFileSync(cmd, args, { encoding: 'utf8', timeout, stdio: ['ignore', 'pipe', 'pipe'], env: ENV });
  } catch (e: any) {
    const msg = String(e.stderr || e.stdout || e.message || e).trim().split('\n').slice(-6).join('\n');
    throw new Error(`${cmd} ${args.join(' ')}: ${msg}`);
  }
}
const quiet = (cmd: string, args: string[], timeout = 15_000): string | null => {
  try {
    return execFileSync(cmd, args, { encoding: 'utf8', timeout, stdio: ['ignore', 'pipe', 'ignore'], env: ENV });
  } catch {
    return null;
  }
};

// ------------------------------------------------------------------ sshd
const SSHD_DEFAULTS: Record<string, string> = {
  permitrootlogin: 'prohibit-password', passwordauthentication: 'yes', permitemptypasswords: 'no', maxauthtries: '6',
  x11forwarding: 'no', logingracetime: '120', clientaliveinterval: '0', clientalivecountmax: '3',
};

/** The effective sshd settings (lower-case keys). `sshd -T` when we are root on the host, else a parse of the files. */
export function sshdConfig(): Record<string, string> | null {
  if (isNativeRoot) {
    const out = quiet('sshd', ['-T']) ?? quiet('/usr/sbin/sshd', ['-T']);
    if (out) {
      const cfg: Record<string, string> = {};
      for (const l of out.split('\n')) {
        const i = l.indexOf(' ');
        if (i > 0) cfg[l.slice(0, i)] = l.slice(i + 1).trim().toLowerCase();
      }
      return cfg;
    }
  }
  const main = readText(hp('etc/ssh/sshd_config'));
  if (main === null) return null;
  const cfg: Record<string, string> = { ...SSHD_DEFAULTS };
  const seen = new Set<string>();
  const parse = (text: string) => {
    for (const raw of text.split('\n')) {
      const l = raw.trim();
      if (!l || l.startsWith('#')) continue;
      const m = l.match(/^(\S+)\s+(.+)$/);
      if (!m) continue;
      const k = m[1].toLowerCase();
      if (k === 'match') return false; // everything after is conditional
      if (k === 'include') {
        for (const pat of m[2].split(/\s+/)) {
          const full = pat.startsWith('/') ? pat : `/etc/ssh/${pat}`;
          const dir = dirname(full);
          const re = new RegExp('^' + full.slice(dir.length + 1).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
          let names: string[] = [];
          try {
            names = readdirSync(hp(dir)).filter((n) => re.test(n)).sort();
          } catch {
            /* no such directory */
          }
          for (const n of names) if (parse(readText(hp(join(dir, n))) ?? '') === false) return false;
        }
        continue;
      }
      if (!seen.has(k)) {
        seen.add(k);
        cfg[k] = m[2].trim().toLowerCase();
      }
    }
    return true;
  };
  parse(main);
  return cfg;
}

const WEAK_SSH = /(^|,)(3des-cbc|aes\d+-cbc|blowfish-cbc|cast128-cbc|arcfour\d*|hmac-md5[^,]*|hmac-sha1(-96)?|umac-64[^,]*|diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)(,|$)/;

const SSH_MODERN = {
  KexAlgorithms: 'curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512',
  Ciphers: 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr',
  MACs: 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com',
};

const DROPIN = '/etc/ssh/sshd_config.d/00-oculyx.conf';
const BLOCK_START = '# >>> oculyx managed (do not edit between the markers)';
const BLOCK_END = '# <<< oculyx managed';

/** Users that have at least one public key authorized for SSH. */
export function authorizedKeyUsers(): { user: string; keys: number }[] {
  const out: { user: string; keys: number }[] = [];
  const homes: [string, string][] = [['root', '/root']];
  for (const l of (readText(hp('etc/passwd')) ?? '').split('\n')) {
    const f = l.split(':');
    if (f.length >= 6 && Number(f[2]) >= 1000 && f[0] !== 'nobody') homes.push([f[0], f[5]]);
  }
  for (const [user, home] of homes) {
    const txt = readText(hp(join(home, '.ssh/authorized_keys')));
    const keys = (txt ?? '').split('\n').filter((l) => /^\s*(ssh-|ecdsa-|sk-)/.test(l) || /\s(ssh-|ecdsa-|sk-)\S+\s/.test(l)).length;
    if (keys) out.push({ user, keys });
  }
  return out;
}

function reloadSshd() {
  for (const unit of ['ssh', 'sshd']) {
    if (quiet('systemctl', ['reload', unit], 20_000) !== null) return;
  }
  throw new Error('could not reload the SSH service');
}

/** Applies sshd settings safely: validates the configuration, checks they took effect, and restores everything otherwise. */
function setSshd(settings: Record<string, string>): string[] {
  const mainPath = '/etc/ssh/sshd_config';
  const main = readFileSync(mainPath, 'utf8');
  const useDropin = /^\s*Include\s+\/etc\/ssh\/sshd_config\.d\/\*\.conf/im.test(main);
  const before = useDropin ? (existsSync(DROPIN) ? readFileSync(DROPIN, 'utf8') : null) : main;

  const merge = (existing: string) => {
    const cur = new Map<string, string>();
    for (const l of existing.split('\n')) {
      const m = l.match(/^(\w+)\s+(.+)$/);
      if (m && !l.startsWith('#')) cur.set(m[1], m[2]);
    }
    for (const [k, v] of Object.entries(settings)) cur.set(k, v);
    return [...cur.entries()].map(([k, v]) => `${k} ${v}`).join('\n');
  };

  let next: string;
  if (useDropin) {
    next = `# Managed by Oculyx. Remove this file (or use "Undo SSH changes") to go back to the distribution defaults.\n${merge(before ?? '')}\n`;
  } else {
    const re = new RegExp(`${BLOCK_START}\\n([\\s\\S]*?)${BLOCK_END}\\n?`);
    const m = main.match(re);
    const body = merge(m ? m[1] : '');
    // sshd keeps the first value it sees, so the managed block goes on top
    next = `${BLOCK_START}\n${body}\n${BLOCK_END}\n${m ? main.replace(re, '') : main}`;
  }

  const target = useDropin ? DROPIN : mainPath;
  const restore = () => {
    if (before === null) {
      try {
        unlinkSync(target);
      } catch {
        /* already gone */
      }
    } else {
      writeFileSync(target, before);
    }
  };
  const backup = `${mainPath}.oculyx-backup`;
  if (!existsSync(backup)) copyFileSync(mainPath, backup);
  if (useDropin) mkdirSync(dirname(DROPIN), { recursive: true });
  writeFileSync(target, next, { mode: 0o644 });
  try {
    mkdirSync('/run/sshd', { recursive: true }); // privilege separation dir; absent while sshd is stopped
    sh('sshd', ['-t']);
    const eff = quiet('sshd', ['-T']);
    if (eff) {
      const got = new Map(eff.split('\n').map((l) => [l.slice(0, l.indexOf(' ')), l.slice(l.indexOf(' ') + 1).trim().toLowerCase()] as const));
      for (const [k, v] of Object.entries(settings)) {
        const have = got.get(k.toLowerCase());
        if (have !== undefined && have !== v.toLowerCase()) throw new Error(`${k} did not take effect (effective value is "${have}"; another setting overrides it)`);
      }
    }
    reloadSshd();
  } catch (e) {
    restore();
    quiet('systemctl', ['reload', 'ssh']) ?? quiet('systemctl', ['reload', 'sshd']);
    throw e;
  }
  return Object.entries(settings).map(([k, v]) => `sshd: ${k} ${v.length > 40 ? v.slice(0, 40) + '…' : v}`);
}

function undoSsh(): string[] {
  const steps: string[] = [];
  if (existsSync(DROPIN)) {
    unlinkSync(DROPIN);
    steps.push(`removed ${DROPIN}`);
  }
  const main = readFileSync('/etc/ssh/sshd_config', 'utf8');
  const re = new RegExp(`${BLOCK_START}\\n[\\s\\S]*?${BLOCK_END}\\n?`);
  if (re.test(main)) {
    writeFileSync('/etc/ssh/sshd_config', main.replace(re, ''));
    steps.push('removed the managed block from sshd_config');
  }
  sh('sshd', ['-t']);
  reloadSshd();
  steps.push('SSH service reloaded');
  return steps;
}

// ------------------------------------------------------------------ packages and misc
const dpkgStatus = (): string => readText(hp('var/lib/dpkg/status')) ?? '';
const pkgInstalled = (status: string, name: string) => new RegExp(`^Package: ${name}\\nStatus: install ok installed`, 'm').test(status);
const aptInstall = (...pkgs: string[]) => sh('apt-get', ['install', '-y', '-q', '-o', 'DPkg::Lock::Timeout=120', ...pkgs], 400_000);

const SYSCTL: [string, string][] = [
  ['net.ipv4.conf.all.rp_filter', '1'], ['net.ipv4.conf.default.rp_filter', '1'],
  ['net.ipv4.conf.all.accept_redirects', '0'], ['net.ipv4.conf.default.accept_redirects', '0'], ['net.ipv6.conf.all.accept_redirects', '0'],
  ['net.ipv4.conf.all.send_redirects', '0'], ['net.ipv4.conf.all.accept_source_route', '0'], ['net.ipv6.conf.all.accept_source_route', '0'],
  ['net.ipv4.tcp_syncookies', '1'], ['net.ipv4.conf.all.log_martians', '1'], ['net.ipv4.icmp_echo_ignore_broadcasts', '1'],
  ['kernel.randomize_va_space', '2'], ['fs.protected_hardlinks', '1'], ['fs.protected_symlinks', '1'], ['fs.suid_dumpable', '0'],
  ['kernel.dmesg_restrict', '1'], ['kernel.kptr_restrict', '2'],
];
const sysctlValue = (key: string) => readText(hp('proc/sys/' + key.replaceAll('.', '/')))?.trim() ?? null;
const sysctlGaps = () => SYSCTL.filter(([k, want]) => {
  const have = sysctlValue(k);
  if (have === null) return false;
  return k === 'kernel.kptr_restrict' ? Number(have) < 1 : have !== want;
});

const PERMS: [string, number][] = [
  ['etc/shadow', 0o640], ['etc/gshadow', 0o640], ['etc/passwd', 0o644], ['etc/group', 0o644],
  ['etc/ssh/sshd_config', 0o644], ['etc/crontab', 0o644], ['etc/sudoers', 0o440],
];
function permTargets(): [string, number][] {
  const list = [...PERMS];
  try {
    for (const n of readdirSync(hp('etc/ssh'))) if (/^ssh_host_.*_key$/.test(n)) list.push([`etc/ssh/${n}`, 0o600]);
  } catch {
    /* no ssh */
  }
  return list;
}
const permGaps = () => permTargets().flatMap(([p, max]) => {
  try {
    const mode = statSync(hp(p)).mode & 0o7777;
    return mode & ~max ? [{ path: p, mode, max }] : [];
  } catch {
    return [];
  }
});

const octal = (n: number) => n.toString(8).padStart(4, '0');

// ------------------------------------------------------------------ checks (read-only)
export function hardeningChecks(exposedPorts: () => number[]): Finding[] {
  if (!isLinux) return [];
  const out: Finding[] = [];
  const canFix = (id: string) => id; // the UI explains when this agent cannot apply it
  const ssh = sshdConfig();
  if (ssh) {
    const n = (k: string) => Number(ssh[k] ?? SSHD_DEFAULTS[k]);
    if (ssh['permitrootlogin'] === 'yes') out.push({ checkId: 'ssh:root-login', severity: 'high', title: 'SSH permits root login with a password', detail: 'Allow root only with keys ("PermitRootLogin prohibit-password") or disable it.', fix: canFix('ssh.root-login') });
    if ((ssh['passwordauthentication'] ?? 'yes') !== 'no') out.push({ checkId: 'ssh:password-auth', severity: 'medium', title: 'SSH password authentication enabled', detail: 'Passwords can be guessed; keys cannot. Deploy a key from the panel, test it, then turn passwords off.', fix: canFix('ssh.password-auth') });
    if (ssh['permitemptypasswords'] === 'yes') out.push({ checkId: 'ssh:empty-pw', severity: 'critical', title: 'SSH permits empty passwords', detail: 'Set "PermitEmptyPasswords no".', fix: canFix('ssh.empty-pw') });
    if (n('maxauthtries') > 4) out.push({ checkId: 'ssh:max-auth-tries', severity: 'low', title: `SSH allows ${n('maxauthtries')} authentication attempts per connection`, detail: 'Lower MaxAuthTries to 3 to slow brute-force attempts.', fix: canFix('ssh.max-auth-tries') });
    if ((ssh['x11forwarding'] ?? 'no') === 'yes') out.push({ checkId: 'ssh:x11', severity: 'low', title: 'SSH X11 forwarding enabled', detail: 'Servers rarely need it; it widens the attack surface.', fix: canFix('ssh.x11') });
    if (n('logingracetime') > 60 || n('logingracetime') === 0) out.push({ checkId: 'ssh:login-grace', severity: 'low', title: `SSH login grace time is ${ssh['logingracetime'] ?? '120'}s`, detail: 'Unauthenticated connections can stay open for a long time. 30 seconds is plenty.', fix: canFix('ssh.login-grace') });
    if (n('clientaliveinterval') === 0) out.push({ checkId: 'ssh:client-alive', severity: 'low', title: 'SSH does not drop idle or dead sessions', detail: 'Set ClientAliveInterval 300 and ClientAliveCountMax 2.', fix: canFix('ssh.client-alive') });
    const weak = ['kexalgorithms', 'ciphers', 'macs'].filter((k) => ssh[k] && WEAK_SSH.test(ssh[k]));
    if (weak.length) out.push({ checkId: 'ssh:weak-crypto', severity: 'medium', title: 'SSH offers legacy cryptographic algorithms', detail: `Weak entries in: ${weak.join(', ')}. Restrict to modern key exchange, ciphers and MACs. Very old SSH clients may stop working.`, fix: canFix('ssh.crypto') });
  }

  const pam = readText(hp('etc/pam.d/su'));
  if (pam !== null && !/^\s*auth\s+(required|requisite)\s+pam_wheel\.so/m.test(pam)) {
    out.push({ checkId: 'acct:su-open', severity: 'low', title: 'Any local user may try to su to root', detail: 'Restrict su to a dedicated group (pam_wheel) so a compromised unprivileged account cannot guess root passwords.', fix: canFix('su.restrict') });
  }
  const sudoers = [readText(hp('etc/sudoers')) ?? ''];
  try {
    for (const n of readdirSync(hp('etc/sudoers.d'))) sudoers.push(readText(hp(join('etc/sudoers.d', n))) ?? '');
  } catch {
    /* none */
  }
  const nopass = sudoers.join('\n').split('\n').filter((l) => /NOPASSWD/.test(l) && !l.trim().startsWith('#'));
  if (nopass.length) out.push({ checkId: 'acct:sudo-nopasswd', severity: 'low', title: 'sudo without a password is allowed', detail: `${nopass.length} rule(s) grant NOPASSWD. Fine for automation, but any compromise of those accounts is instant root. Review: visudo.` });

  const status = dpkgStatus();
  const apt = status !== '' && hasApt();
  if (apt) {
    if (!pkgInstalled(status, 'libpam-pwquality') && !pkgInstalled(status, 'libpam-passwdqc')) out.push({ checkId: 'acct:pw-quality', severity: 'low', title: 'No password strength enforcement installed', detail: 'Install libpam-pwquality so weak passwords are rejected when set.', fix: canFix('pwquality.install') });
    const auto = readText(hp('etc/apt/apt.conf.d/20auto-upgrades')) ?? '';
    if (!pkgInstalled(status, 'unattended-upgrades') || !/Unattended-Upgrade\s+"1"/.test(auto)) out.push({ checkId: 'sys:auto-updates', severity: 'medium', title: 'Automatic security updates are not enabled', detail: 'Install and enable unattended-upgrades so known vulnerabilities are patched without waiting for you.', fix: canFix('autoupdates.enable') });
    const f2b = pkgInstalled(status, 'fail2ban') || pkgInstalled(status, 'crowdsec');
    if (!f2b) out.push({ checkId: 'net:no-ids', severity: 'medium', title: 'No intrusion prevention (fail2ban / CrowdSec)', detail: 'Repeated failed logins are not blocked automatically. fail2ban bans offending addresses at the firewall.', fix: canFix('fail2ban.install') });
  }

  const ufw = readText(hp('etc/ufw/ufw.conf'));
  const fwActive = (ufw && /ENABLED=yes/i.test(ufw)) || existsSync(hp('usr/sbin/firewalld')) || (readText(hp('etc/nftables.conf')) ?? '').includes('hook input');
  if (!fwActive && (ufw !== null || apt) && exposedPorts().length) {
    out.push({ checkId: 'fw:inactive', severity: 'medium', title: 'No active host firewall detected', detail: 'Everything that listens is reachable. Enable a default-deny firewall that allows only what you use.', fix: canFix('firewall.enable') });
  }

  if (!inContainer()) {
    const gaps = sysctlGaps();
    if (gaps.length) out.push({ checkId: 'sys:sysctl', severity: 'medium', title: `${gaps.length} kernel network/security settings are not hardened`, detail: gaps.map(([k, w]) => `${k}=${w}`).join(', '), fix: canFix('sysctl.apply') });
    const mounts = readText(hp('proc/mounts')) ?? '';
    const procLine = mounts.split('\n').find((l) => l.split(' ')[1] === '/proc');
    if (procLine && !/hidepid=(1|2|invisible)/.test(procLine)) out.push({ checkId: 'sys:hidepid', severity: 'low', title: '/proc shows every process to every user', detail: 'Mount /proc with hidepid=2 so users only see their own processes (needs a reboot to be fully effective with systemd-logind).', fix: canFix('proc.hidepid') });
  }

  for (const g of permGaps()) {
    out.push({ checkId: `file:perm:${g.path}`, severity: g.path.includes('shadow') || g.path.includes('_key') || g.path === 'etc/sudoers' ? 'high' : 'medium', title: `/${g.path} is too permissive (${octal(g.mode)})`, detail: `Should be ${octal(g.max)} or stricter.`, fix: canFix('perm.fix') });
  }
  return out;
}

// ------------------------------------------------------------------ fixes
export interface FixPreview {
  title: string;
  steps: string[];
  warning?: string;
  /** the user must tick a box acknowledging the warning */
  confirm?: boolean;
  args?: Record<string, unknown>;
}

const rootGuard = (what: string) => {
  const keyed = authorizedKeyUsers();
  if (!keyed.length) throw new Error(`Refusing to ${what}: no account has an SSH key yet, so you would be locked out. Deploy a key first (Host > SSH access).`);
  return keyed;
};

export function previewFix(fix: string, args: Record<string, any>, exposedPorts: () => number[]): FixPreview {
  switch (fix) {
    case 'ssh.root-login': return { title: 'Allow root SSH login only with keys', steps: ['PermitRootLogin prohibit-password'], warning: 'Root will no longer be able to log in with a password.' };
    case 'ssh.password-auth': {
      const keyed = authorizedKeyUsers();
      return {
        title: 'Turn off SSH password logins', steps: ['PasswordAuthentication no', 'KbdInteractiveAuthentication no', `Accounts with a key: ${keyed.map((k) => `${k.user} (${k.keys})`).join(', ') || 'none'}`],
        warning: keyed.length ? 'Only key-based logins will work afterwards. Make sure you tested a key login first (the panel can do that from Host > SSH access); otherwise you can lock yourself out.' : 'No account has an SSH key, so this will be refused. Deploy a key first.',
        confirm: true,
      };
    }
    case 'ssh.empty-pw': return { title: 'Forbid empty SSH passwords', steps: ['PermitEmptyPasswords no'] };
    case 'ssh.max-auth-tries': return { title: 'Limit SSH authentication attempts', steps: ['MaxAuthTries 3'] };
    case 'ssh.x11': return { title: 'Disable SSH X11 forwarding', steps: ['X11Forwarding no'] };
    case 'ssh.login-grace': return { title: 'Shorten the SSH login grace time', steps: ['LoginGraceTime 30'] };
    case 'ssh.client-alive': return { title: 'Drop idle SSH sessions', steps: ['ClientAliveInterval 300', 'ClientAliveCountMax 2'] };
    case 'ssh.crypto': return { title: 'Use only modern SSH algorithms', steps: Object.keys(SSH_MODERN).map((k) => `${k}: modern set`), warning: 'Very old SSH clients (before 2015) may not be able to connect.' };
    case 'ssh.revert': return { title: 'Undo the SSH changes made by Oculyx', steps: ['Remove the Oculyx SSH settings and reload sshd'] };
    case 'su.restrict': return { title: 'Restrict su to a dedicated group', steps: ['Create the group "sugroup"', 'Require membership of sugroup to use su'], warning: 'Regular users will no longer be able to su. Add trusted users with: usermod -aG sugroup <user>. sudo is not affected.' };
    case 'pwquality.install': return { title: 'Enforce password strength', steps: ['apt-get install libpam-pwquality'] };
    case 'autoupdates.enable': return { title: 'Enable automatic security updates', steps: ['apt-get install unattended-upgrades', 'Enable the daily update and unattended-upgrade timers'] };
    case 'fail2ban.install': return { title: 'Install fail2ban', steps: ['apt-get install fail2ban', 'Enable the sshd jail: 5 failures in 10 minutes bans the address for 1 hour'], warning: 'Make sure you do not mistype your own password repeatedly: you would ban yourself for an hour.' };
    case 'firewall.enable': {
      const ports = [...new Set([...exposedPorts(), ...(sshdPorts())])].sort((a, b) => a - b);
      return {
        title: 'Enable the firewall (default deny)', args: { ports },
        steps: ['Install ufw if missing', 'Default policy: deny incoming, allow outgoing', ...ports.map((p) => `Allow ${p}/tcp (currently listening)`), 'Enable ufw'],
        warning: 'Only the ports listed above stay reachable. If a service must be reachable and is not listening yet, allow it afterwards. Docker-published ports bypass ufw by design.',
        confirm: true,
      };
    }
    case 'sysctl.apply': return { title: 'Apply kernel hardening settings', steps: sysctlGaps().map(([k, v]) => `${k} = ${v}`), warning: 'Written to /etc/sysctl.d/99-oculyx-hardening.conf, so it survives reboots.' };
    case 'proc.hidepid': return { title: 'Hide other users\' processes in /proc', steps: ['Create the group "proc"', 'Mount /proc with hidepid=2,gid=proc (also in /etc/fstab)', 'Let systemd-logind keep seeing all processes'], warning: 'A reboot is recommended afterwards.' };
    case 'perm.fix': return { title: 'Tighten file permissions', steps: permGaps().map((g) => `/${g.path}: ${octal(g.mode)} -> ${octal(g.mode & g.max)}`) };
    default: throw new Error(`unknown fix: ${fix}`);
  }
}

function sshdPorts(): number[] {
  const out = quiet('sshd', ['-T']);
  const ports = (out ?? '').split('\n').filter((l) => l.startsWith('port ')).map((l) => Number(l.slice(5)));
  return ports.length ? ports : [22];
}

export function applyFix(fix: string, args: Record<string, any>, exposedPorts: () => number[]): { steps: string[] } {
  if (!isNativeRoot) throw new Error('This agent cannot change the system: it must run natively as root (Docker mode mounts the host read-only).');
  const steps: string[] = [];
  switch (fix) {
    case 'ssh.root-login':
      rootGuard('disable root password login');
      return { steps: setSshd({ PermitRootLogin: 'prohibit-password' }) };
    case 'ssh.password-auth': {
      rootGuard('turn off SSH passwords');
      if (args.confirm !== true) throw new Error('Confirmation required: tick the box saying you tested a key login.');
      try {
        return { steps: setSshd({ PasswordAuthentication: 'no', KbdInteractiveAuthentication: 'no' }) };
      } catch {
        return { steps: setSshd({ PasswordAuthentication: 'no', ChallengeResponseAuthentication: 'no' }) };
      }
    }
    case 'ssh.empty-pw': return { steps: setSshd({ PermitEmptyPasswords: 'no' }) };
    case 'ssh.max-auth-tries': return { steps: setSshd({ MaxAuthTries: '3' }) };
    case 'ssh.x11': return { steps: setSshd({ X11Forwarding: 'no' }) };
    case 'ssh.login-grace': return { steps: setSshd({ LoginGraceTime: '30' }) };
    case 'ssh.client-alive': return { steps: setSshd({ ClientAliveInterval: '300', ClientAliveCountMax: '2' }) };
    case 'ssh.crypto': return { steps: setSshd(SSH_MODERN) };
    case 'ssh.revert': return { steps: undoSsh() };

    case 'su.restrict': {
      const path = '/etc/pam.d/su';
      const txt = readFileSync(path, 'utf8');
      if (/^\s*auth\s+(required|requisite)\s+pam_wheel\.so/m.test(txt)) return { steps: ['already restricted'] };
      sh('groupadd', ['-f', 'sugroup']);
      copyFileSync(path, `${path}.oculyx-backup`);
      const line = 'auth       required   pam_wheel.so use_uid group=sugroup';
      let next: string;
      if (/^#\s*auth\s+required\s+pam_wheel\.so.*$/m.test(txt)) next = txt.replace(/^#\s*auth\s+required\s+pam_wheel\.so.*$/m, line);
      else if (/^auth\s+sufficient\s+pam_rootok\.so.*$/m.test(txt)) next = txt.replace(/^(auth\s+sufficient\s+pam_rootok\.so.*)$/m, `$1\n${line}`);
      else throw new Error('Unrecognised /etc/pam.d/su layout; not changed.');
      writeFileSync(path, next);
      return { steps: ['created group sugroup', 'su now requires membership of sugroup'] };
    }

    case 'pwquality.install':
      aptInstall('libpam-pwquality');
      return { steps: ['installed libpam-pwquality'] };

    case 'autoupdates.enable':
      aptInstall('unattended-upgrades');
      writeFileSync('/etc/apt/apt.conf.d/20auto-upgrades', 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n');
      quiet('systemctl', ['enable', '--now', 'apt-daily.timer', 'apt-daily-upgrade.timer'], 30_000);
      return { steps: ['installed unattended-upgrades', 'enabled daily security updates'] };

    case 'fail2ban.install':
      aptInstall('fail2ban');
      mkdirSync('/etc/fail2ban/jail.d', { recursive: true });
      writeFileSync('/etc/fail2ban/jail.d/oculyx.local', '[sshd]\nenabled = true\nmaxretry = 5\nfindtime = 10m\nbantime = 1h\n');
      sh('systemctl', ['enable', 'fail2ban'], 30_000);
      sh('systemctl', ['restart', 'fail2ban'], 30_000);
      return { steps: ['installed fail2ban', 'enabled the sshd jail (5 failures / 10 min = 1 hour ban)'] };

    case 'firewall.enable': {
      if (!existsSync('/usr/sbin/ufw')) aptInstall('ufw');
      const ports = (Array.isArray(args.ports) ? args.ports : [...exposedPorts(), ...sshdPorts()]).map(Number).filter((p) => Number.isInteger(p) && p > 0 && p < 65536);
      if (!ports.length) throw new Error('No ports to allow; refusing to enable a firewall that would block everything.');
      const sshp = sshdPorts();
      for (const p of sshp) if (!ports.includes(p)) ports.push(p); // never lock out SSH
      sh('ufw', ['default', 'deny', 'incoming']);
      sh('ufw', ['default', 'allow', 'outgoing']);
      for (const p of [...new Set(ports)]) sh('ufw', ['allow', `${p}/tcp`]);
      sh('ufw', ['--force', 'enable']);
      return { steps: ['default deny incoming', ...[...new Set(ports)].map((p) => `allowed ${p}/tcp`), 'ufw enabled'] };
    }

    case 'sysctl.apply': {
      const gaps = sysctlGaps();
      if (!gaps.length) return { steps: ['already hardened'] };
      const file = '/etc/sysctl.d/99-oculyx-hardening.conf';
      writeFileSync(file, '# Managed by Oculyx\n' + SYSCTL.filter(([k]) => sysctlValue(k) !== null).map(([k, v]) => `${k} = ${v}`).join('\n') + '\n');
      const failed: string[] = [];
      for (const [k, v] of gaps) {
        try {
          sh('sysctl', ['-w', `${k}=${v}`]);
          steps.push(`${k} = ${v}`);
        } catch {
          failed.push(k);
        }
      }
      if (failed.length === gaps.length) throw new Error('The kernel refused every setting (read-only /proc/sys?). Apply them on the Proxmox host instead.');
      if (failed.length) steps.push(`could not set: ${failed.join(', ')}`);
      return { steps };
    }

    case 'proc.hidepid': {
      sh('groupadd', ['-f', '-r', 'proc']);
      const gid = (quiet('getent', ['group', 'proc']) ?? '').split(':')[2]?.trim();
      if (!gid) throw new Error('could not create the proc group');
      sh('mount', ['-o', `remount,hidepid=2,gid=${gid}`, '/proc']);
      const fstab = readText('/etc/fstab') ?? '';
      if (!/^\s*proc\s+\/proc\s/m.test(fstab)) writeFileSync('/etc/fstab', fstab.replace(/\n?$/, '\n') + `proc /proc proc defaults,hidepid=2,gid=${gid} 0 0\n`);
      else writeFileSync('/etc/fstab', fstab.replace(/^(\s*proc\s+\/proc\s+proc\s+)\S+(.*)$/m, `$1defaults,hidepid=2,gid=${gid}$2`));
      mkdirSync('/etc/systemd/system/systemd-logind.service.d', { recursive: true });
      writeFileSync('/etc/systemd/system/systemd-logind.service.d/hidepid.conf', '[Service]\nSupplementaryGroups=proc\n');
      quiet('systemctl', ['daemon-reload']);
      return { steps: ['group proc created', '/proc remounted with hidepid=2', 'persisted in /etc/fstab', 'systemd-logind allowed to see all processes (reboot recommended)'] };
    }

    case 'perm.fix': {
      const gaps = permGaps();
      if (!gaps.length) return { steps: ['already fine'] };
      for (const g of gaps) {
        chmodSync(hp(g.path), g.mode & g.max);
        steps.push(`/${g.path}: ${octal(g.mode)} -> ${octal(g.mode & g.max)}`);
      }
      return { steps };
    }

    default:
      throw new Error(`unknown fix: ${fix}`);
  }
}
