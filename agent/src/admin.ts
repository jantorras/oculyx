import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { isIP } from 'node:net';
import { hp, readText } from './host.ts';
import { isNativeRoot } from './hardening.ts';

/**
 * Day-to-day server administration from the panel: blocked IPs, accounts, services, firewall rules, updates, reboot.
 * Like the hardening fixes, every operation is named and its parameters are validated; nothing runs a free-form
 * command. Reading works everywhere; changing needs the native agent as root with actions enabled.
 */

const ENV = { PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', DEBIAN_FRONTEND: 'noninteractive', LC_ALL: 'C' };
function sh(cmd: string, args: string[], timeout = 60_000): string {
  try {
    return execFileSync(cmd, args, { encoding: 'utf8', timeout, stdio: ['ignore', 'pipe', 'pipe'], env: ENV });
  } catch (e: any) {
    const msg = String(e.stderr || e.stdout || e.message || e).trim().split('\n').slice(-4).join('\n');
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
const have = (bin: string) => ['/usr/sbin/', '/usr/bin/', '/sbin/', '/bin/'].some((d) => existsSync(d + bin));

const USER_RE = /^[a-z_][a-z0-9_-]{0,31}$/;
const SUDO_GROUPS = ['sudo', 'wheel', 'admin'];

interface Account { user: string; uid: number; home: string; shell: string }
function accounts(): Account[] {
  return (readText(hp('etc/passwd')) ?? '').split('\n').filter(Boolean).map((l) => {
    const f = l.split(':');
    return { user: f[0], uid: Number(f[2]), home: f[5], shell: f[6] ?? '' };
  }).filter((a) => a.user && Number.isInteger(a.uid));
}
const humanShell = (s: string) => !/(nologin|false)$/.test(s) && s !== '';
function lockedUsers(): Set<string> {
  const out = new Set<string>();
  for (const l of (readText(hp('etc/shadow')) ?? '').split('\n')) {
    const f = l.split(':');
    if (f[1] && /^[!*]/.test(f[1])) out.add(f[0]);
  }
  return out;
}
function sudoers(): Set<string> {
  const out = new Set<string>();
  for (const l of (readText(hp('etc/group')) ?? '').split('\n')) {
    const f = l.split(':');
    if (SUDO_GROUPS.includes(f[0])) for (const u of (f[3] ?? '').split(',').filter(Boolean)) out.add(u);
  }
  return out;
}
const sudoGroup = (): string | null => {
  const names = (readText(hp('etc/group')) ?? '').split('\n').map((l) => l.split(':')[0]);
  return SUDO_GROUPS.find((g) => names.includes(g)) ?? null;
};

// ------------------------------------------------------------------ read
export function adminOverview() {
  const locked = lockedUsers();
  const sudo = sudoers();
  const users = accounts().filter((a) => a.uid === 0 || (a.uid >= 1000 && a.uid < 60000)).map((a) => ({
    user: a.user, uid: a.uid, shell: a.shell, login: humanShell(a.shell), locked: locked.has(a.user), sudo: sudo.has(a.user) || a.uid === 0,
  }));

  const sessions = (quiet('who', []) ?? '').split('\n').filter(Boolean).map((l) => {
    const m = l.match(/^(\S+)\s+(\S+)\s+(\d{4}-\d\d-\d\d \d\d:\d\d)\s*(?:\((.*)\))?/);
    return m ? { user: m[1], tty: m[2], since: m[3], from: m[4] ?? '' } : null;
  }).filter(Boolean);

  const units = new Map<string, { unit: string; active: string; sub: string; description: string; enabled: string }>();
  for (const l of (quiet('systemctl', ['list-units', '--type=service', '--all', '--no-legend', '--plain', '--no-pager']) ?? '').split('\n')) {
    const m = l.trim().match(/^(\S+\.service)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$/);
    if (m) units.set(m[1], { unit: m[1], active: m[3], sub: m[4], description: m[5], enabled: '' });
  }
  for (const l of (quiet('systemctl', ['list-unit-files', '--type=service', '--no-legend', '--plain', '--no-pager']) ?? '').split('\n')) {
    const m = l.trim().match(/^(\S+\.service)\s+(\S+)/);
    if (m && units.has(m[1])) units.get(m[1])!.enabled = m[2];
  }
  const services = [...units.values()].filter((u) => u.active !== 'inactive' || u.enabled === 'enabled').slice(0, 400);

  const ufw = quiet('ufw', ['status', 'numbered']);
  const ufwActive = ufw !== null && /Status: active/.test(ufw);
  const rules = ufwActive ? ufw!.split('\n').filter((l) => /^\[\s*\d+\]/.test(l)).map((l) => l.replace(/^\[\s*\d+\]\s*/, '').replace(/\s{2,}/g, '  ').trim()) : [];
  const blockedUfw = rules.map((r) => r.match(/^Anywhere\s+DENY IN\s+(\S+)$/)?.[1] ?? r.match(/^(\S+)\s+DENY IN\s+Anywhere$/)?.[1] ?? null).filter(Boolean) as string[];
  const jail = quiet('fail2ban-client', ['status', 'sshd']);
  const banned = [...new Set([...(jail?.match(/Banned IP list:\s*(.*)$/m)?.[1] ?? '').split(/\s+/).filter(Boolean), ...blockedUfw])];

  const up = quiet('apt-get', ['-s', 'upgrade'], 30_000);
  const pending = up ? up.split('\n').filter((l) => l.startsWith('Inst ')) : null;

  return {
    users, sessions, services,
    firewall: { tool: ufwActive ? 'ufw' : have('ufw') ? 'ufw (inactive)' : null, active: ufwActive, rules },
    banned, fail2ban: jail !== null,
    updates: pending ? { pending: pending.length, security: pending.filter((l) => /security/i.test(l)).length } : null,
    rebootRequired: existsSync(hp('var/run/reboot-required')) || existsSync(hp('run/reboot-required')),
  };
}

// ------------------------------------------------------------------ guards
const sshPorts = (): number[] => {
  const p = (quiet('sshd', ['-T']) ?? '').split('\n').filter((l) => l.startsWith('port ')).map((l) => Number(l.slice(5)));
  return p.length ? p : [22];
};
/** Addresses currently connected over SSH: blocking one of them is probably the admin cutting their own branch. */
function sshPeers(): string[] {
  const ports = sshPorts();
  const out = quiet('ss', ['-Hnt', 'state', 'established']) ?? '';
  const peers: string[] = [];
  for (const l of out.split('\n')) {
    const f = l.trim().split(/\s+/);
    if (f.length < 4) continue;
    const local = f[2] ?? '';
    const port = Number(local.slice(local.lastIndexOf(':') + 1));
    if (ports.includes(port)) peers.push((f[3] ?? '').replace(/^\[|\]:\d+$|:\d+$/g, '').replace(/^::ffff:/, ''));
  }
  return peers;
}
const ownAddresses = (): string[] => (quiet('hostname', ['-I']) ?? '').split(/\s+/).filter(Boolean);

interface Ctx { /** account the panel uses for SSH: never locked, deleted or demoted */ protectUser?: string }

function needUser(args: Record<string, any>, ctx: Ctx, opts: { allowRoot?: boolean; allowProtected?: boolean } = {}): Account {
  const name = String(args.user ?? '');
  if (!USER_RE.test(name)) throw new Error('Invalid account name.');
  const a = accounts().find((x) => x.user === name);
  if (!a) throw new Error(`No account named ${name}.`);
  if (a.uid === 0 && !opts.allowRoot) throw new Error('Refusing to change root from here.');
  if (a.uid !== 0 && a.uid < 1000) throw new Error('Refusing to change a system account.');
  if (!opts.allowProtected && ctx.protectUser && name === ctx.protectUser) throw new Error(`${name} is the account the panel uses for SSH; changing it could cut your access.`);
  return a;
}
const needIp = (v: unknown): string => {
  const ip = String(v ?? '').trim();
  const [addr, mask] = ip.split('/');
  if (!isIP(addr) || (mask !== undefined && !/^\d{1,3}$/.test(mask))) throw new Error('Invalid IP address.');
  return ip;
};

// ------------------------------------------------------------------ preview and apply
export function applyAdmin(op: string, args: Record<string, any>, ctx: Ctx): { steps: string[] } {
  if (!isNativeRoot) throw new Error('Administration needs the native agent running as root (not the Docker mode).');
  const confirm = args.confirm === true;
  switch (op) {
    case 'ip.block': {
      const ip = needIp(args.ip);
      const addr = ip.split('/')[0];
      if (addr === '127.0.0.1' || addr === '::1' || ownAddresses().includes(addr)) throw new Error('Refusing to block this server itself.');
      if (!args.force && sshPeers().includes(addr)) throw new Error(`${addr} is connected over SSH right now (maybe you).`);
      if (quiet('ufw', ['status'])?.includes('Status: active')) {
        sh('ufw', ['insert', '1', 'deny', 'from', ip]);
        return { steps: [`ufw: deny all traffic from ${ip}`] };
      }
      if (quiet('fail2ban-client', ['status', 'sshd']) !== null) {
        sh('fail2ban-client', ['set', 'sshd', 'banip', addr]);
        return { steps: [`fail2ban: banned ${addr} on the sshd jail (until the ban time ends)`] };
      }
      throw new Error('There is no active firewall or fail2ban to block with. Enable the firewall first (Security tab).');
    }
    case 'ip.unblock': {
      const ip = needIp(args.ip);
      const steps: string[] = [];
      if (quiet('ufw', ['status'])?.includes('Status: active')) {
        const r = quiet('ufw', ['delete', 'deny', 'from', ip]);
        if (r !== null && /Rule deleted/i.test(r)) steps.push(`ufw: rule for ${ip} removed`);
      }
      if (quiet('fail2ban-client', ['status', 'sshd']) !== null) {
        const r = quiet('fail2ban-client', ['set', 'sshd', 'unbanip', ip.split('/')[0]]);
        if (r !== null) steps.push(`fail2ban: unbanned ${ip}`);
      }
      if (!steps.length) throw new Error(`${ip} was not blocked.`);
      return { steps };
    }
    case 'user.lock': {
      const a = needUser(args, ctx);
      sh('usermod', ['-L', a.user]);
      quiet('chage', ['-E', '0', a.user]);
      quiet('loginctl', ['terminate-user', a.user]);
      return { steps: [`${a.user}: password locked, account expired, sessions ended`] };
    }
    case 'user.unlock': {
      const a = needUser(args, ctx, { allowProtected: true });
      sh('usermod', ['-U', a.user]);
      quiet('chage', ['-E', '-1', a.user]);
      return { steps: [`${a.user}: unlocked`] };
    }
    case 'user.expire-password': {
      const a = needUser(args, ctx, { allowProtected: true });
      sh('chage', ['-d', '0', a.user]);
      return { steps: [`${a.user} must choose a new password at the next login`] };
    }
    case 'user.kill-sessions': {
      const a = needUser(args, ctx);
      sh('loginctl', ['terminate-user', a.user]);
      return { steps: [`${a.user}: all sessions ended`] };
    }
    case 'user.sudo': {
      const a = needUser(args, ctx, { allowProtected: args.enable === true });
      const g = sudoGroup();
      if (!g) throw new Error('This system has no sudo, wheel or admin group.');
      if (args.enable === true) {
        sh('gpasswd', ['-a', a.user, g]);
        return { steps: [`${a.user} added to ${g}: can now run commands as root`] };
      }
      const rest = [...sudoers()].filter((u) => u !== a.user);
      if (!rest.length) throw new Error('Refusing to remove the last account with sudo; nobody could administer the server.');
      sh('gpasswd', ['-d', a.user, g]);
      return { steps: [`${a.user} removed from ${g}`] };
    }
    case 'user.delete': {
      const a = needUser(args, ctx);
      if (!confirm) throw new Error('Confirmation required.');
      if (sudoers().has(a.user) && [...sudoers()].filter((u) => u !== a.user).length === 0) throw new Error('Refusing to delete the last account with sudo.');
      quiet('loginctl', ['terminate-user', a.user]);
      sh('userdel', args.removeHome === true ? ['-r', a.user] : [a.user]);
      return { steps: [`${a.user} deleted${args.removeHome === true ? ' with its home directory' : ' (home directory kept)'}`] };
    }
    case 'svc.start':
    case 'svc.stop':
    case 'svc.restart':
    case 'svc.enable':
    case 'svc.disable': {
      const unit = String(args.unit ?? '');
      if (!/^[A-Za-z0-9@:._-]{1,80}\.service$/.test(unit)) throw new Error('Invalid service name.');
      const name = unit.replace(/\.service$/, '');
      const protectedSvc = /^(ssh|sshd|oculyx-agent|dbus|systemd-.*|getty@.*|networking|network-manager|networkmanager|systemd-networkd)$/i;
      if (protectedSvc.test(name) && op !== 'svc.start' && !(name.match(/^ssh(d)?$/i) && op === 'svc.restart')) throw new Error(`${name} is protected: stopping or disabling it could cut your access to this server.`);
      if (/^oculyx-agent$/i.test(name)) throw new Error('The Oculyx agent cannot manage itself.');
      const verb = op.slice(4);
      if (verb === 'enable') sh('systemctl', ['enable', '--now', unit], 90_000);
      else if (verb === 'disable') sh('systemctl', ['disable', '--now', unit], 90_000);
      else sh('systemctl', [verb, unit], 90_000);
      return { steps: [`${unit}: ${verb} done`] };
    }
    case 'fw.open':
    case 'fw.close': {
      if (!quiet('ufw', ['status'])?.includes('Status: active')) throw new Error('The firewall (ufw) is not active. Enable it from the Security tab first.');
      const port = Number(args.port);
      const proto = String(args.proto ?? 'tcp');
      if (!Number.isInteger(port) || port < 1 || port > 65535 || !['tcp', 'udp'].includes(proto)) throw new Error('Invalid port or protocol.');
      if (op === 'fw.open') {
        sh('ufw', args.from ? ['allow', 'from', needIp(args.from), 'to', 'any', 'port', String(port), 'proto', proto] : ['allow', `${port}/${proto}`]);
        return { steps: [`allowed ${port}/${proto}${args.from ? ` from ${args.from}` : ''}`] };
      }
      if (sshPorts().includes(port) && proto === 'tcp') throw new Error(`Port ${port} is SSH; closing it would lock you out.`);
      sh('ufw', ['delete', 'allow', `${port}/${proto}`]);
      return { steps: [`removed the allow rule for ${port}/${proto}`] };
    }
    case 'updates.apply': {
      if (!have('apt-get')) throw new Error('Updates from the panel only support apt based systems (Debian, Ubuntu).');
      if (!confirm) throw new Error('Confirmation required.');
      sh('apt-get', ['update', '-q', '-o', 'DPkg::Lock::Timeout=120'], 300_000);
      const out = sh('apt-get', ['upgrade', '-y', '-q', '-o', 'DPkg::Lock::Timeout=120', '-o', 'Dpkg::Options::=--force-confold'], 840_000);
      const n = out.match(/(\d+) upgraded/)?.[1] ?? '0';
      return { steps: [`${n} packages upgraded`, existsSync('/var/run/reboot-required') ? 'A reboot is needed to finish (kernel or core libraries).' : 'No reboot needed.'] };
    }
    case 'system.reboot': {
      if (!confirm) throw new Error('Confirmation required.');
      sh('shutdown', ['-r', '+1', 'Reboot requested from the Oculyx panel']);
      return { steps: ['Reboot scheduled in 1 minute. The server will reconnect by itself afterwards.'] };
    }
    case 'system.cancel-reboot': {
      sh('shutdown', ['-c']);
      return { steps: ['Scheduled reboot cancelled'] };
    }
    default:
      throw new Error(`unknown operation: ${op}`);
  }
}
