import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { AgentEvent, Finding, Port, SecuritySnapshot } from './protocol.ts';

/**
 * Windows host support. Everything that needs the operating system's own tooling goes through
 * PowerShell (always present, no extra dependencies); the JSON it prints is turned into findings here.
 */

/** Runs a PowerShell script and returns its stdout parsed as JSON, or null if it failed. */
export function ps<T = any>(script: string, timeout = 90_000): Promise<T | null> {
  const prelude = "$ErrorActionPreference='SilentlyContinue';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.Encoding]::UTF8;\n";
  const encoded = Buffer.from(prelude + script, 'utf16le').toString('base64');
  return new Promise((resolve) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded],
      { timeout, windowsHide: true, maxBuffer: 16 * 1024 * 1024 },
      (err, stdout) => {
        if (err && !stdout) return resolve(null);
        try {
          resolve(JSON.parse(String(stdout).trim() || 'null'));
        } catch {
          resolve(null);
        }
      },
    );
  });
}

export interface WindowsInfo {
  caption: string;
  build: string;
  cpu: string;
}

export function windowsInfo(): Promise<WindowsInfo | null> {
  return ps<WindowsInfo>(
    "$os=Get-CimInstance Win32_OperatingSystem;$cpu=Get-CimInstance Win32_Processor|Select-Object -First 1;" +
      "@{caption=([string]$os.Caption).Trim();build=[string]$os.BuildNumber;cpu=([string]$cpu.Name).Trim()}|ConvertTo-Json -Compress",
  );
}

/** Cumulative received/sent bytes across interfaces, from `netstat -e` (first numeric row is Bytes in every locale). */
export function netstatBytes(): Promise<{ rx: number; tx: number } | null> {
  return new Promise((resolve) => {
    execFile('netstat', ['-e'], { windowsHide: true, timeout: 5000 }, (err, stdout) => {
      if (err) return resolve(null);
      for (const line of String(stdout).split(/\r?\n/)) {
        const m = line.trim().match(/^\S+\s+(\d+)\s+(\d+)$/);
        if (m) return resolve({ rx: Number(m[1]), tx: Number(m[2]) });
      }
      resolve(null);
    });
  });
}

const RISKY_PORTS: Record<number, [string, Finding['severity']]> = {
  445: ['SMB', 'medium'], 3389: ['Remote Desktop (RDP)', 'medium'], 5985: ['WinRM (HTTP)', 'medium'], 1433: ['SQL Server', 'high'],
  3306: ['MySQL', 'high'], 5432: ['PostgreSQL', 'high'], 6379: ['Redis', 'high'], 27017: ['MongoDB', 'high'], 9200: ['Elasticsearch', 'high'], 2375: ['Docker API (unencrypted)', 'critical'],
};

interface ScanResult {
  defender?: { RealTimeProtectionEnabled?: boolean; AntivirusSignatureAge?: number } | null;
  firewall?: { Name: string; Enabled: boolean }[];
  smb1?: boolean | null;
  rdp?: { enabled: boolean; nla: boolean };
  reboot?: boolean;
  lastHotfixDays?: number | null;
  ports?: { LocalAddress: string; LocalPort: number }[];
  admins?: string[];
  guest?: boolean | null;
  noPassword?: string[];
  failedServices?: { Name: string; DisplayName: string; ExitCode: number }[];
  bitlocker?: number | null;
  failed?: string[]; // "ip|user" per failed logon in the last hour
  failedRecent?: string[]; // same, only since the previous scan
  rdpLogons?: string[]; // "ip|user"
}

const wrap = <T>(v: T | T[] | undefined | null): T[] => (v == null ? [] : Array.isArray(v) ? v : [v]);

function buildScript(sinceMs: number): string {
  return `
$o=@{}
$o.defender=Get-MpComputerStatus|Select-Object RealTimeProtectionEnabled,AntivirusSignatureAge
$o.firewall=@(Get-NetFirewallProfile|ForEach-Object{@{Name=[string]$_.Name;Enabled=($_.Enabled -eq 'True' -or $_.Enabled -eq 1)}})
$o.smb1=(Get-SmbServerConfiguration).EnableSMB1Protocol
$ts='HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server'
$o.rdp=@{enabled=((Get-ItemProperty $ts).fDenyTSConnections -eq 0);nla=((Get-ItemProperty "$ts\\WinStations\\RDP-Tcp").UserAuthentication -eq 1)}
$o.reboot=[bool]((Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired') -or (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending'))
$hf=Get-HotFix|Where-Object{$_.InstalledOn}|Sort-Object InstalledOn -Descending|Select-Object -First 1
$o.lastHotfixDays=if($hf){[int]((Get-Date)-$hf.InstalledOn).TotalDays}else{$null}
$o.ports=@(Get-NetTCPConnection -State Listen|Select-Object LocalAddress,LocalPort -Unique)
$o.admins=@(Get-LocalGroupMember -SID S-1-5-32-544|ForEach-Object{[string]$_.Name})
$o.guest=(Get-LocalUser|Where-Object{$_.SID.Value -like '*-501'}|Select-Object -First 1).Enabled
$o.noPassword=@(Get-LocalUser|Where-Object{$_.Enabled -and $_.PasswordRequired -eq $false}|ForEach-Object{[string]$_.Name})
$o.failedServices=@(Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State<>'Running'"|Where-Object{$_.ExitCode -ne 0 -and $_.ExitCode -ne 1077}|Select-Object -First 8 Name,DisplayName,ExitCode)
$o.bitlocker=[int](Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus
$since=[DateTimeOffset]::FromUnixTimeMilliseconds(${Math.floor(sinceMs)}).LocalDateTime
$hour=(Get-Date).AddMinutes(-60)
function Pick($e,$n){($e.Event.EventData.Data|Where-Object{$_.Name -eq $n}).'#text'}
$o.failed=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$hour} -MaxEvents 1500|ForEach-Object{$x=[xml]$_.ToXml();(Pick $x 'IpAddress')+'|'+(Pick $x 'TargetUserName')})
$o.failedRecent=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$since} -MaxEvents 1500|ForEach-Object{$x=[xml]$_.ToXml();(Pick $x 'IpAddress')+'|'+(Pick $x 'TargetUserName')})
$o.rdpLogons=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=$since} -MaxEvents 300|ForEach-Object{$x=[xml]$_.ToXml();if((Pick $x 'LogonType') -eq '10'){(Pick $x 'IpAddress')+'|'+(Pick $x 'TargetUserName')}})
$o|ConvertTo-Json -Compress -Depth 4`;
}

export class WindowsScanner {
  private stateDir: string;
  private events: AgentEvent[] = [];
  private lastScan = Date.now() - 5 * 60_000;
  private knownPorts: Set<string> | null = null;
  private baseline: { hosts?: string; admins?: string } = {};
  private baselineFile: string;
  private current: { hosts?: string; admins?: string } = {};

  constructor(stateDir: string) {
    this.stateDir = stateDir;
    this.baselineFile = join(stateDir, 'fim-windows.json');
    if (existsSync(this.baselineFile)) this.baseline = JSON.parse(readFileSync(this.baselineFile, 'utf8'));
  }

  drainEvents(): AgentEvent[] {
    return this.events.splice(0);
  }

  rebaseline() {
    this.baseline = { ...this.current };
    mkdirSync(this.stateDir, { recursive: true });
    writeFileSync(this.baselineFile, JSON.stringify(this.baseline));
  }

  async scan(): Promise<SecuritySnapshot> {
    const since = this.lastScan;
    this.lastScan = Date.now();
    const d = (await ps<ScanResult>(buildScript(since), 120_000)) ?? {};
    const findings: Finding[] = [];
    const ports: Port[] = [];

    // ---- listening ports
    const seen = new Set<string>();
    for (const p of wrap(d.ports)) {
      const loop = p.LocalAddress === '127.0.0.1' || p.LocalAddress === '::1';
      const key = `${p.LocalPort}|${loop}`;
      if (seen.has(key)) continue;
      seen.add(key);
      ports.push({ port: p.LocalPort, proto: 'tcp', addr: loop ? 'loopback' : p.LocalAddress, exposed: !loop });
    }
    ports.sort((a, b) => a.port - b.port);
    const exposedNow = new Set(ports.filter((p) => p.exposed).map((p) => `tcp/${p.port}`));
    if (this.knownPorts) for (const k of exposedNow) if (!this.knownPorts.has(k)) this.events.push({ type: 'port_opened', severity: 'medium', message: `New listening port ${k}`, data: { port: k } });
    this.knownPorts = exposedNow;
    for (const p of ports.filter((x) => x.exposed && RISKY_PORTS[x.port])) {
      const [label, sev] = RISKY_PORTS[p.port];
      findings.push({ checkId: `port:tcp:${p.port}`, severity: sev, title: `${label} listening on port ${p.port}`, detail: `Reachable from the network on ${p.addr}:${p.port}. Restrict it with the Windows firewall to the addresses that need it.` });
    }

    // ---- protection and hardening
    const av = d.defender;
    if (av && av.RealTimeProtectionEnabled === false) findings.push({ checkId: 'win:defender-off', severity: 'high', title: 'Microsoft Defender real-time protection is off', detail: 'Turn it on, or make sure another endpoint protection product is active.' });
    if (av && typeof av.AntivirusSignatureAge === 'number' && av.AntivirusSignatureAge > 7) findings.push({ checkId: 'win:defender-sigs', severity: 'medium', title: `Defender signatures are ${av.AntivirusSignatureAge} days old`, detail: 'Check Windows Update / the update source for security intelligence.' });
    for (const p of wrap(d.firewall)) if (p.Enabled === false) findings.push({ checkId: `win:firewall:${p.Name}`, severity: 'medium', title: `Windows Firewall is off for the ${p.Name} profile`, detail: 'Enable it: Set-NetFirewallProfile -Profile ' + p.Name + ' -Enabled True' });
    if (d.smb1 === true) findings.push({ checkId: 'win:smb1', severity: 'high', title: 'SMBv1 is enabled', detail: 'Obsolete and exploited by wormable attacks. Disable: Set-SmbServerConfiguration -EnableSMB1Protocol $false' });
    if (d.rdp?.enabled && !d.rdp.nla) findings.push({ checkId: 'win:rdp-nla', severity: 'high', title: 'Remote Desktop does not require Network Level Authentication', detail: 'Enable NLA in System Properties > Remote, or via the RDP-Tcp UserAuthentication setting.' });
    if (d.guest === true) findings.push({ checkId: 'win:guest', severity: 'medium', title: 'The Guest account is enabled', detail: 'Disable it: Disable-LocalUser -Name Guest' });
    for (const u of wrap(d.noPassword)) findings.push({ checkId: `win:nopw:${u}`, severity: 'high', title: `Account ${u} does not require a password`, detail: 'Set a password and enable "password required".' });
    if (d.bitlocker === 0) findings.push({ checkId: 'win:bitlocker', severity: 'low', title: 'The system drive is not encrypted with BitLocker', detail: 'Consider BitLocker for laptops and any machine holding sensitive data.' });

    // ---- patching and health
    if (d.reboot) findings.push({ checkId: 'win:reboot', severity: 'low', title: 'Reboot required', detail: 'Windows is waiting for a restart to finish installing updates.' });
    if (typeof d.lastHotfixDays === 'number' && d.lastHotfixDays > 60) findings.push({ checkId: 'win:updates-old', severity: d.lastHotfixDays > 120 ? 'high' : 'medium', title: `No Windows updates installed in ${d.lastHotfixDays} days`, detail: 'Run Windows Update and review the update policy.' });
    const failed = wrap(d.failedServices);
    if (failed.length) findings.push({ checkId: 'win:svc-failed', severity: 'low', title: `${failed.length} automatic service(s) failed to start`, detail: failed.map((s) => `${s.DisplayName || s.Name} (exit ${s.ExitCode})`).join(', ') });

    // ---- remote logons
    const byIp = new Map<string, { n: number; users: Set<string> }>();
    for (const row of wrap(d.failed)) {
      const [ip, user] = row.split('|');
      if (!ip || ip === '-' || ip === '::1' || ip === '127.0.0.1') continue;
      const r = byIp.get(ip) ?? { n: 0, users: new Set<string>() };
      r.n++;
      if (user) r.users.add(user);
      byIp.set(ip, r);
    }
    for (const [ip, r] of byIp) {
      if (r.n >= 10) findings.push({ checkId: `win:bruteforce:${ip}`, severity: 'high', title: `Logon brute-force from ${ip}`, detail: `${r.n} failed logons in the last hour (accounts: ${[...r.users].slice(0, 6).join(', ')}). Block the address in the firewall or put RDP behind a VPN.` });
    }
    const recent = new Map<string, number>();
    for (const row of wrap(d.failedRecent)) {
      const ip = row.split('|')[0];
      if (ip && ip !== '-') recent.set(ip, (recent.get(ip) ?? 0) + 1);
    }
    for (const [ip, n] of recent) if (n >= 5) this.events.push({ type: 'rdp_failed', severity: 'medium', message: `${n} failed logons from ${ip}`, data: { ip, count: n } });
    for (const row of wrap(d.rdpLogons)) {
      const [ip, user] = row.split('|');
      this.events.push({ type: 'rdp_login', severity: 'info', message: `RDP logon: ${user} from ${ip || 'unknown'}`, data: { user, ip } });
    }

    // ---- integrity: hosts file and local Administrators membership
    const hostsPath = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'drivers', 'etc', 'hosts');
    try {
      this.current.hosts = createHash('sha256').update(readFileSync(hostsPath)).digest('hex');
    } catch {
      /* unreadable */
    }
    if (d.admins) this.current.admins = [...wrap(d.admins)].sort().join(';');
    if (this.baseline.hosts === undefined && this.baseline.admins === undefined) {
      if (this.current.hosts || this.current.admins) this.rebaseline();
    } else {
      if (this.current.hosts && this.baseline.hosts && this.current.hosts !== this.baseline.hosts) {
        findings.push({ checkId: 'fim:hosts', severity: 'medium', title: 'The hosts file was modified', detail: 'It differs from the recorded baseline. If the change was intentional, accept it as the new baseline.' });
        if (!this.events.some((e) => e.type === 'fim')) this.events.push({ type: 'fim', severity: 'medium', message: 'hosts file modified', data: { file: 'hosts' } });
      }
      if (this.current.admins && this.baseline.admins !== undefined && this.current.admins !== this.baseline.admins) {
        findings.push({ checkId: 'win:admins-changed', severity: 'high', title: 'Local Administrators group membership changed', detail: `Now: ${this.current.admins.replaceAll(';', ', ')}. Review it, then accept it as the new baseline if expected.` });
        if (!this.events.some((e) => e.type === 'win_admin_change')) this.events.push({ type: 'win_admin_change', severity: 'high', message: 'Local Administrators membership changed', data: {} });
      }
    }

    return { findings, ports };
  }
}
