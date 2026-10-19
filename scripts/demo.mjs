// Local demo: server + 3 simulated hosts + an offline one, with 24h of back-filled history.
//   npm run build:web && npm run demo     ->  http://localhost:8080   (admin / oculyx-demo-1234)
import { spawn } from 'node:child_process';
import { rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes } from 'node:crypto';

const root = resolve(import.meta.dirname, '..');
const PORT = process.env.PORT ?? '8080';
const base = `http://localhost:${PORT}`;
const PASSWORD = 'oculyx-demo-1234';
const dataDir = resolve(root, 'data-demo');
rmSync(dataDir, { recursive: true, force: true });
rmSync(resolve(root, 'demo-agents'), { recursive: true, force: true });

const children = [];
const run = (args, env) => {
  const c = spawn(process.execPath, args, { cwd: root, stdio: 'inherit', env: { ...process.env, ...env } });
  children.push(c);
  return c;
};
process.on('SIGINT', () => process.exit(0));
process.on('exit', () => children.forEach((c) => c.kill()));

run(['server/src/main.ts'], { PORT, OCULYX_DATA: dataDir, OCULYX_ADMIN_PASSWORD: PASSWORD, LOG_LEVEL: 'warn' });
for (let i = 0; i < 50; i++) {
  try {
    if ((await fetch(`${base}/healthz`)).ok) break;
  } catch {}
  await new Promise((r) => setTimeout(r, 200));
}

const api = async (path, opts = {}, token) =>
  (await fetch(base + path, { ...opts, headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) } })).json();
const { token } = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ username: 'admin', password: PASSWORD }) });
const tokens = [];
for (const label of ['web-prod-01', 'db-primary', 'edge-gateway']) tokens.push((await api('/api/enroll', { method: 'POST', body: JSON.stringify({ label }) }, token)).token);
for (const [username, role] of [['maria', 'operator'], ['jordi', 'viewer']])
  await api('/api/users', { method: 'POST', body: JSON.stringify({ username, password: 'demo-password-1', role }) }, token);

run(['agent/src/sim.ts'], { OCULYX_SERVER: base, OCULYX_SIM_TOKENS: tokens.join(','), OCULYX_STATE_DIR: resolve(root, 'demo-agents') });

// wait for enrollment, then back-fill history so charts are not empty
let agents = [];
for (let i = 0; i < 60 && agents.length < 3; i++) {
  await new Promise((r) => setTimeout(r, 500));
  agents = (await api('/api/overview', {}, token)).agents ?? [];
}
const db = new DatabaseSync(resolve(dataDir, 'oculyx.db'));
const now = Date.now();
db.prepare('INSERT INTO agents(name,secret_hash,info,first_seen,last_seen,ip) VALUES(?,?,?,?,?,?)').run(
  'backup-nas', randomBytes(8).toString('hex'),
  JSON.stringify({ hostname: 'backup-nas', os: 'Ubuntu 22.04.4 LTS', kernel: '5.15.0-105-generic', arch: 'x86_64', cpus: 4, cpuModel: 'Intel N100', memTotal: 8 * 1024 ** 3, docker: false, agentVersion: '0.1.0' }),
  now - 9 * 86400_000, now - 2 * 3600_000, '10.0.0.52');
const all = db.prepare('SELECT id,name FROM agents').all();
const ins = db.prepare('INSERT INTO metrics(agent_id,ts,cpu,mem,disk,rx,tx,load1) VALUES(?,?,?,?,?,?,?,?)');
const profile = { 'web-prod-01': [34, 22, 61, 54, 2.4e6], 'db-primary': [52, 30, 90, 87, 9.8e6], 'edge-gateway': [18, 12, 47, 41, 14e6], 'backup-nas': [8, 6, 38, 71, 1.2e6] };
db.exec('BEGIN');
for (const a of all) {
  const [c, amp, m, d, n] = profile[a.name];
  const end = a.name === 'backup-nas' ? now - 2 * 3600_000 : now - 5000;
  for (let t = now - 24 * 3600_000; t < end; t += 30_000) {
    const x = t / 1000;
    const spike = Math.sin(x / 5400) > 0.93 ? 35 : 0;
    const cpu = Math.min(100, Math.max(1, c + Math.sin(x / 2700) * amp * 0.6 + Math.sin(x / 190) * 4 + (Math.random() - 0.5) * 8 + spike));
    const net = n * (0.6 + Math.sin(x / 1800) * 0.4 + Math.random() * 0.4);
    ins.run(a.id, t, cpu, m + Math.sin(x / 9000) * 2 + Math.random() * 0.5, d + ((t - (now - 24 * 3600_000)) / 86400_000) * 0.4, net, net * 0.45, (cpu / 100) * 6);
  }
}
const evIns = db.prepare('INSERT INTO events(agent_id,ts,type,severity,message,data) VALUES(?,?,?,?,?,?)');
const kinds = [
  ['ssh_failed', 'medium', (ip) => `${12 + Math.floor(Math.random() * 90)} failed SSH logins from ${ip}`],
  ['ssh_login', 'info', () => `SSH login: deploy from 10.0.0.${2 + Math.floor(Math.random() * 40)} (publickey)`],
  ['sudo', 'info', () => 'sudo by deploy: /usr/bin/systemctl restart nginx'],
  ['port_opened', 'medium', () => `New listening port tcp/${3000 + Math.floor(Math.random() * 6000)}`],
  ['fim', 'high', () => '/etc/ssh/sshd_config modified'],
];
const live = all.filter((a) => a.name !== 'backup-nas');
for (let h = 24; h > 0; h--) {
  const busy = h % 24 < 7 || h % 24 > 20 ? 3 : 1; // more brute-force noise at night
  for (let i = 0; i < 2 + Math.floor(Math.random() * 5) * busy; i++) {
    const [type, severity, msg] = kinds[Math.floor(Math.random() ** 1.6 * kinds.length)];
    const ip = `${45 + Math.floor(Math.random() * 150)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${1 + Math.floor(Math.random() * 253)}`;
    evIns.run(live[Math.floor(Math.random() * live.length)].id, now - h * 3600_000 + Math.random() * 3600_000, type, severity, msg(ip), '{}');
  }
}
// resolved alert history so the Alerts screen has something to show (rule, severity, message, hours ago, minutes open)
const histIns = db.prepare("INSERT INTO alerts(agent_id,rule,severity,message,state,opened,closed) VALUES(?,?,?,?,'closed',?,?)");
const hist = [
  ['cpu_high', 'medium', 'CPU 94% ≥ 90%', 1.2, 14], ['mem_high', 'medium', 'Memory 91% ≥ 90%', 3.5, 95], ['disk_high', 'high', 'Disk 91% ≥ 90%', 5, 240],
  ['container_crashed', 'high', 'cron-reports (exit 1)', 6.4, 38], ['cpu_high', 'medium', 'CPU 97% ≥ 90%', 8.8, 9], ['offline', 'high', 'No heartbeat from agent', 10.5, 7],
  ['mem_high', 'medium', 'Memory 93% ≥ 90%', 13, 130], ['cpu_high', 'medium', 'CPU 92% ≥ 90%', 15.5, 21], ['container_crashed', 'high', 'uptime-probe (exit 137)', 19, 55],
  ['offline', 'high', 'No heartbeat from agent', 22, 12], ['disk_high', 'high', 'Disk 90% ≥ 90%', 30, 600], ['cpu_high', 'medium', 'CPU 95% ≥ 90%', 52, 17],
  ['mem_high', 'medium', 'Memory 92% ≥ 90%', 75, 310], ['container_crashed', 'high', 'shop-worker (exit 1)', 120, 6],
];
hist.forEach(([rule, sev, msg, hAgo, mins], i) => {
  const a = live[i % live.length];
  const opened = now - hAgo * 3600_000;
  histIns.run(a.id, rule, sev, msg, opened, opened + mins * 60_000);
});
db.exec('COMMIT');
db.close();

console.log(`\n  Oculyx demo ready -> ${base}\n  admin / ${PASSWORD}   (also: maria=operator, jordi=viewer, password demo-password-1)\n  Ctrl+C to stop.\n`);
