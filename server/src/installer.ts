import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const AGENT_DOCKERFILE = `FROM node:24-slim
ENV NODE_ENV=production OCULYX_STATE_DIR=/var/lib/oculyx
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY src ./src
VOLUME /var/lib/oculyx
CMD ["node", "--disable-warning=ExperimentalWarning", "src/main.ts"]
`;

const URL_RE = /^https?:\/\/[A-Za-z0-9.\-_:[\]]+(\/[A-Za-z0-9.\-_/]*)?$/;

/** The address embedded in the install script. It is validated because it ends up inside a shell script. */
export function safeServerUrl(candidate: string | undefined, fallback: string): string {
  const c = (candidate ?? '').trim().replace(/\/+$/, '');
  return URL_RE.test(c) ? c : fallback;
}

export function renderInstallScript(template: string, serverUrl: string): string {
  return template.replaceAll('__SERVER__', serverUrl).replaceAll('\r\n', '\n');
}

/** Files an agent needs, served without auth so a fresh machine can fetch them with plain curl. */
/** Same fingerprint the agent computes over its own source files (agent/src/host.ts BUILD). */
export function bundleBuild(bundle: Map<string, string | Buffer>): string {
  const h = createHash('sha1');
  for (const k of [...bundle.keys()].filter((x) => x.startsWith('src/')).sort((a, b) => a.slice(4).localeCompare(b.slice(4)))) h.update(k.slice(4)).update('\0').update(bundle.get(k)!).update('\0');
  return h.digest('hex').slice(0, 12);
}

export function agentBundle(agentDir: string): Map<string, string | Buffer> {
  const files = new Map<string, string | Buffer>();
  files.set('Dockerfile', AGENT_DOCKERFILE);
  const pkg = join(agentDir, 'package.json');
  if (existsSync(pkg)) files.set('package.json', readFileSync(pkg));
  const src = join(agentDir, 'src');
  if (existsSync(src)) {
    for (const f of readdirSync(src)) {
      if (f.endsWith('.ts') && f !== 'sim.ts') files.set(`src/${f}`, readFileSync(join(src, f)));
    }
  }
  return files;
}

/**
 * Windows app: the server stamps the connection settings onto the end of OculyxSetup.exe, so the user
 * only has to double-click it. Layout: [exe][json][int32 json length][ascii "OCXCFG01"].
 */
export function stampExe(exe: Buffer, cfg: { server: string; token: string; name: string; allow: boolean }): Buffer {
  const json = Buffer.from(JSON.stringify(cfg), 'utf8');
  const tail = Buffer.alloc(12);
  tail.writeInt32LE(json.length, 0);
  tail.write('OCXCFG01', 4, 'ascii');
  return Buffer.concat([exe, json, tail]);
}
