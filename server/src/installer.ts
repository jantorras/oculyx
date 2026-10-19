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
