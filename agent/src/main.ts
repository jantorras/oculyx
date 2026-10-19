import { hostname } from 'node:os';
import { resolve } from 'node:path';
import { Connection } from './connection.ts';
import { createHostProvider } from './provider.ts';

const server = (process.env.OCULYX_SERVER ?? '').replace(/\/$/, '');
if (!server) {
  console.error('OCULYX_SERVER is required, e.g. https://oculyx.example.com:8080');
  process.exit(1);
}
const stateDir = resolve(process.env.OCULYX_STATE_DIR ?? './agent-state');
const name = process.env.OCULYX_NAME ?? hostname();

const provider = await createHostProvider(stateDir);
await new Connection({ server, name, stateDir, enrollToken: process.env.OCULYX_ENROLL_TOKEN }, provider).run();
