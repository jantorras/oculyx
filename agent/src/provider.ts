import { adminOverview, applyAdmin } from './admin.ts';
import { collectMetrics, hostInfo } from './host.ts';
import { containerAction, containerLogs, dockerAvailable, listContainers } from './docker.ts';
import { SecurityScanner } from './security.ts';
import { applyFix, isNativeRoot, previewFix } from './hardening.ts';
import { authorizeKey, listHostKeys, revokeKey } from './sshkeys.ts';
import { WindowsScanner, windowsInfo } from './windows.ts';
import type { Provider } from './protocol.ts';

/** Provider for a real host. Mutating actions stay disabled unless OCULYX_ALLOW_ACTIONS=true. */
export async function createHostProvider(stateDir: string): Promise<Provider> {
  const docker = await dockerAvailable();
  const allowActions = process.env.OCULYX_ALLOW_ACTIONS === 'true';
  const win = process.platform === 'win32';
  const scanner = win ? new WindowsScanner(stateDir) : new SecurityScanner(stateDir, () => docker);
  return {
    info: async () => {
      const info = hostInfo(docker);
      if (win) {
        const w = await windowsInfo();
        if (w?.caption) info.os = `${w.caption} (build ${w.build})`;
        if (w?.cpu) info.cpuModel = w.cpu;
      }
      info.actions = allowActions;
      info.canHarden = allowActions && isNativeRoot && !win;
      return info;
    },
    metrics: collectMetrics,
    docker: async () => (docker ? listContainers() : null),
    security: () => scanner.scan(),
    drainEvents: () => scanner.drainEvents(),
    tick: () => (scanner instanceof SecurityScanner ? scanner.tick() : undefined),
    async command(action, args) {
      if (action === 'docker.logs') return containerLogs(String(args.id), Number(args.tail ?? 200));
      const ports = () => (scanner instanceof SecurityScanner ? scanner.exposedTcpPorts() : []);
      if (action === 'ssh.list') return listHostKeys();
      if (action === 'admin.overview') return adminOverview();
      if (action === 'harden.preview') return previewFix(String(args.fix), args.args ?? {}, ports);
      if (!allowActions) throw new Error('actions are disabled on this agent (OCULYX_ALLOW_ACTIONS=true to enable)');
      switch (action) {
        case 'docker.start':
        case 'docker.stop':
        case 'docker.restart':
          return containerAction(action.slice(7) as 'start' | 'stop' | 'restart', String(args.id));
        case 'ssh.authorize': {
          const r = authorizeKey(String(args.user), String(args.key));
          if (scanner instanceof SecurityScanner) scanner.acceptKeys();
          return r;
        }
        case 'ssh.revoke': {
          const r = revokeKey(String(args.user), String(args.fingerprint));
          if (scanner instanceof SecurityScanner) scanner.acceptKeys();
          return r;
        }
        case 'admin.apply':
          return applyAdmin(String(args.op), args.args ?? {}, { protectUser: typeof args.protectUser === 'string' ? args.protectUser : undefined });
        case 'harden.apply':
          return applyFix(String(args.fix), args.args ?? {}, ports);
        case 'fim.rebaseline':
          scanner.rebaseline();
          return { ok: true };
        default:
          throw new Error(`unknown action: ${action}`);
      }
    },
  };
}
