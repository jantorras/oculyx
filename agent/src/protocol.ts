export interface HostInfo {
  hostname: string;
  os: string;
  kernel: string;
  arch: string;
  cpus: number;
  cpuModel: string;
  memTotal: number;
  docker: boolean;
  agentVersion: string;
  /** fingerprint of the agent's source files (see host.ts) */
  build?: string;
  /** how the agent runs: native (systemd), docker (container with the host mounted) or windows */
  mode?: 'native' | 'docker' | 'windows';
  platform?: string;
  /** actions enabled on this agent */
  actions?: boolean;
  /** this agent can change the system (native, root, actions enabled) */
  canHarden?: boolean;
}

export interface MetricsSample {
  cpu: number; // 0-100
  memUsed: number;
  memTotal: number;
  diskUsed: number;
  diskTotal: number;
  rx: number; // bytes/s
  tx: number;
  load1: number;
  uptime: number;
}

export interface ContainerInfo {
  id: string;
  name: string;
  image: string;
  state: string;
  status: string;
  exitCode?: number;
  created: number;
  ports: string[];
  cpu?: number;
  mem?: number;
  memLimit?: number;
}

export interface Finding {
  checkId: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  detail?: string;
  /** id of a one-click remediation the agent can apply (see hardening.ts) */
  fix?: string;
}

export interface Port {
  port: number;
  proto: string;
  addr: string;
  exposed: boolean;
}

export interface AgentEvent {
  type: string;
  severity: Finding['severity'];
  message: string;
  data?: Record<string, unknown>;
  ts?: number;
}

export interface SecuritySnapshot {
  findings: Finding[];
  ports: Port[];
}

/** Everything the connection loop needs from a host; real hosts and the demo simulator both implement it. */
export interface Provider {
  info(): Promise<HostInfo>;
  metrics(): Promise<MetricsSample>;
  docker(): Promise<ContainerInfo[] | null>;
  security(): Promise<SecuritySnapshot>;
  drainEvents(): AgentEvent[];
  /** called every few seconds for continuous collectors (log tailing, intrusion watchers) */
  tick?(): void;
  /** the server pushes which optional checks to run (see checks.ts) */
  configure?(checks: unknown): void;
  /** results of scheduled checks that are not events (configuration audit, inventory) */
  drainMessages?(): unknown[];
  command(action: string, args: Record<string, any>): Promise<unknown>;
}
