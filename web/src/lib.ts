import { useEffect, useRef, useState, useCallback } from 'react';

// ---------- API ----------
const TOKEN_KEY = 'oculyx.token';
export const getToken = () => {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
};
export const setToken = (t: string | null) => {
  try {
    t ? localStorage.setItem(TOKEN_KEY, t) : localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable */
  }
};

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export async function api<T = any>(path: string, opts: { method?: string; body?: unknown } = {}): Promise<T> {
  const token = getToken();
  const res = await fetch('/api' + path, {
    method: opts.method ?? (opts.body ? 'POST' : 'GET'),
    headers: { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && path !== '/auth/login') {
    setToken(null);
    location.reload();
  }
  if (!res.ok) throw new ApiError(res.status, data.error ?? 'error');
  return data;
}

/** Polls an async loader; keeps the last good value on transient failures. */
export function usePoll<T>(load: () => Promise<T>, ms = 5000, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const loadRef = useRef(load);
  loadRef.current = load;
  const refresh = useCallback(async () => {
    try {
      setData(await loadRef.current());
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);
  useEffect(() => {
    setData(null);
    void refresh();
    const t = setInterval(refresh, ms);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ms, refresh, ...deps]);
  return { data, error, refresh };
}

// ---------- routing (hash based, so any static host works) ----------
export function useRoute(): [string, (to: string) => void] {
  const get = () => location.hash.replace(/^#/, '') || '/';
  const [route, setRoute] = useState(get);
  useEffect(() => {
    const on = () => setRoute(get());
    window.addEventListener('hashchange', on);
    return () => window.removeEventListener('hashchange', on);
  }, []);
  return [route, (to) => (location.hash = to)];
}

// ---------- formatting ----------
export function bytes(n: number | null | undefined, digits = 1): string {
  if (n == null || !isFinite(n)) return '-';
  const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(i === 0 ? 0 : digits)} ${u[i]}`;
}
export const rate = (n: number | null | undefined) => (n == null ? '-' : `${bytes(n)}/s`);
export const pct = (n: number | null | undefined, d = 0) => (n == null ? '-' : `${n.toFixed(d)}%`);

export function ago(ts: number | null | undefined, now = Date.now()): string {
  if (!ts) return '-';
  const s = Math.max(0, Math.round((now - ts) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}
export function uptime(sec: number | null | undefined): string {
  if (!sec) return '-';
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  return d ? `${d}d ${h}h` : `${h}h ${Math.floor((sec % 3600) / 60)}m`;
}
export const clock = (ts: number) => new Date(ts).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEV_COLOR: Record<string, string> = { critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--med)', low: 'var(--low)', info: 'var(--info)' };

export function scoreTone(score: number | null): 'ok' | 'warn' | 'bad' {
  if (score == null) return 'ok';
  return score >= 85 ? 'ok' : score >= 60 ? 'warn' : 'bad';
}

// ---------- theme ----------
export function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem('oculyx.theme') ?? (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
    } catch {
      return 'dark';
    }
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem('oculyx.theme', theme);
    } catch {
      /* ignore */
    }
  }, [theme]);
  return [theme, () => setTheme(theme === 'dark' ? 'light' : 'dark')];
}

// ---------- filter state kept in the URL (#/path?key=value) so views are linkable ----------
export function hashQuery(): URLSearchParams {
  const h = location.hash.replace(/^#/, '');
  const i = h.indexOf('?');
  return new URLSearchParams(i >= 0 ? h.slice(i + 1) : '');
}
export function setHashQuery(patch: Record<string, string | null>) {
  const h = location.hash.replace(/^#/, '') || '/';
  const i = h.indexOf('?');
  const path = i >= 0 ? h.slice(0, i) : h;
  const q = hashQuery();
  for (const [k, v] of Object.entries(patch)) (v == null || v === '' ? q.delete(k) : q.set(k, v));
  const s = q.toString();
  location.hash = path + (s ? `?${s}` : '');
}
export function duration(ms: number): string {
  const m = Math.round(ms / 60000);
  if (m < 1) return '<1m';
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  return h < 24 ? `${h}h ${m % 60}m` : `${Math.floor(h / 24)}d ${h % 24}h`;
}
