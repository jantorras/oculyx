import { useState } from 'react';
import { api, usePoll, useRoute, hashQuery, setHashQuery, bytes, pct } from '../lib';
import { useT } from '../i18n';
import { useUser, canOperate } from '../App';
import { Card, Empty, Icon, Skeleton } from '../components/ui';
import { Donut, HBars } from '../components/Chart';

export function Containers() {
  const t = useT();
  const user = useUser();
  useRoute(); // re-render when the URL query changes
  const { data: all, refresh } = usePoll(() => api<any[]>('/containers'), 5000);
  const { data: overview } = usePoll(() => api<any>('/overview'), 10000);
  const [q, setQ] = useState('');
  if (!all) return <Skeleton />;
  const hostId = Number(hashQuery().get('host')) || 0;
  const hosts: { id: number; name: string; online: boolean; total: number }[] = (overview?.agents ?? [])
    .filter((a: any) => a.docker)
    .map((a: any) => ({ id: a.id, name: a.name, online: a.online, total: a.docker.total }));
  const data = hostId ? all.filter((c) => c.agentId === hostId) : all;
  const rows = data.filter((c) => !q || `${c.name} ${c.image} ${c.agent}`.toLowerCase().includes(q.toLowerCase()));
  const running = data.filter((c) => c.state === 'running').length;
  return (
    <div className="page">
      <div className="page-head">
        <div className="grow">
          <h1>{t('nav.containers')}</h1>
          <div className="sub">{hostId ? t('containers.subtitle_one', { running, total: data.length, name: hosts.find((h) => h.id === hostId)?.name ?? '' }) : t('containers.subtitle', { running, total: data.length })}</div>
        </div>
      </div>
      <section className="sect">
      <h2 className="sect-title">{t('nav.containers')}</h2>
      <div className="filterbar">
        <select value={hostId || ''} onChange={(e) => setHashQuery({ host: e.target.value || null })} aria-label={t('containers.server')} name="host">
          <option value="">{t('containers.all_servers')} ({all.length})</option>
          {hosts.map((h) => (
            <option key={h.id} value={h.id}>{h.name} ({h.total}){h.online ? '' : ` - ${t('status.offline')}`}</option>
          ))}
        </select>
        <input type="search" name="q" autoComplete="off" spellCheck={false} placeholder={t('common.search')} value={q} onChange={(e) => setQ(e.target.value)} aria-label={t('common.search')} />
      </div>
        {rows.length === 0 ? <Empty>{t('containers.none')}</Empty> : <ContainerTable rows={rows} hideHost={!!hostId} onChange={refresh} canAct={canOperate(user)} />}
      </section>
      <section className="sect">
      <h2 className="sect-title">{t('host.resources')}</h2>
      <div className="grid g3">
        <Card title={t('containers.by_state')}>
          <Donut size={130} center={data.length} caption={t('nav.containers')} slices={[
            { label: t('overview.running'), value: running, color: 'var(--ok)' },
            { label: t('overview.stopped'), value: data.filter((c) => c.state === 'exited').length, color: 'var(--high)' },
            ...(data.some((c) => c.state !== 'running' && c.state !== 'exited') ? [{ label: '·', value: data.filter((c) => c.state !== 'running' && c.state !== 'exited').length, color: 'var(--muted)' }] : []),
          ]} />
        </Card>
        <Card title={t('containers.top_cpu')}>
          <HBars thresholds={false} max={Math.max(10, ...data.map((c) => c.cpu ?? 0))} format={(v) => `${v.toFixed(1)}%`} rows={[...data].filter((c) => c.cpu != null).sort((a, b) => b.cpu - a.cpu).slice(0, 5).map((c) => ({ label: c.name, value: c.cpu, sub: c.agent }))} />
        </Card>
        <Card title={t('containers.top_mem')}>
          <HBars thresholds={false} max={Math.max(1, ...data.map((c) => c.mem ?? 0))} format={(v) => bytes(v, 0)} rows={[...data].filter((c) => c.mem != null).sort((a, b) => b.mem - a.mem).slice(0, 5).map((c) => ({ label: c.name, value: c.mem, sub: c.agent }))} />
        </Card>
      </div>
      </section>
    </div>
  );
}

const STATE_TONE: Record<string, string> = { running: 'ok', exited: 'high', paused: 'medium', restarting: 'medium', created: 'neutral' };

export function ContainerTable({ rows, hideHost, onChange, canAct }: { rows: any[]; hideHost?: boolean; onChange: () => void; canAct: boolean }) {
  const t = useT();
  const [busy, setBusy] = useState<string | null>(null);
  const [logs, setLogs] = useState<{ title: string; text: string } | null>(null);
  const [error, setError] = useState('');

  async function act(c: any, action: string) {
    if (action === 'stop' && !confirm(t('containers.confirm_stop', { name: c.name }))) return;
    setBusy(c.id + action);
    setError('');
    try {
      await api(`/agents/${c.agentId}/containers/${c.id}/${action}`, { method: 'POST', body: {} });
      setTimeout(onChange, 900);
    } catch (e) {
      setError(`${c.name}: ${(e as Error).message}`);
    } finally {
      setBusy(null);
    }
  }
  async function showLogs(c: any) {
    setLogs({ title: c.name, text: t('common.loading') });
    try {
      const r = await api<{ logs: string }>(`/agents/${c.agentId}/containers/${c.id}/logs`);
      setLogs({ title: c.name, text: r.logs || t('containers.no_logs') });
    } catch (e) {
      setLogs({ title: c.name, text: (e as Error).message });
    }
  }

  return (
    <>
      {error && <div className="banner warn" role="alert" style={{ margin: 12 }}>{error}</div>}
      <div className="table-wrap">
        <table className="tbl-dense">
          <thead>
            <tr>
              <th>{t('containers.name')}</th>
              {!hideHost && <th>{t('nav.hosts')}</th>}
              <th>{t('containers.state')}</th>
              <th>CPU</th>
              <th>{t('host.memory')}</th>
              <th>{t('containers.ports')}</th>
              <th className="r">{t('common.actions')}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => {
              const running = c.state === 'running';
              const exposed = c.ports.filter((p: string) => /^(0\.0\.0\.0|::)?:/.test(p)).length;
              return (
                <tr key={c.agentId + c.id}>
                  <td>
                    <div style={{ fontWeight: 600 }}>{c.name}</div>
                    <div className="muted mono" style={{ fontSize: 11.5 }}>{c.image}</div>
                  </td>
                  {!hideHost && <td><a href={`#/hosts/${c.agentId}/containers`}>{c.agent}</a></td>}
                  <td>
                    <span className={`pill ${STATE_TONE[c.state] ?? 'neutral'}`}>{c.state}</span>
                    <div className="muted" style={{ fontSize: 12, marginTop: 3 }}>{c.status}</div>
                  </td>
                  <td className="num">{running && c.cpu != null ? pct(c.cpu, 1) : <span className="muted">-</span>}</td>
                  <td className="num">{running && c.mem != null ? bytes(c.mem, 0) : <span className="muted">-</span>}</td>
                  <td>
                    {c.ports.length ? <span className="mono" style={{ fontSize: 12, color: exposed ? 'var(--warn)' : undefined }}>{c.ports.map((p: string) => p.replace(/^0\.0\.0\.0:/, '').replace(/^127\.0\.0\.1:/, 'lo:')).slice(0, 3).join(', ')}{c.ports.length > 3 ? ' …' : ''}</span> : <span className="muted">-</span>}
                  </td>
                  <td className="r">
                    <div className="row" style={{ justifyContent: 'flex-end', gap: 6 }}>
                      <button className="btn sm" onClick={() => showLogs(c)} disabled={!c.online} title={t('containers.logs')} aria-label={`${t('containers.logs')}: ${c.name}`}>{Icon.doc}</button>
                      {running ? (
                        <>
                          <button className="btn sm" disabled={!canAct || !!busy} onClick={() => act(c, 'restart')} title={t('containers.restart')} aria-label={`${t('containers.restart')}: ${c.name}`}>{Icon.restart}</button>
                          <button className="btn sm danger" disabled={!canAct || !!busy} onClick={() => act(c, 'stop')} title={t('containers.stop')} aria-label={`${t('containers.stop')}: ${c.name}`}>{Icon.stop}</button>
                        </>
                      ) : (
                        <button className="btn sm" disabled={!canAct || !!busy} onClick={() => act(c, 'start')} title={t('containers.start')} aria-label={`${t('containers.start')}: ${c.name}`}>{Icon.play}</button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {logs && (
        <div style={{ padding: 16, borderTop: '1px solid var(--line)' }}>
          <div className="row spread" style={{ marginBottom: 8 }}>
            <h2>{t('containers.logs')}: {logs.title}</h2>
            <button className="btn sm ghost" onClick={() => setLogs(null)}>{t('common.close')}</button>
          </div>
          <div className="logbox">{logs.text}</div>
        </div>
      )}
    </>
  );
}
