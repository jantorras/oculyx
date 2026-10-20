import { useState } from 'react';
import { api, usePoll, bytes, rate, pct, uptime, ago, clock } from '../lib';
import { useT } from '../i18n';
import { useUser, canOperate } from '../App';
import { Card, Empty, Score, SevPill, Skeleton, StatusDot } from '../components/ui';
import { Chart, Gauge } from '../components/Chart';
import { ContainerTable } from './Containers';
import { FindingList } from './Security';
import { SshAccess } from './SshAccess';
import { HostAdmin } from './HostAdmin';

const RANGES = ['1h', '6h', '24h', '7d'];

export function HostDetail({ id, tab: tabParam }: { id: number; tab?: string }) {
  const t = useT();
  const user = useUser();
  const tab = tabParam || 'metrics';
  const [range, setRange] = useState('1h');
  const { data: a, error, refresh } = usePoll(() => api(`/agents/${id}`), 4000, [id]);
  const { data: series } = usePoll(() => api<any[]>(`/agents/${id}/metrics?range=${range}`), 15000, [id, range]);

  if (!a) return error ? <p className="error" role="alert">{t(`err.${error}`)}</p> : <Skeleton kpis={1} />;

  const m = a.metrics;
  const tabs: [string, string][] = [
    ['metrics', t('host.tab_metrics')],
    ['containers', `${t('nav.containers')}${a.docker ? ` (${a.docker.total})` : ''}`],
    ['security', `${t('nav.security')} (${a.findings.length})`],
    ['events', t('nav.events')],
    ...(user.role === 'admin' ? ([['admin', t('adm.tab')], ['ssh', 'SSH']] as [string, string][]) : []),
  ];

  async function remove() {
    if (!confirm(t('host.confirm_delete', { name: a.name }))) return;
    await api(`/agents/${id}`, { method: 'DELETE' });
    location.hash = '/';
  }

  return (
    <>
      <div className="topbar">
        <a href="#/" className="muted">← {t('nav.overview')}</a>
      </div>
      <div className="row wrap" style={{ marginBottom: 20, gap: 18 }}>
        <Score value={a.score} large />
        <div className="grow">
          <h1>{a.name}</h1>
          <div className="row wrap muted" style={{ marginTop: 4, gap: 14 }}>
            <StatusDot online={a.online} />
            <span>{a.info?.os}</span>
            <span className="mono">{a.ip}</span>
            {a.online && <span>{t('host.up')} {uptime(m?.uptime)}</span>}
            {!a.online && <span>{t('host.last_seen')} {ago(a.lastSeen)}</span>}
          </div>
        </div>
        {user.role === 'admin' && (
          <button className="btn danger sm" onClick={remove}>{t('host.remove')}</button>
        )}
      </div>

      <div className="tabs" role="tablist">
        {tabs.map(([k, label]) => (
          <button key={k} role="tab" className={tab === k ? 'active' : ''} onClick={() => (location.hash = `/hosts/${id}/${k}`)}>{label}</button>
        ))}
      </div>

      {tab === 'metrics' && (
        <>
          <Card title={t('host.resources')} actions={<div className="legend-inline"><span>{t('host.load')}: <b className="num" style={{ color: 'var(--text)' }}>{m?.load1?.toFixed(2) ?? '-'}</b></span></div>}>
            <div className="gauges">
              <Gauge size={150} value={m?.cpu} label="CPU" sub={`${a.info?.cpus ?? '?'} cores`} />
              <Gauge size={150} value={m?.mem} label={t('host.memory')} sub={m ? `${bytes(m.memUsed)} / ${bytes(m.memTotal, 0)}` : undefined} />
              <Gauge size={150} value={m?.disk} label={t('host.disk')} sub={m ? `${bytes(m.diskUsed, 0)} / ${bytes(m.diskTotal, 0)}` : undefined} />
              {a.info?.platform !== 'win32' && <Gauge size={150} value={m && a.info?.cpus ? Math.min(100, (m.load1 / a.info.cpus) * 100) : null} label={t('host.load')} sub={`${m?.load1?.toFixed(2) ?? '-'} / ${a.info?.cpus ?? '?'}`} />}
            </div>
          </Card>
          <div className="row" style={{ justifyContent: 'space-between', margin: '20px 0 12px' }}>
            <h2 style={{ fontSize: 16 }}>{t('host.history')}</h2>
            <div className="seg">
              {RANGES.map((r) => (
                <button key={r} className={range === r ? 'active' : ''} onClick={() => setRange(r)}>{r}</button>
              ))}
            </div>
          </div>
          <div className="grid g2">
            <Card title="CPU" actions={<span className="num" style={{ color: 'var(--c1)' }}>{pct(m?.cpu, 1)}</span>}><Chart data={series ?? []} series={[{ key: 'cpu', label: 'CPU', color: 'var(--c1)' }]} max={100} format={(v) => pct(v, 1)} axisFormat={(v) => pct(v)} /></Card>
            <Card title={t('host.memory')} actions={<span className="num" style={{ color: 'var(--c2)' }}>{pct(m?.mem, 1)}</span>}><Chart data={series ?? []} series={[{ key: 'mem', label: t('host.memory'), color: 'var(--c2)' }]} max={100} format={(v) => pct(v, 1)} axisFormat={(v) => pct(v)} /></Card>
            <Card title={t('host.network')} actions={<span className="num muted" style={{ fontSize: 12.5 }}>↓ {rate(m?.rx)} · ↑ {rate(m?.tx)}</span>}>
              <Chart data={series ?? []} series={[{ key: 'rx', label: '↓ rx', color: 'var(--c3)' }, { key: 'tx', label: '↑ tx', color: 'var(--c4)' }]} format={rate} axisFormat={(v) => rate(v).replace('/s', '')} />
            </Card>
            {a.info?.platform !== 'win32' && <Card title={t('host.load')} actions={<span className="num" style={{ color: 'var(--c5)' }}>{m?.load1?.toFixed(2)}</span>}><Chart data={series ?? []} series={[{ key: 'load1', label: t('host.load'), color: 'var(--c5)' }]} format={(v) => v.toFixed(2)} axisFormat={(v) => v.toFixed(1)} /></Card>}
          </div>
          <div className="grid g2" style={{ marginTop: 16 }}>
            <Card title={t('host.system')}>
              <dl className="kv">
                <dt>{t('host.hostname')}</dt><dd>{a.info?.hostname}</dd>
                <dt>OS</dt><dd>{a.info?.os}</dd>
                <dt>Kernel</dt><dd className="mono">{a.info?.kernel}</dd>
                <dt>CPU</dt><dd>{a.info?.cpus}× {a.info?.cpuModel}</dd>
                <dt>{t('host.memory')}</dt><dd>{bytes(a.info?.memTotal, 0)}</dd>
                <dt>Agent</dt><dd className="mono">v{a.info?.agentVersion}</dd>
                <dt>{t('host.enrolled')}</dt><dd>{clock(a.firstSeen)}</dd>
              </dl>
            </Card>
            <Card title={t('host.listening_ports')}>
              {a.ports.length === 0 ? <span className="muted">-</span> : (
                <div className="ports">
                  {a.ports.map((p: any) => (
                    <span key={p.proto + p.port + p.exposed} className={`port ${p.exposed ? 'exposed' : ''}`} title={`${p.addr}`}>{p.port}/{p.proto.replace('6', '')}</span>
                  ))}
                </div>
              )}
              <p className="muted" style={{ fontSize: 12, margin: '12px 0 0' }}>{t('host.ports_legend')}</p>
            </Card>
          </div>
        </>
      )}

      {tab === 'containers' && (
        a.containers ? <Card flush><ContainerTable rows={a.containers.map((c: any) => ({ ...c, agentId: a.id, agent: a.name, online: a.online }))} hideHost onChange={refresh} canAct={canOperate(user) && a.online} /></Card> : <Card><Empty>{t('containers.no_docker')}</Empty></Card>
      )}

      {tab === 'security' && (
        <Card title={t('security.findings')} flush actions={canOperate(user) && a.findings.some((f: any) => f.check_id.startsWith('fim:')) ? <button className="btn sm" disabled={!a.online} onClick={async () => { await api(`/agents/${id}/fim/accept`, { method: 'POST', body: {} }).catch((e) => alert(e.message)); refresh(); }}>{t('security.accept_fim')}</button> : undefined}>
          <FindingList rows={a.findings} onChange={refresh} />
        </Card>
      )}

      {tab === 'admin' && user.role === 'admin' && <HostAdmin agentId={a.id} />}
      {tab === 'ssh' && user.role === 'admin' && <SshAccess agentId={a.id} name={a.name} onGoSecurity={() => (location.hash = `/hosts/${a.id}/security`)} />}

      {tab === 'events' && (
        <Card flush>
          {a.events.length === 0 ? <Empty>{t('events.none')}</Empty> : a.events.map((e: any) => (
            <div className="finding" key={e.id} style={{ padding: '10px 16px' }}>
              <SevPill sev={e.severity} />
              <div><div>{e.message}</div><div className="muted mono" style={{ fontSize: 11.5 }}>{e.type}</div></div>
              <span className="muted num" title={clock(e.ts)}>{ago(e.ts)}</span>
            </div>
          ))}
        </Card>
      )}
    </>
  );
}
