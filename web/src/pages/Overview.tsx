import { useState } from 'react';
import { api, usePoll, ago, uptime, rate, pct, SEV_COLOR, SEVERITIES } from '../lib';
import { useT } from '../i18n';
import { Card, Empty, Icon, Kpi, Score, Skeleton } from '../components/ui';
import { Chart, Columns, Donut, Gauge, Spark } from '../components/Chart';

const RANGES = ['1h', '6h', '24h', '7d'];

export function Overview() {
  const t = useT();
  const [range, setRange] = useState('6h');
  const [view, setView] = useState<'cards' | 'table'>(() => (localStorage.getItem('oculyx.view') as any) || 'cards');
  const { data, error } = usePoll(() => api('/overview'), 4000);
  const { data: fleet } = usePoll(() => api<any[]>(`/fleet/metrics?range=${range}`), 15000, [range]);
  const { data: timeline } = usePoll(() => api<any[]>('/stats/timeline'), 30000);
  if (!data) return error ? <p className="error" role="alert">{t(`err.${error}`)}</p> : <Skeleton />;

  const agents: any[] = data.agents;
  const online = agents.filter((a) => a.online).length;
  const sev = data.findingsBySeverity as Record<string, number>;
  const totalFindings = Object.values(sev).reduce((a, b) => a + b, 0);
  const urgent = (sev.critical ?? 0) + (sev.high ?? 0);
  const scored = agents.filter((a) => a.score != null);
  const avg = scored.length ? Math.round(scored.reduce((s, a) => s + a.score, 0) / scored.length) : null;
  const dockerRun = agents.reduce((s, a) => s + (a.docker?.running ?? 0), 0);
  const dockerAll = agents.reduce((s, a) => s + (a.docker?.total ?? 0), 0);
  const setViewP = (v: 'cards' | 'table') => {
    setView(v);
    try {
      localStorage.setItem('oculyx.view', v);
    } catch {
      /* ignore */
    }
  };

  return (
    <div className="page-in">
      <div className="topbar">
        <div className="grow">
          <h1>{t('nav.overview')}</h1>
          <div className="sub">{t('overview.subtitle', { n: agents.length })}</div>
        </div>
        <a className="btn primary" href="#/settings/enroll">+ {t('overview.add_host')}</a>
      </div>

      <div className="grid g4" style={{ marginBottom: 16 }}>
        <Kpi icon={Icon.hosts} label={t('overview.hosts_online')} value={online} unit={`/ ${agents.length}`} tone={online === agents.length ? 'ok' : 'warn'} hint={agents.length - online > 0 ? t('overview.offline_n', { n: agents.length - online }) : t('overview.all_up')} />
        <Kpi icon={Icon.bell} label={t('overview.active_alerts')} value={data.alerts.length} tone={data.alerts.length ? 'bad' : 'ok'} hint={t('overview.alerts_hint')} />
        <Kpi icon={Icon.shield} label={t('overview.urgent_findings')} value={urgent} tone={urgent ? 'high' : 'ok'} hint={t('overview.findings_hint', { n: totalFindings })} />
        <Kpi icon={Icon.overview} label={t('overview.avg_score')} value={avg ?? '–'} unit="/ 100" tone={avg == null ? undefined : avg >= 85 ? 'ok' : avg >= 60 ? 'warn' : 'bad'} hint={t('overview.score_hint')} />
      </div>

      <div className="grid g-main" style={{ marginBottom: 16 }}>
        <Card
          title={t('overview.fleet_usage')}
          actions={
            <>
              <div className="legend-inline">
                <span><i style={{ background: 'var(--c1)' }} />CPU</span>
                <span><i style={{ background: 'var(--c2)' }} />{t('host.memory')}</span>
              </div>
              <div className="seg">
                {RANGES.map((r) => <button key={r} className={range === r ? 'active' : ''} onClick={() => setRange(r)}>{r}</button>)}
              </div>
            </>
          }
        >
          <Chart height={210} max={100} data={fleet ?? []} format={(v) => pct(v, 1)} axisFormat={(v) => pct(v)} series={[{ key: 'cpu', label: 'CPU', color: 'var(--c1)' }, { key: 'mem', label: t('host.memory'), color: 'var(--c2)' }]} />
        </Card>
        <Card title={t('overview.posture')}>
          <Donut
            center={totalFindings}
            caption={t('overview.findings_caption')}
            slices={SEVERITIES.filter((s) => s !== 'info').map((s) => ({ label: t(`sev.${s}`), value: sev[s] ?? 0, color: SEV_COLOR[s] }))}
          />
        </Card>
      </div>

      <div className="row" style={{ marginBottom: 12 }}>
        <h2 style={{ fontSize: 16 }}>{t('overview.hosts')}</h2>
        <div className="seg view-toggle">
          <button className={view === 'cards' ? 'active' : ''} onClick={() => setViewP('cards')}>{t('overview.view_cards')}</button>
          <button className={view === 'table' ? 'active' : ''} onClick={() => setViewP('table')}>{t('overview.view_table')}</button>
        </div>
      </div>

      {agents.length === 0 ? (
        <section className="card quiet">
          <span className="quiet-ico">{Icon.hosts}</span>
          <h2>{t('overview.no_hosts')}</h2>
          <p className="muted">{t('add.intro')}</p>
          <a className="btn primary" href="#/settings/enroll">{t('overview.add_host')} {Icon.arrow}</a>
        </section>
      ) : view === 'cards' ? (
        <div className="hosts-grid">{agents.map((a) => <HostCard key={a.id} a={a} />)}</div>
      ) : (
        <HostTable agents={agents} />
      )}

      <div className="grid g3" style={{ marginTop: 16 }}>
        <Card title={t('overview.network')} actions={<div className="legend-inline"><span><i style={{ background: 'var(--c3)' }} />↓</span><span><i style={{ background: 'var(--c4)' }} />↑</span></div>}>
          <Chart height={150} data={fleet ?? []} format={rate} axisFormat={(v) => rate(v).replace('/s', '')} series={[{ key: 'rx', label: '↓ rx', color: 'var(--c3)' }, { key: 'tx', label: '↑ tx', color: 'var(--c4)' }]} />
        </Card>
        <Card title={t('overview.activity')} actions={<div className="legend-inline"><span><i style={{ background: SEV_COLOR.high }} />{t('sev.high')}</span><span><i style={{ background: SEV_COLOR.medium }} />{t('sev.medium')}</span><span><i style={{ background: SEV_COLOR.low }} />{t('sev.low')}</span></div>}>
          <Columns height={150} cols={(timeline ?? []).map((h) => ({ label: new Date(h.ts).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }), parts: [{ name: t('sev.high'), value: h.high, color: SEV_COLOR.high }, { name: t('sev.medium'), value: h.medium, color: SEV_COLOR.medium }, { name: t('sev.low'), value: h.low, color: SEV_COLOR.low }] }))} />
        </Card>
        <Card title="Docker">
          <Donut center={`${dockerRun}/${dockerAll}`} caption={t('overview.running')} size={140} slices={[{ label: t('overview.running'), value: dockerRun, color: 'var(--ok)' }, { label: t('overview.stopped'), value: dockerAll - dockerRun, color: 'var(--high)' }]} />
        </Card>
      </div>

      <div className="grid g2" style={{ marginTop: 16 }}>
        <Card title={t('overview.active_alerts')} flush actions={<a className="muted" href="#/alerts">{t('common.view_all')}</a>}>
          {data.alerts.length === 0 ? <Empty>{t('alerts.none')}</Empty> : data.alerts.slice(0, 6).map((a: any) => (
            <div className="timeline-item" key={a.id}>
              <i className="tdot" style={{ background: SEV_COLOR[a.severity] }} />
              <div>
                <div style={{ fontWeight: 600 }}>{t(`rule.${a.rule.split(':')[0]}`)} <span className="muted" style={{ fontWeight: 400 }}>· {a.agent}</span></div>
                <div className="muted" style={{ fontSize: 12.5 }}>{a.message}</div>
              </div>
              <span className="muted num">{ago(a.opened)}</span>
            </div>
          ))}
        </Card>
        <Card title={t('overview.recent_events')} flush actions={<a className="muted" href="#/events">{t('common.view_all')}</a>}>
          {data.events.length === 0 ? <Empty>{t('events.none')}</Empty> : data.events.slice(0, 7).map((e: any) => (
            <div className="timeline-item" key={e.id}>
              <i className="tdot" style={{ background: SEV_COLOR[e.severity] }} />
              <div>
                <div>{e.message}</div>
                <div className="muted" style={{ fontSize: 12.5 }}>{e.agent}</div>
              </div>
              <span className="muted num">{ago(e.ts)}</span>
            </div>
          ))}
        </Card>
      </div>
    </div>
  );
}

function HostCard({ a }: { a: any }) {
  const t = useT();
  const m = a.metrics;
  return (
    <a className={`card hcard ${a.online ? '' : 'down'}`} href={`#/hosts/${a.id}`} aria-label={a.name}>
      <div className="head">
        <div className="grow">
          <div className="name">{a.name}</div>
          <div className="meta">{a.info?.os}</div>
        </div>
        <Score value={a.score} />
      </div>
      {a.online ? (
        <>
          <div className="mini">
            <Gauge size={84} value={m?.cpu} label="CPU" />
            <Gauge size={84} value={m?.mem} label={t('host.memory')} />
            <Gauge size={84} value={m?.disk} label={t('host.disk')} />
          </div>
          <Spark values={a.spark ?? []} width="100%" />
        </>
      ) : (
        <div className="down-note"><div>{t('host.last_seen')} {ago(a.lastSeen)}<br /><span style={{ fontSize: 12 }}>{a.ip}</span></div></div>
      )}
      <div className="foot2">
        <span className={`status-badge ${a.online ? '' : 'off'}`}><i />{a.online ? t('status.online') : t('status.offline')}</span>
        {a.online && <span className="chip">{Icon.overview}{t('host.up')} {uptime(m?.uptime)}</span>}
        {a.docker && <span className="chip">{Icon.docker}{a.docker.running}/{a.docker.total}</span>}
        {a.openFindings > 0 && <span className="chip">{Icon.shield}{a.openFindings}</span>}
        {a.openAlerts > 0 && <span className="pill high" style={{ marginLeft: 'auto' }} title={t('nav.alerts')}>{Icon.bell}{a.openAlerts}</span>}
      </div>
    </a>
  );
}

function HostTable({ agents }: { agents: any[] }) {
  const t = useT();
  return (
    <Card flush>
      <div className="table-wrap">
        <table>
          <thead><tr><th>{t('host.name')}</th><th>CPU</th><th>{t('host.memory')}</th><th>{t('host.disk')}</th><th>{t('host.network')}</th><th>{t('nav.containers')}</th><th>{t('host.alerts')}</th><th className="r">{t('host.score')}</th></tr></thead>
          <tbody>
            {agents.map((a) => (
              <tr key={a.id} className="link" onClick={() => (location.hash = `/hosts/${a.id}`)}>
                <td>
                  <a href={`#/hosts/${a.id}`} style={{ fontWeight: 600 }}>{a.name}</a>
                  <div className="muted" style={{ fontSize: 12 }}>{a.online ? <>{a.info?.os} · {t('host.up')} {uptime(a.metrics?.uptime)}</> : <>{t('status.offline')} · {t('host.last_seen')} {ago(a.lastSeen)}</>}</div>
                </td>
                <td>{a.online ? <div className="row num">{a.metrics?.cpu?.toFixed(0)}%<Spark values={a.spark ?? []} /></div> : '-'}</td>
                <td className="num">{a.online ? pct(a.metrics?.mem) : '-'}</td>
                <td className="num">{pct(a.metrics?.disk)}</td>
                <td className="num muted" style={{ fontSize: 12 }}>{a.online ? <>↓ {rate(a.metrics?.rx)}<br />↑ {rate(a.metrics?.tx)}</> : '-'}</td>
                <td className="num">{a.docker ? `${a.docker.running}/${a.docker.total}` : '-'}</td>
                <td>{a.openAlerts ? <span className="pill high">{a.openAlerts}</span> : <span className="muted">0</span>}</td>
                <td className="r"><Score value={a.score} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

