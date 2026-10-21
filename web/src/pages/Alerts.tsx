import { AlertInfo } from '../components/AlertInfo';
import { useMemo, useState } from 'react';
import { api, usePoll, useRoute, hashQuery, setHashQuery, ago, clock, duration, SEV_COLOR } from '../lib';
import { useT } from '../i18n';
import { useUser, canOperate } from '../App';
import { Card, Icon, SevPill, Skeleton } from '../components/ui';
import { Columns } from '../components/Chart';

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVS = ['critical', 'high', 'medium', 'low'] as const;
const PAGE = 40;

export function Alerts() {
  const t = useT();
  const user = useUser();
  useRoute(); // re-render when the URL query changes
  const q = hashQuery();
  const state = q.get('state') === 'history' ? 'history' : 'active';
  const sev = q.get('sev') ?? '';
  const host = q.get('host') ?? '';
  const text = q.get('q') ?? '';
  const [shown, setShown] = useState(PAGE);
  const [busy, setBusy] = useState(false);

  const { data, refresh } = usePoll(() => api<any[]>(`/alerts${state === 'active' ? '?state=open' : ''}`), 5000, [state]);
  const { data: stats, refresh: refreshStats } = usePoll(() => api<any>('/stats/alerts'), 15000);

  const hosts = useMemo(() => [...new Set((data ?? []).map((a) => a.agent as string))].sort(), [data]);
  const filtered = useMemo(() => {
    const needle = text.trim().toLowerCase();
    return (data ?? [])
      .filter((a) => (!sev || a.severity === sev) && (!host || a.agent === host) && (!needle || `${a.agent} ${a.message} ${a.rule} ${t(`rule.${a.rule.split(':')[0]}`)}`.toLowerCase().includes(needle)))
      .sort((a, b) => (state === 'active' ? (a.state === 'open' ? 0 : 1) - (b.state === 'open' ? 0 : 1) || SEV_RANK[a.severity] - SEV_RANK[b.severity] : 0) || b.opened - a.opened);
  }, [data, sev, host, text, state, t]);

  if (!data || !stats) return <Skeleton kpis={4} blocks={1} />;

  const counts = Object.fromEntries(SEVS.map((s) => [s, data.filter((a) => a.severity === s).length]));
  const filtersOn = !!(sev || host || text);
  const set = (patch: Record<string, string | null>) => {
    setShown(PAGE);
    setHashQuery(patch);
  };

  const ack = async (id: number) => {
    await api(`/alerts/${id}/ack`, { method: 'POST', body: {} });
    refresh();
    refreshStats();
  };
  const ackAll = async () => {
    setBusy(true);
    try {
      await api('/alerts/ack-all', { method: 'POST', body: {} });
      refresh();
      refreshStats();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page page-in">
      <div className="page-head">
        <div className="grow">
          <h1>{t('nav.alerts')}</h1>
          <div className="sub">{t('alerts.subtitle')}</div>
        </div>
        {canOperate(user) && stats.open > 0 && (
          <button className="btn" onClick={ackAll} disabled={busy}>
            {Icon.check}
            {t('alerts.ack_all')} ({stats.open})
          </button>
        )}
      </div>

      <div className="alerts-top">
        <dl className="statgrid kpi-row">
          <div className={stats.open ? 'hot' : ''}>
            <dt>{t('alerts.open_n')}</dt>
            <dd className="num">{stats.open}</dd>
          </div>
          <div>
            <dt>{t('alerts.ack_n')}</dt>
            <dd className="num">{stats.ack}</dd>
          </div>
          <div>
            <dt>{t('alerts.resolved_24h')}</dt>
            <dd className="num">{stats.resolved24h}</dd>
          </div>
          <div>
            <dt>{t('alerts.mttr')}</dt>
            <dd className="num">{stats.mttrMs == null ? '–' : duration(stats.mttrMs)}</dd>
            <dd className="hint">{t('alerts.mttr_hint')}</dd>
          </div>
        </dl>
        <Card
          title={t('alerts.last_24h')}
          actions={
            <div className="legend-inline">
              <span><i style={{ background: SEV_COLOR.high }} />{t('sev.high')}</span>
              <span><i style={{ background: SEV_COLOR.medium }} />{t('sev.medium')}</span>
              <span><i style={{ background: SEV_COLOR.low }} />{t('sev.low')}</span>
            </div>
          }
        >
          <Columns
            height={92}
            cols={stats.timeline.map((h: any) => ({
              label: new Date(h.ts).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }),
              parts: [
                { name: t('sev.high'), value: h.high, color: SEV_COLOR.high },
                { name: t('sev.medium'), value: h.medium, color: SEV_COLOR.medium },
                { name: t('sev.low'), value: h.low, color: SEV_COLOR.low },
              ],
            }))}
          />
        </Card>
      </div>

      <section className="sect">
      <h2 className="sect-title">{t(state === 'active' ? 'alerts.active' : 'alerts.history')} <span className="muted num">({filtered.length})</span></h2>
      <div className="filterbar" role="search">
        <div className="seg" role="tablist" aria-label={t('alerts.state')}>
          <button role="tab" aria-selected={state === 'active'} className={state === 'active' ? 'active' : ''} onClick={() => set({ state: null })}>{t('alerts.active')}</button>
          <button role="tab" aria-selected={state === 'history'} className={state === 'history' ? 'active' : ''} onClick={() => set({ state: 'history' })}>{t('alerts.history')}</button>
        </div>
        <div className="chips" role="group" aria-label={t('security.severity')}>
          <button className={`chip-btn ${sev === '' ? 'on' : ''}`} aria-pressed={sev === ''} onClick={() => set({ sev: null })}>{t('alerts.all_sev')}<b className="num">{data.length}</b></button>
          {SEVS.map((s) => (
            <button key={s} className={`chip-btn ${sev === s ? 'on' : ''}`} aria-pressed={sev === s} onClick={() => set({ sev: sev === s ? null : s })} disabled={!counts[s] && sev !== s}>
              <i style={{ background: SEV_COLOR[s] }} />
              {t(`sev.${s}`)}
              <b className="num">{counts[s]}</b>
            </button>
          ))}
        </div>
        <div className="grow" />
        <select value={host} onChange={(e) => set({ host: e.target.value })} aria-label={t('nav.hosts')} name="host">
          <option value="">{t('alerts.all_hosts')}</option>
          {hosts.map((h) => <option key={h} value={h}>{h}</option>)}
        </select>
        <input className="search" type="search" name="q" autoComplete="off" spellCheck={false} placeholder={t('alerts.search')} aria-label={t('alerts.search')} value={text} onChange={(e) => set({ q: e.target.value })} />
      </div>

      {filtered.length === 0 ? (
        <section className="card quiet">
          <span className="quiet-ico">{filtersOn ? Icon.arrow : Icon.check}</span>
          {filtersOn || data.length > 0 ? (
            <>
              <h2>{t('alerts.no_match')}</h2>
              <button className="btn" onClick={() => set({ sev: null, host: null, q: null })}>{t('alerts.clear_filters')}</button>
            </>
          ) : (
            <>
              <h2>{state === 'active' ? t('alerts.quiet_title') : t('alerts.none')}</h2>
              {state === 'active' && <p className="muted">{t('alerts.quiet_body')}</p>}
            </>
          )}
        </section>
      ) : (
        <div className="table-wrap" aria-live="polite">
          <table className="rows tbl-dense">
            <thead><tr><th>{t('security.severity')}</th><th>{t('nav.alerts')}</th><th>{t('pol.host')}</th><th>{t('alerts.state')}</th><th>{t('alerts.opened')}</th><th>{t('common.actions')}</th></tr></thead>
            <tbody>
          {filtered.slice(0, shown).map((a) => {
            const closed = a.state === 'closed';
            return (
              <tr key={a.id} className={a.state} data-severity={a.severity} style={{ ['--row-severity' as string]: SEV_COLOR[a.severity] }}>
                <td><SevPill sev={a.severity} /></td>
                <td>
                  <b>{t(`rule.${a.rule.split(':')[0]}`)}</b>
                  <div style={{ overflowWrap: 'anywhere' }}>{a.message}</div>
                  <details><summary className="muted small">{t('alerts.what_to_do')}</summary><AlertInfo rule={a.rule} /></details>
                </td>
                <td><a href={`#/hosts/${a.agent_id}`}>{a.agent}</a></td>
                <td>
                  <span className={`pill ${a.state === 'open' ? 'high' : a.state === 'ack' ? 'medium' : 'ok'}`}>{t(`alerts.state_${a.state}`)}</span>
                </td>
                <td><span className="num muted" title={clock(a.opened)}>
                    {closed ? `${t('alerts.lasted')} ${duration(a.closed - a.opened)}` : `${ago(a.opened)}`}
                  </span>
                  {closed && <div className="muted small">{ago(a.closed)} · {clock(a.opened)}</div>}
                </td>
                <td><div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
                  {a.state === 'open' && canOperate(user) && (
                    <button className="btn sm" onClick={() => ack(a.id)}>
                      {Icon.check}
                      {t('alerts.ack')}
                    </button>
                  )}
                  <a className="btn sm ghost" href={`#/hosts/${a.agent_id}`}>
                    {t('alerts.view_host')}
                    {Icon.arrow}
                  </a>
                </div></td>
              </tr>
            );
          })}
            </tbody>
          </table>
          {filtered.length > shown && (
            <button className="btn more" onClick={() => setShown(shown + PAGE)}>
              {t('common.show_more', { n: Math.min(PAGE, filtered.length - shown) })}
            </button>
          )}
        </div>
      )}
      </section>
    </div>
  );
}
