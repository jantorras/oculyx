import { useState } from 'react';
import { api, usePoll, ago, clock } from '../lib';
import { useT } from '../i18n';
import { Card, Empty, SevPill } from '../components/ui';
import { Columns } from '../components/Chart';
import { SEV_COLOR } from '../lib';

const TYPES = ['', 'ssh_failed', 'ssh_login', 'sudo', 'fim', 'port_opened'];

export function Events() {
  const t = useT();
  const [type, setType] = useState('');
  const { data } = usePoll(() => api<any[]>(`/events${type ? `?type=${type}` : ''}`), 6000, [type]);
  const { data: timeline } = usePoll(() => api<any[]>('/stats/timeline'), 30000);
  return (
    <>
      <div className="topbar">
        <div className="grow">
          <h1>{t('nav.events')}</h1>
          <div className="sub">{t('events.subtitle')}</div>
        </div>
        <select value={type} onChange={(e) => setType(e.target.value)} aria-label={t('events.type')}>
          {TYPES.map((x) => <option key={x} value={x}>{x ? t(`evt.${x}`) : t('events.all_types')}</option>)}
        </select>
      </div>
      <Card title={t('overview.activity')} actions={<div className="legend-inline"><span><i style={{ background: SEV_COLOR.high }} />{t('sev.high')}</span><span><i style={{ background: SEV_COLOR.medium }} />{t('sev.medium')}</span><span><i style={{ background: SEV_COLOR.low }} />{t('sev.low')}</span></div>}>
        <Columns height={110} cols={(timeline ?? []).map((h) => ({ label: new Date(h.ts).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }), parts: [{ name: t('sev.high'), value: h.high, color: SEV_COLOR.high }, { name: t('sev.medium'), value: h.medium, color: SEV_COLOR.medium }, { name: t('sev.low'), value: h.low, color: SEV_COLOR.low }] }))} />
      </Card>
      <div style={{ height: 16 }} />
      <Card flush>
        {!data ? <Empty>{t('common.loading')}</Empty> : data.length === 0 ? <Empty>{t('events.none')}</Empty> : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>{t('security.severity')}</th><th>{t('events.type')}</th><th>{t('events.message')}</th><th>{t('nav.hosts')}</th><th className="r">{t('events.when')}</th></tr></thead>
              <tbody>
                {data.map((e) => (
                  <tr key={e.id}>
                    <td><SevPill sev={e.severity} /></td>
                    <td className="mono muted">{e.type}</td>
                    <td>{e.message}</td>
                    <td><a href={`#/hosts/${e.agent_id}/events`} style={{ color: 'var(--accent)' }}>{e.agent}</a></td>
                    <td className="r num muted" title={clock(e.ts)}>{ago(e.ts)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
