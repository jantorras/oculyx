import { useState } from 'react';
import { api, usePoll, ago, SEVERITIES, SEV_COLOR } from '../lib';
import { useT } from '../i18n';
import { useUser, canOperate } from '../App';
import { Card, Empty, SevPill, Skeleton, Tile } from '../components/ui';
import { Donut, HBars, StackedBars } from '../components/Chart';

export function Security() {
  const t = useT();
  const [status, setStatus] = useState('open');
  const [sev, setSev] = useState<string>('all');
  const { data, refresh } = usePoll(() => api<any[]>(`/findings?status=${status}`), 6000, [status]);
  const { data: stats } = usePoll(() => api<any>('/stats/security'), 8000);
  if (!data) return <Skeleton />;

  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, data.filter((f) => f.severity === s).length]));
  const rows = sev === 'all' ? data : data.filter((f) => f.severity === sev);

  return (
    <>
      <div className="topbar">
        <div className="grow">
          <h1>{t('nav.security')}</h1>
          <div className="sub">{t('security.subtitle')}</div>
        </div>
        <div className="seg">
          {['open', 'ignored', 'resolved'].map((s) => (
            <button key={s} className={status === s ? 'active' : ''} onClick={() => setStatus(s)}>{t(`security.status_${s}`)}</button>
          ))}
        </div>
      </div>
      <div className="grid g4" style={{ gridTemplateColumns: 'repeat(4, minmax(0,1fr))', marginBottom: 16 }}>
        {(['critical', 'high', 'medium', 'low'] as const).map((s) => (
          <button key={s} onClick={() => setSev(sev === s ? 'all' : s)} style={{ all: 'unset', cursor: 'pointer', display: 'block' }} aria-pressed={sev === s}>
            <div style={sev === s ? { borderRadius: 12, boxShadow: `0 0 0 1.5px var(--${s === 'medium' ? 'med' : s})` } : undefined}>
              <Tile label={t(`sev.${s}`)} value={counts[s]} tone={counts[s] ? (s === 'medium' ? 'med' : s) : undefined} />
            </div>
          </button>
        ))}
      </div>
      {stats && (
        <div className="grid g3" style={{ marginBottom: 16 }}>
          <Card title={t('security.by_severity')}>
            <Donut size={130} center={stats.byHost.reduce((a: number, r: any) => a + r.n, 0)} caption={t('overview.findings_caption')}
              slices={(['critical', 'high', 'medium', 'low', 'info'] as const).map((s) => ({ label: t(`sev.${s}`), value: stats.byHost.filter((r: any) => r.severity === s).reduce((a: number, r: any) => a + r.n, 0), color: SEV_COLOR[s] }))} />
          </Card>
          <Card title={t('security.by_host')}>
            <StackedBars rows={hostRows(stats.byHost, t)} />
          </Card>
          <Card title={t('security.by_category')}>
            <HBars max={Math.max(1, ...catRows(stats.byCategory, t).map((r) => r.value))} format={(v) => String(v)} rows={catRows(stats.byCategory, t)} />
          </Card>
        </div>
      )}
      <Card flush>
        <FindingList rows={rows} showHost onChange={refresh} />
      </Card>
    </>
  );
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;
function hostRows(byHost: any[], t: (k: string) => string) {
  const hosts = new Map<number, { name: string; n: Record<string, number> }>();
  for (const r of byHost) {
    const h = hosts.get(r.id) ?? { name: r.name as string, n: {} as Record<string, number> };
    h.n[r.severity] = r.n;
    hosts.set(r.id, h);
  }
  return [...hosts.entries()].map(([id, h]) => ({ label: <a href={`#/hosts/${id}/security`}>{h.name}</a>, parts: SEV_ORDER.map((s) => ({ name: t(`sev.${s}`), value: h.n[s] ?? 0, color: SEV_COLOR[s] })) }));
}
function catRows(byCat: any[], t: (k: string) => string) {
  const m = new Map<string, number>();
  for (const r of byCat) m.set(r.cat, (m.get(r.cat) ?? 0) + r.n);
  return [...m.entries()].sort((a, b) => b[1] - a[1]).map(([cat, value]) => ({ label: t(`cat.${cat}`), value }));
}

export function FindingList({ rows, showHost, onChange }: { rows: any[]; showHost?: boolean; onChange: () => void }) {
  const t = useT();
  const user = useUser();
  if (rows.length === 0) return <Empty>{t('security.none')}</Empty>;
  const act = async (id: number, action: string) => {
    await api(`/findings/${id}/${action}`, { method: 'POST', body: {} });
    onChange();
  };
  return (
    <>
      {rows.map((f) => (
        <div key={f.id} className={`finding ${f.status === 'ignored' ? 'ignored' : ''}`}>
          <SevPill sev={f.severity} />
          <div className="t">{f.title}</div>
          <div className="row" style={{ gap: 6 }}>
            {canOperate(user) && f.status === 'open' && <button className="btn sm" onClick={() => act(f.id, 'ignore')}>{t('security.ignore')}</button>}
            {canOperate(user) && f.status === 'ignored' && <button className="btn sm" onClick={() => act(f.id, 'reopen')}>{t('security.reopen')}</button>}
          </div>
          {f.detail && <div className="d">{f.detail}</div>}
          <div className="m">
            {showHost && <><a href={`#/hosts/${f.agent_id}/security`} style={{ color: 'var(--accent)' }}>{f.agent}</a> · </>}
            <span className="mono">{f.check_id}</span> · {t('security.first_seen')} {ago(f.first_seen)}
          </div>
        </div>
      ))}
    </>
  );
}
