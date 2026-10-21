import { useEffect, useMemo, useState } from 'react';
import { api, usePoll, clock } from '../lib';
import { useT } from '../i18n';
import { Card, Empty, Modal, Skeleton } from '../components/ui';
import { Menu, ask, toast } from '../components/overlay';
import { PolicyEditor, isEmpty, type PolicyConfig, type Effective, type RuleMeta } from '../components/PolicyEditor';

interface Profile { id: number; name: string; description: string; config: PolicyConfig; hosts: number[] }
interface HostRow { id: number; name: string; profileId: number | null; overrides: number; mutedUntil: number; mutedReason: string }
interface Data {
  profiles: Profile[];
  rules: (RuleMeta & { global: { enabled: boolean; severity: any } })[];
  base: { thresholds: Effective['thresholds']; samples: number; minSeverity: string };
  hosts: HostRow[];
  criticalBreaks: boolean;
}

/** Alert policies: what each host alerts about. Profiles are reusable; each host can add exceptions. */
export function Policies() {
  const t = useT();
  const { data, refresh } = usePoll(() => api<Data>('/policies'), 8000);
  const [tab, setTab] = useState<'profiles' | 'hosts'>('profiles');
  if (!data) return <Skeleton />;
  const globalEff: Effective = {
    ...data.base,
    rules: Object.fromEntries(data.rules.map((r) => [r.id, { enabled: r.global.enabled, severity: r.global.severity }])),
  };
  return (
    <div style={{ maxWidth: 1100 }}>
      <div className="topbar">
        <div className="grow">
          <h1>{t('nav.policies')}</h1>
          <div className="sub">{t('pol.subtitle')}</div>
        </div>
      </div>
      <div className="tabs" role="tablist">
        {(['profiles', 'hosts'] as const).map((k) => (
          <button key={k} role="tab" aria-selected={tab === k} className={tab === k ? 'active' : ''} onClick={() => setTab(k)}>{t(`pol.tab_${k}`)}</button>
        ))}
      </div>
      {tab === 'profiles'
        ? <Profiles data={data} base={globalEff} refresh={refresh} />
        : <Hosts data={data} base={globalEff} refresh={refresh} />}
    </div>
  );
}

function Profiles({ data, base, refresh }: { data: Data; base: Effective; refresh: () => void }) {
  const t = useT();
  const [sel, setSel] = useState<number | 'new'>(data.profiles[0]?.id ?? 'new');
  const cur = typeof sel === 'number' ? data.profiles.find((p) => p.id === sel) : undefined;
  const [name, setName] = useState('');
  const [desc, setDesc] = useState('');
  const [cfg, setCfg] = useState<PolicyConfig>({});
  const [hosts, setHosts] = useState<Set<number>>(new Set());
  const [q, setQ] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  // load the selected profile into the form (only when the selection changes)
  useEffect(() => {
    setName(cur?.name ?? '');
    setDesc(cur?.description ?? '');
    setCfg(cur?.config ?? {});
    setHosts(new Set(cur?.hosts ?? []));
    setErr('');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sel]);
  useEffect(() => { if (sel !== 'new' && !cur) setSel(data.profiles[0]?.id ?? 'new'); }, [data, sel, cur]);

  const shown = useMemo(() => data.hosts.filter((h) => h.name.toLowerCase().includes(q.trim().toLowerCase())), [data.hosts, q]);
  const save = async () => {
    setBusy(true);
    setErr('');
    try {
      const body = { name, description: desc, config: cfg };
      const r = sel === 'new' ? await api<{ id: number }>('/profiles', { method: 'POST', body }) : await api<{ id: number }>(`/profiles/${sel}`, { method: 'PUT', body });
      await api(`/profiles/${r.id}/hosts`, { method: 'PUT', body: { agentIds: [...hosts] } });
      toast(t('common.saved'));
      setSel(r.id);
      refresh();
    } catch (e: any) {
      setErr(e.message === 'name_taken' ? t('pol.name_taken') : e.message === 'name_required' ? t('pol.name_required') : e.message);
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    if (!cur || !(await ask({ title: t('pol.delete_title', { name: cur.name }), body: t('pol.delete_body', { n: cur.hosts.length }), confirm: t('pol.delete'), danger: true }))) return;
    await api(`/profiles/${cur.id}`, { method: 'DELETE' });
    setSel('new');
    refresh();
  };
  const duplicate = () => {
    setSel('new');
    setTimeout(() => { setName(`${cur?.name ?? ''} (2)`); setDesc(cur?.description ?? ''); setCfg(cur?.config ?? {}); setHosts(new Set()); }, 0);
  };

  return (
    <div className="pol-layout">
      <aside className="pol-list" aria-label={t('pol.tab_profiles')}>
        {data.profiles.map((p) => (
          <button key={p.id} className={`pol-item ${sel === p.id ? 'active' : ''}`} onClick={() => setSel(p.id)}>
            <b>{p.name}</b>
            <span className="muted small">{t('pol.n_hosts', { n: p.hosts.length })}</span>
          </button>
        ))}
        <button className={`pol-item new ${sel === 'new' ? 'active' : ''}`} onClick={() => setSel('new')}>+ {t('pol.new')}</button>
        <p className="muted small" style={{ margin: '10px 4px 0' }}>{t('pol.order_help')}</p>
      </aside>

      <div className="grid" style={{ minWidth: 0 }}>
        <Card title={sel === 'new' ? t('pol.new') : cur?.name}
          actions={<div className="row" style={{ gap: 8 }}>{cur && <button className="btn sm" onClick={duplicate}>{t('pol.duplicate')}</button>}{cur && <button className="btn sm danger" onClick={remove}>{t('pol.delete')}</button>}</div>}>
          <div className="grid g2">
            <label className="field">{t('pol.name')}<input value={name} maxLength={60} onChange={(e) => setName(e.target.value)} /></label>
            <label className="field">{t('pol.description')}<input value={desc} maxLength={200} onChange={(e) => setDesc(e.target.value)} /></label>
          </div>
        </Card>

        <Card title={t('pol.hosts_in')}>
          {data.hosts.length === 0 ? <Empty>{t('pol.no_hosts')}</Empty> : (
            <>
              <input className="search" placeholder={t('pol.search_hosts')} value={q} onChange={(e) => setQ(e.target.value)} style={{ marginBottom: 10, maxWidth: 280 }} />
              <div className="pol-hosts">
                {shown.map((h) => {
                  const other = h.profileId && h.profileId !== sel ? data.profiles.find((p) => p.id === h.profileId)?.name : '';
                  return (
                    <label key={h.id} className="pol-host">
                      <input type="checkbox" checked={hosts.has(h.id)} onChange={() => setHosts((s) => { const n = new Set(s); n.has(h.id) ? n.delete(h.id) : n.add(h.id); return n; })} />
                      <span>{h.name}</span>
                      {other && !hosts.has(h.id) && <span className="muted small">{t('pol.currently', { name: other })}</span>}
                      {other && hosts.has(h.id) && <span className="muted small">{t('pol.will_move', { name: other })}</span>}
                    </label>
                  );
                })}
              </div>
            </>
          )}
        </Card>

        <Card title={t('pol.alerts_in')}>
          <PolicyEditor value={cfg} onChange={setCfg} inherited={base} rules={data.rules} from={t('pol.from_global')} />
        </Card>

        <div className="row" style={{ gap: 12 }}>
          <button className="btn primary" disabled={busy || !name.trim()} onClick={save}>{t('common.save')}</button>
          {err && <span className="error" role="alert">{err}</span>}
        </div>
      </div>
    </div>
  );
}

const WINDOWS = [30, 120, 480, 1440];

function Hosts({ data, base, refresh }: { data: Data; base: Effective; refresh: () => void }) {
  const t = useT();
  const [edit, setEdit] = useState<HostRow | null>(null);
  const [sel, setSel] = useState<Set<number>>(new Set());
  const names = new Map(data.profiles.map((p) => [p.id, p.name]));
  const setProfile = async (id: number, profileId: number | null) => { await api(`/agents/${id}/policy`, { method: 'PUT', body: { profileId } }); refresh(); };
  const mute = async (ids: number[], minutes: number | null) => {
    await api('/maintenance', { method: 'POST', body: { agentIds: ids, minutes } });
    toast(minutes ? t('pol.maint_started') : t('pol.maint_ended'));
    setSel(new Set());
    refresh();
  };
  const label = (m: number) => (m < 60 ? `${m} min` : `${m / 60} h`);
  const maintItems = (ids: number[], active: boolean) => [
    ...WINDOWS.map((m) => ({ label: t('pol.silence_for', { d: label(m) }), onClick: () => mute(ids, m) })),
    ...(active ? ['sep' as const, { label: t('pol.end_maint'), onClick: () => mute(ids, null) }] : []),
  ];
  const allSel = data.hosts.length > 0 && data.hosts.every((h) => sel.has(h.id));

  return (
    <>
      <Card flush title={t('pol.tab_hosts')}
        actions={sel.size > 0 ? (
          <select aria-label={t('pol.maintenance')} value="" onChange={(e) => e.target.value && mute([...sel], Number(e.target.value))}>
            <option value="">{t('pol.silence_selected', { n: sel.size })}</option>
            {WINDOWS.map((m) => <option key={m} value={m}>{t('pol.silence_for', { d: label(m) })}</option>)}
          </select>
        ) : undefined}>
        {data.hosts.length === 0 ? <Empty>{t('pol.no_hosts')}</Empty> : (
          <table className="rows">
            <thead>
              <tr>
                <th style={{ width: 32 }}><input type="checkbox" checked={allSel} onChange={() => setSel(allSel ? new Set() : new Set(data.hosts.map((h) => h.id)))} aria-label={t('pol.select_all')} /></th>
                <th>{t('pol.host')}</th><th>{t('pol.profile')}</th><th>{t('pol.exceptions')}</th><th>{t('pol.maintenance')}</th>
              </tr>
            </thead>
            <tbody>
              {data.hosts.map((h) => (
                <tr key={h.id}>
                  <td><input type="checkbox" checked={sel.has(h.id)} onChange={() => setSel((s) => { const n = new Set(s); n.has(h.id) ? n.delete(h.id) : n.add(h.id); return n; })} aria-label={h.name} /></td>
                  <td><a href={`#/hosts/${h.id}`}><b>{h.name}</b></a></td>
                  <td>
                    <select value={h.profileId ?? ''} onChange={(e) => setProfile(h.id, e.target.value ? Number(e.target.value) : null)} aria-label={`${h.name}: ${t('pol.profile')}`}>
                      <option value="">{t('pol.no_profile')}</option>
                      {[...names].map(([id, n]) => <option key={id} value={id}>{n}</option>)}
                    </select>
                  </td>
                  <td>
                    <button className="btn sm" onClick={() => setEdit(h)}>{h.overrides ? t('pol.n_exceptions', { n: h.overrides }) : t('pol.add_exceptions')}</button>
                  </td>
                  <td>
                    {h.mutedUntil ? <span className="tag warn" title={h.mutedReason}>{t('pol.until', { t: clock(h.mutedUntil) })}</span> : <span className="muted small">{t('pol.alerting')}</span>}{' '}
                    <Menu label={`${h.name}: ${t('pol.maintenance')}`} items={maintItems([h.id], !!h.mutedUntil)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <label className="optrow" style={{ marginTop: 14 }}>
        <span className="grow"><b>{t('pol.critical_breaks')}</b><span className="muted small" style={{ display: 'block' }}>{t('pol.critical_breaks_hint')}</span></span>
        <button type="button" className={`toggle ${data.criticalBreaks ? 'on' : ''}`} role="switch" aria-checked={data.criticalBreaks} onClick={async () => { await api('/maintenance/settings', { method: 'PUT', body: { criticalBreaks: !data.criticalBreaks } }); refresh(); }}><i /></button>
      </label>
      {edit && <HostExceptions host={edit} rules={data.rules} onClose={() => { setEdit(null); refresh(); }} />}
    </>
  );
}

function HostExceptions({ host, rules, onClose }: { host: HostRow; rules: RuleMeta[]; onClose: () => void }) {
  const t = useT();
  const [pol, setPol] = useState<{ profileName: string | null; inherited: Effective; overrides: PolicyConfig } | null>(null);
  const [cfg, setCfg] = useState<PolicyConfig>({});
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    void api<any>(`/agents/${host.id}/policy`).then((p) => { setPol(p); setCfg(p.overrides); });
  }, [host.id]);
  const save = async () => {
    setBusy(true);
    try {
      await api(`/agents/${host.id}/policy`, { method: 'PUT', body: { overrides: cfg } });
      toast(t('common.saved'));
      onClose();
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal wide title={t('pol.exceptions_for', { name: host.name })} onClose={onClose}>
      {!pol ? <Skeleton /> : (
        <>
          <p className="muted small" style={{ marginTop: 0 }}>{pol.profileName ? t('pol.inherits_from', { name: pol.profileName }) : t('pol.inherits_global')}</p>
          <PolicyEditor value={cfg} onChange={setCfg} inherited={pol.inherited} rules={rules} from={pol.profileName ?? t('pol.from_global')} />
          <div className="row" style={{ gap: 10, marginTop: 18 }}>
            <button className="btn primary" disabled={busy} onClick={save}>{t('common.save')}</button>
            {!isEmpty(cfg) && <button className="btn" onClick={() => setCfg({})}>{t('pol.clear_all')}</button>}
          </div>
        </>
      )}
    </Modal>
  );
}
