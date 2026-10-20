import { useMemo, useState } from 'react';
import { api, usePoll, ago, clock } from '../lib';
import { useT } from '../i18n';
import { useUser } from '../App';
import { Card, Empty, Modal, Skeleton, StatusDot } from '../components/ui';

/** Fleet administration: every host that ever connected, with rename and (bulk) removal. */
export function Servers() {
  const t = useT();
  const user = useUser();
  const isAdmin = user.role === 'admin';
  const { data, refresh } = usePoll(() => api<{ agents: any[] }>('/overview'), 5000);
  const [q, setQ] = useState('');
  const [filter, setFilter] = useState<'all' | 'online' | 'offline'>('all');
  const [sel, setSel] = useState<Set<number>>(new Set());
  const [confirm, setConfirm] = useState(false);
  const [rename, setRename] = useState<{ id: number; name: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (data?.agents ?? [])
      .filter((a) => (filter === 'all' || (filter === 'online') === a.online) && (!needle || `${a.name} ${a.ip ?? ''} ${a.info?.os ?? ''}`.toLowerCase().includes(needle)))
      .sort((x, y) => Number(x.online) - Number(y.online) || x.name.localeCompare(y.name));
  }, [data, q, filter]);

  if (!data) return <Skeleton />;
  const names = new Map(data.agents.map((a) => [a.id, a.name]));
  const toggle = (id: number) => setSel((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const allShown = rows.length > 0 && rows.every((a) => sel.has(a.id));
  const mode = (a: any) => (!a.info ? '-' : a.info.canHarden ? t('servers.mode_full') : t('servers.mode_native'));

  const remove = async () => {
    setBusy(true);
    setErr('');
    try {
      const r = await api<{ removed: number }>('/agents/delete', { body: { ids: [...sel] } });
      setMsg(t('servers.removed', { n: r.removed }));
      setSel(new Set());
      setConfirm(false);
      refresh();
    } catch (e) {
      setErr(t(`err.${(e as Error).message}`));
    } finally {
      setBusy(false);
    }
  };
  const doRename = async () => {
    if (!rename) return;
    setErr('');
    try {
      await api(`/agents/${rename.id}`, { method: 'PATCH', body: { name: rename.name } });
      setRename(null);
      refresh();
    } catch (e) {
      setErr(t(`err.${(e as Error).message}`));
    }
  };

  return (
    <>
      <div className="topbar">
        <div className="grow">
          <h1>{t('nav.servers')}</h1>
          <div className="sub">{t('servers.subtitle')}</div>
        </div>
        {isAdmin && <a className="btn primary" href="#/settings/enroll">{t('servers.add')}</a>}
      </div>

      <div className="row wrap" style={{ gap: 10, marginBottom: 14, alignItems: 'center' }}>
        <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder={t('servers.search')} aria-label={t('servers.search')} style={{ minWidth: 220, flex: '1 1 220px', maxWidth: 360 }} />
        <div className="seg">
          {(['all', 'online', 'offline'] as const).map((f) => <button key={f} className={filter === f ? 'active' : ''} onClick={() => setFilter(f)}>{t(`servers.${f}`)}</button>)}
        </div>
        <span className="grow" />
        {isAdmin && (
          <>
            <button className="btn" onClick={() => setSel(new Set(data.agents.filter((a) => !a.online).map((a) => a.id)))}>{t('servers.select_offline')}</button>
            <button className="btn danger" disabled={sel.size === 0} onClick={() => setConfirm(true)}>{t('servers.delete_selected', { n: sel.size })}</button>
          </>
        )}
      </div>
      {msg && <div role="status" style={{ color: 'var(--ok)', marginBottom: 10 }}>{msg}</div>}

      <Card flush>
        {rows.length === 0 ? <Empty>{t('servers.none')}</Empty> : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  {isAdmin && <th style={{ width: 36 }}><input type="checkbox" checked={allShown} onChange={() => setSel(allShown ? new Set() : new Set(rows.map((a) => a.id)))} aria-label="select all" /></th>}
                  <th>{t('servers.col_name')}</th><th>{t('servers.col_status')}</th><th>OS</th><th>IP</th><th>{t('servers.col_agent')}</th><th>{t('servers.col_seen')}</th><th className="r">{t('nav.security')}</th>{isAdmin && <th />}
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => (
                  <tr key={a.id}>
                    {isAdmin && <td><input type="checkbox" checked={sel.has(a.id)} onChange={() => toggle(a.id)} aria-label={a.name} /></td>}
                    <td style={{ fontWeight: 600, whiteSpace: 'nowrap' }}><a href={`#/hosts/${a.id}`}>{a.name}</a></td>
                    <td style={{ whiteSpace: 'nowrap' }}><StatusDot online={a.online} /></td>
                    <td className="muted">{a.info?.os ?? '-'}</td>
                    <td className="mono muted">{(a.ip ?? '').replace('::ffff:', '') || '-'}</td>
                    <td className="muted" style={{ fontSize: 12.5 }}>{a.info?.agentVersion ?? '-'} · {mode(a)}</td>
                    <td className="muted num" title={clock(a.lastSeen)}>{a.online ? '-' : ago(a.lastSeen)}</td>
                    <td className="r num">{a.openFindings}{a.openAlerts ? <span className="muted"> · {a.openAlerts} ⚑</span> : null}</td>
                    {isAdmin && (
                      <td className="r">
                        <div className="row" style={{ gap: 6, justifyContent: 'flex-end' }}>
                          <button className="btn sm" onClick={() => setRename({ id: a.id, name: a.name })}>{t('servers.rename')}</button>
                          <button className="btn sm danger" onClick={() => { setSel(new Set([a.id])); setConfirm(true); }}>{t('common.delete')}</button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {confirm && (
        <Modal title={t('servers.confirm_title', { n: sel.size })} onClose={() => !busy && setConfirm(false)}>
          <ul className="steps">{[...sel].map((id) => <li key={id}><b>{names.get(id) ?? `#${id}`}</b></li>)}</ul>
          <div className="warn">{t('servers.confirm_body')}</div>
          {err && <div className="error" role="alert">{err}</div>}
          <div className="row" style={{ justifyContent: 'flex-end', gap: 8 }}>
            <button className="btn" disabled={busy} onClick={() => setConfirm(false)}>{t('common.cancel')}</button>
            <button className="btn danger" disabled={busy} onClick={remove}>{busy ? t('servers.deleting') : t('common.delete')}</button>
          </div>
        </Modal>
      )}
      {rename && (
        <Modal title={t('servers.rename_title')} onClose={() => setRename(null)}>
          <form className="grid" onSubmit={(e) => { e.preventDefault(); void doRename(); }}>
            <label className="field">{t('servers.col_name')}<input autoFocus value={rename.name} onChange={(e) => setRename({ ...rename, name: e.target.value })} maxLength={64} required /></label>
            {err && <div className="error" role="alert">{err}</div>}
            <div className="row" style={{ justifyContent: 'flex-end', gap: 8 }}>
              <button type="button" className="btn" onClick={() => setRename(null)}>{t('common.cancel')}</button>
              <button className="btn primary">{t('common.save')}</button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}
