import { useState } from 'react';
import { api, usePoll, clock, ago } from '../lib';
import { useT } from '../i18n';
import { useUser } from '../App';
import { Card, Empty } from '../components/ui';
import { AddHost } from './AddHost';

export function Settings({ tab: tabParam }: { tab?: string }) {
  const t = useT();
  const user = useUser();
  const isAdmin = user.role === 'admin';
  const tabs = isAdmin ? ['enroll', 'users', 'notify', 'domain', 'audit', 'account'] : ['account'];
  const tab = tabs.includes(tabParam ?? '') ? tabParam! : tabs[0];
  return (
    <>
      <div className="topbar"><h1>{t('nav.settings')}</h1></div>
      <div className="tabs">
        {tabs.map((k) => <button key={k} className={tab === k ? 'active' : ''} onClick={() => (location.hash = `/settings/${k}`)}>{t(`settings.${k}`)}</button>)}
      </div>
      {tab === 'enroll' && <AddHost />}
      {tab === 'users' && <Users />}
      {tab === 'notify' && <Notify />}
      {tab === 'domain' && <Domain />}
      {tab === 'audit' && <Audit />}
      {tab === 'account' && <Account />}
    </>
  );
}

function Users() {
  const t = useT();
  const me = useUser();
  const { data, refresh } = usePoll(() => api<any[]>('/users'), 10000);
  const [f, setF] = useState({ username: '', password: '', role: 'viewer' });
  const [err, setErr] = useState('');
  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr('');
    try {
      await api('/users', { body: f });
      setF({ username: '', password: '', role: 'viewer' });
      refresh();
    } catch (x) {
      setErr(t(`err.${(x as Error).message}`));
    }
  };
  return (
    <div className="grid" style={{ maxWidth: 880 }}>
      <Card title={t('users.add')}>
        <form className="row wrap" onSubmit={add} style={{ alignItems: 'flex-end' }}>
          <label className="field"><span>{t('auth.username')}</span><input value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} required /></label>
          <label className="field"><span>{t('auth.password')}</span><input type="password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} minLength={10} required autoComplete="new-password" /></label>
          <label className="field"><span>{t('users.role')}</span>
            <select value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}>
              {['viewer', 'operator', 'admin'].map((r) => <option key={r} value={r}>{t(`role.${r}`)}</option>)}
            </select>
          </label>
          <button className="btn primary">{t('common.add')}</button>
        </form>
        {err && <div className="error" style={{ marginTop: 8 }}>{err}</div>}
        <p className="muted" style={{ fontSize: 12.5, marginBottom: 0 }}>{t('users.roles_help')}</p>
      </Card>
      <Card flush>
        <div className="table-wrap"><table>
          <thead><tr><th>{t('auth.username')}</th><th>{t('users.role')}</th><th>{t('users.last_login')}</th><th /></tr></thead>
          <tbody>
            {(data ?? []).map((u) => (
              <tr key={u.id}>
                <td style={{ fontWeight: 600 }}>{u.username}{u.id === me.id && <span className="muted"> ({t('users.you')})</span>}</td>
                <td>
                  <select value={u.role} onChange={async (e) => { await api(`/users/${u.id}`, { method: 'PATCH', body: { role: e.target.value } }).catch((x) => alert(t(`err.${x.message}`))); refresh(); }}>
                    {['viewer', 'operator', 'admin'].map((r) => <option key={r} value={r}>{t(`role.${r}`)}</option>)}
                  </select>
                </td>
                <td className="muted">{u.last_login ? `${ago(u.last_login)}` : '-'}</td>
                <td className="r">{u.id !== me.id && <button className="btn sm danger" onClick={async () => { if (confirm(t('users.confirm_delete', { name: u.username }))) { await api(`/users/${u.id}`, { method: 'DELETE' }); refresh(); } }}>{t('common.delete')}</button>}</td>
              </tr>
            ))}
          </tbody>
        </table></div>
      </Card>
    </div>
  );
}

function Notify() {
  const t = useT();
  const { data, refresh } = usePoll(() => api<any>('/settings'), 60000);
  const [f, setF] = useState<Record<string, string> | null>(null);
  const [msg, setMsg] = useState('');
  if (!data) return null;
  const v = f ?? data;
  const set = (k: string, val: string) => setF({ ...v, [k]: val });
  const save = async () => {
    await api('/settings', { method: 'PUT', body: v });
    setF(null);
    refresh();
    setMsg(t('common.saved'));
    setTimeout(() => setMsg(''), 2500);
  };
  return (
    <div className="grid" style={{ maxWidth: 680 }}>
      <Card title={t('notify.thresholds')}>
        <div className="grid g3">
          {(['cpu', 'mem', 'disk'] as const).map((k) => (
            <label className="field" key={k}>{k === 'cpu' ? 'CPU %' : k === 'mem' ? t('host.memory') + ' %' : t('host.disk') + ' %'}
              <input type="number" min={1} max={100} placeholder={String(data.defaults[k])} value={v[`threshold.${k}`] ?? ''} onChange={(e) => set(`threshold.${k}`, e.target.value)} />
            </label>
          ))}
        </div>
      </Card>
      <Card title={t('notify.channels')}>
        <div className="grid">
          <label className="field">Webhook URL (Slack, Discord, Teams…)<input value={v['notify.webhook'] ?? ''} onChange={(e) => set('notify.webhook', e.target.value)} placeholder="https://hooks.slack.com/…" /></label>
          <div className="grid g2">
            <label className="field">Telegram bot token<input type="password" value={v['notify.telegram_token'] ?? ''} onChange={(e) => set('notify.telegram_token', e.target.value)} autoComplete="off" /></label>
            <label className="field">Telegram chat ID<input value={v['notify.telegram_chat'] ?? ''} onChange={(e) => set('notify.telegram_chat', e.target.value)} /></label>
          </div>
        </div>
      </Card>
      <div className="row">
        <button className="btn primary" onClick={save}>{t('common.save')}</button>
        <button className="btn" onClick={() => api('/settings/test-notify', { method: 'POST', body: {} })}>{t('notify.test')}</button>
        <span className="muted">{msg}</span>
      </div>
    </div>
  );
}

function Domain() {
  const t = useT();
  const { data, refresh } = usePoll(() => api<any>('/tunnel'), 3000);
  const [token, setToken] = useState('');
  const [host, setHost] = useState<string | null>(null);
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  if (!data) return null;
  const hostname = host ?? data.hostname ?? '';
  const run = async (method: string, body?: unknown) => {
    setErr('');
    setBusy(true);
    try {
      await api('/tunnel', { method, body: body ?? {} });
      setToken('');
      setHost(null);
      refresh();
    } catch (x) {
      setErr(t(`err.${(x as Error).message}`));
    } finally {
      setBusy(false);
    }
  };
  const stateLabel = !data.hasToken ? t('domain.not_configured') : t(`domain.state_${data.state}`);
  const tone = data.state === 'connected' ? 'var(--ok)' : data.state === 'error' ? 'var(--bad, #e5484d)' : 'var(--muted)';
  return (
    <div className="grid" style={{ maxWidth: 680 }}>
      <Card title={t('domain.title')}>
        <p className="muted" style={{ marginTop: 0 }}>{t('domain.intro')}</p>
        {!data.available && <div className="error" role="alert">{t('domain.no_binary')}</div>}
        <div className="row" style={{ gap: 8, margin: '10px 0' }}>
          <span style={{ width: 9, height: 9, borderRadius: 99, background: tone, display: 'inline-block' }} />
          <b>{stateLabel}</b>
          {data.state === 'connected' && data.hostname && <a href={`https://${data.hostname}`} target="_blank" rel="noreferrer">https://{data.hostname}</a>}
        </div>
        <div className="grid">
          <label className="field">{t('domain.token')}
            <input type="password" value={token} onChange={(e) => setToken(e.target.value)} autoComplete="off" spellCheck={false}
              placeholder={data.hasToken ? t('domain.token_saved') : 'eyJhIjoi…'} />
          </label>
          <label className="field">{t('domain.hostname')}
            <input value={hostname} onChange={(e) => setHost(e.target.value)} placeholder="oculyx.example.com" autoComplete="off" spellCheck={false} />
          </label>
        </div>
        {err && <div className="error" role="alert" style={{ marginTop: 8 }}>{err}</div>}
        <div className="row" style={{ marginTop: 12, gap: 8 }}>
          <button className="btn primary" disabled={busy || !data.available || (!token && !data.hasToken)}
            onClick={() => run('PUT', { ...(token ? { token } : {}), hostname, enabled: true })}>
            {data.enabled ? t('domain.save_restart') : t('domain.save_enable')}
          </button>
          {data.enabled && <button className="btn" disabled={busy} onClick={() => run('PUT', { enabled: false })}>{t('domain.disable')}</button>}
          {data.hasToken && <button className="btn danger" disabled={busy} onClick={() => { if (confirm(t('domain.confirm_remove'))) run('DELETE'); }}>{t('domain.remove')}</button>}
        </div>
      </Card>
      <Card title={t('domain.howto')}>
        <ol className="muted" style={{ margin: 0, paddingLeft: 20, lineHeight: 1.7, fontSize: 13.5 }}>
          <li>{t('domain.step1')}</li>
          <li>{t('domain.step2')}</li>
          <li>{t('domain.step3')}</li>
          <li>{t('domain.step4')}</li>
        </ol>
        <p className="muted" style={{ fontSize: 12.5, marginBottom: 0 }}>{t('domain.note')}</p>
      </Card>
      {data.log.length > 0 && (
        <Card title={t('domain.log')}>
          <pre className="mono muted" style={{ margin: 0, fontSize: 11.5, whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 220, overflow: 'auto' }}>{data.log.join('\n')}</pre>
        </Card>
      )}
    </div>
  );
}

function Audit() {
  const t = useT();
  const { data } = usePoll(() => api<any[]>('/audit'), 10000);
  return (
    <Card flush>
      {!data || data.length === 0 ? <Empty>{t('events.none')}</Empty> : (
        <div className="table-wrap"><table>
            <thead><tr><th>{t('events.when')}</th><th>{t('auth.username')}</th><th>{t('audit.action')}</th><th>{t('audit.target')}</th><th>IP</th></tr></thead>
            <tbody>
              {data.map((r) => (
                <tr key={r.id}>
                  <td className="muted num">{clock(r.ts)}</td>
                  <td>{r.user ?? '-'}</td>
                  <td className="mono">{r.action}</td>
                  <td className="muted">{r.target ?? ''}</td>
                  <td className="mono muted">{r.ip}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
      )}
    </Card>
  );
}

function Account() {
  const t = useT();
  const [f, setF] = useState({ current: '', next: '' });
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr('');
    setMsg('');
    try {
      await api('/me/password', { body: f });
      setF({ current: '', next: '' });
      setMsg(t('common.saved'));
    } catch (x) {
      setErr(t(`err.${(x as Error).message}`));
    }
  };
  return (
    <Card title={t('account.change_password')}>
      <form className="grid" onSubmit={submit} style={{ maxWidth: 360 }}>
        <label className="field">{t('account.current')}<input type="password" value={f.current} onChange={(e) => setF({ ...f, current: e.target.value })} autoComplete="current-password" required /></label>
        <label className="field">{t('account.new')}<input type="password" value={f.next} onChange={(e) => setF({ ...f, next: e.target.value })} minLength={10} autoComplete="new-password" required /></label>
        {err && <div className="error">{err}</div>}
        {msg && <div style={{ color: 'var(--ok)' }}>{msg}</div>}
        <div><button className="btn primary">{t('common.save')}</button></div>
      </form>
    </Card>
  );
}
