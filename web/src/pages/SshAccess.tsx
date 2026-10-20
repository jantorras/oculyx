import { useState } from 'react';
import { api, usePoll, clock } from '../lib';
import { useT } from '../i18n';
import { Card, Empty } from '../components/ui';
import { TerminalModal } from '../components/Terminal';

/** Per-host SSH: pick a key, put it on the host, test it, open a terminal, and see who else holds a key. */
export function SshAccess({ agentId, name, onGoSecurity }: { agentId: number; name: string; onGoSecurity: () => void }) {
  const t = useT();
  const { data, refresh } = usePoll(() => api<any>(`/agents/${agentId}/ssh`), 8000, [agentId]);
  const { data: keys } = usePoll(() => api<any[]>('/ssh/keys'), 30000);
  const [form, setForm] = useState<{ host: string; port: string; user: string; keyId: string } | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState('');
  const [term, setTerm] = useState(false);
  const [deployUser, setDeployUser] = useState('');

  if (!data) return null;
  const acc = data.access;
  const f = form ?? { host: acc.host ?? '', port: String(acc.port), user: acc.user, keyId: acc.key_id ? String(acc.key_id) : '' };
  const key = (keys ?? []).find((k) => String(k.id) === f.keyId);
  const hostKeys: any[] = data.hostKeys?.keys ?? [];
  const deployed = !!key && hostKeys.some((k) => k.fingerprint === key.fingerprint);
  const tested = !!acc.tested;
  const users: string[] = data.hostKeys?.users ?? [];
  const du = deployUser || (users.includes(f.user) ? f.user : users[0] ?? f.user);

  const run = async (what: string, fn: () => Promise<string | void>) => {
    setBusy(what);
    setMsg(null);
    try {
      const text = await fn();
      setMsg({ ok: true, text: text || t('common.saved') });
      refresh();
    } catch (e) {
      const m = (e as Error).message;
      setMsg({ ok: false, text: t(`err.${m}`) === `err.${m}` ? m : t(`err.${m}`) });
    } finally {
      setBusy('');
    }
  };
  const save = () => run('save', async () => {
    await api(`/agents/${agentId}/ssh`, { method: 'PUT', body: { host: f.host, port: Number(f.port), user: f.user, keyId: f.keyId ? Number(f.keyId) : null } });
    setForm(null);
  });
  const test = () => run('test', async () => {
    if (form) await api(`/agents/${agentId}/ssh`, { method: 'PUT', body: { host: f.host, port: Number(f.port), user: f.user, keyId: f.keyId ? Number(f.keyId) : null } });
    setForm(null);
    const r = await api<any>(`/agents/${agentId}/ssh/test`, { method: 'POST', body: {} }).catch(async (e) => {
      throw new Error(e.message);
    });
    return t('ssh.test_ok', { user: r.user, host: r.hostname });
  });

  const step = (n: number, done: boolean, title: string, body: React.ReactNode) => (
    <div className="row" style={{ gap: 12, alignItems: 'flex-start', padding: '10px 0', borderTop: n > 1 ? '1px solid var(--line)' : 0 }}>
      <span style={{ width: 22, height: 22, borderRadius: 99, display: 'grid', placeItems: 'center', fontSize: 12, fontWeight: 650, flex: 'none', background: done ? 'var(--ok)' : 'var(--surface-2)', color: done ? '#04130d' : 'var(--muted)', border: '1px solid var(--line-strong)' }}>{done ? '✓' : n}</span>
      <div className="grow"><div style={{ fontWeight: 600 }}>{title}</div><div className="muted" style={{ fontSize: 13, marginTop: 2 }}>{body}</div></div>
    </div>
  );

  return (
    <div className="grid" style={{ maxWidth: 960 }}>
      <Card title={t('ssh.connection')}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12, marginBottom: 12, alignItems: 'end' }}>
          <label className="field">{t('ssh.host')}<input value={f.host} onChange={(e) => setForm({ ...f, host: e.target.value })} placeholder="192.168.1.20" spellCheck={false} /></label>
          <label className="field">{t('ssh.port')}<input type="number" min={1} max={65535} value={f.port} onChange={(e) => setForm({ ...f, port: e.target.value })} /></label>
          <label className="field">{t('ssh.user')}<input value={f.user} onChange={(e) => setForm({ ...f, user: e.target.value })} spellCheck={false} /></label>
        </div>
        <label className="field">{t('ssh.key')}
          <select value={f.keyId} onChange={(e) => setForm({ ...f, keyId: e.target.value })}>
            <option value="">{t('ssh.no_key')}</option>
            {(keys ?? []).map((k) => <option key={k.id} value={k.id}>{k.name} · {k.fingerprint.slice(0, 22)}…</option>)}
          </select>
        </label>
        {(keys ?? []).length === 0 && <p className="muted" style={{ fontSize: 13 }}>{t('ssh.no_keys_yet')} <a href="#/settings/sshkeys" style={{ color: 'var(--accent)' }}>{t('ssh.create_key')}</a></p>}
        {acc.hostkey && <p className="muted mono" style={{ fontSize: 11.5, margin: '10px 0 0' }}>{t('ssh.pinned')}: {acc.hostkey} <button className="btn sm" style={{ marginLeft: 8 }} onClick={() => run('reset', async () => { await api(`/agents/${agentId}/ssh`, { method: 'PUT', body: { resetHostKey: true } }); })}>{t('ssh.forget')}</button></p>}
        <div className="row" style={{ gap: 8, marginTop: 12 }}>
          <button className="btn" disabled={!!busy || !form} onClick={save}>{t('common.save')}</button>
          <button className="btn" disabled={!!busy || !f.keyId} onClick={test}>{busy === 'test' ? t('ssh.testing') : t('ssh.test')}</button>
          <button className="btn primary" disabled={!!busy || !f.keyId || !tested || !!form} onClick={() => setTerm(true)}>{t('ssh.open_terminal')}</button>
        </div>
        {msg && <div className={msg.ok ? '' : 'error'} role={msg.ok ? 'status' : 'alert'} style={{ marginTop: 10, color: msg.ok ? 'var(--ok)' : undefined }}>{msg.text}</div>}
      </Card>

      <Card title={t('ssh.steps')}>
        {step(1, !!key, t('ssh.step1'), t('ssh.step1_help'))}
        {step(2, deployed, t('ssh.step2'), data.canHarden ? t('ssh.step2_help') : t('ssh.step2_manual'))}
        {step(3, tested, t('ssh.step3'), t('ssh.step3_help'))}
        {step(4, data.hostKeys?.passwordAuth === 'no', t('ssh.step4'), <>{t('ssh.step4_help')} <button className="btn sm" onClick={onGoSecurity}>{t('ssh.go_security')}</button></>)}
      </Card>

      <Card title={t('ssh.authorized')} flush actions={data.canHarden && key && users.length > 0 ? (
        <div className="row" style={{ gap: 6 }}>
          <select value={du} onChange={(e) => setDeployUser(e.target.value)} aria-label={t('ssh.user')}>{users.map((u) => <option key={u}>{u}</option>)}</select>
          <button className="btn sm primary" disabled={!!busy} onClick={() => run('deploy', async () => { const r = await api<any>(`/agents/${agentId}/ssh/deploy`, { body: { keyId: key.id, user: du } }); return r.steps?.join(' · '); })}>{t('ssh.deploy')}</button>
        </div>
      ) : undefined}>
        {data.hostKeysError ? <Empty>{data.hostKeysError}</Empty> : hostKeys.length === 0 ? <Empty>{t('ssh.no_authorized')}</Empty> : (
          <div className="table-wrap"><table>
            <thead><tr><th>{t('ssh.user')}</th><th>{t('ssh.fingerprint')}</th><th>{t('ssh.comment')}</th><th /></tr></thead>
            <tbody>{hostKeys.map((k, i) => (
              <tr key={i}>
                <td style={{ fontWeight: 600 }}>{k.user}</td>
                <td className="mono muted" style={{ fontSize: 12 }}>{k.fingerprint}{(keys ?? []).some((x) => x.fingerprint === k.fingerprint) && <span className="pill" style={{ marginLeft: 8 }}>{t('ssh.panel_key')}</span>}</td>
                <td className="muted">{k.comment || '-'}</td>
                <td className="r">{data.canHarden && <button className="btn sm danger" disabled={!!busy} onClick={() => confirm(t('ssh.confirm_revoke')) && run('revoke', async () => { await api(`/agents/${agentId}/ssh/revoke`, { body: { user: k.user, fingerprint: k.fingerprint } }); })}>{t('ssh.revoke')}</button>}</td>
              </tr>
            ))}</tbody>
          </table></div>
        )}
      </Card>
      {!data.canHarden && key && (
        <Card title={t('ssh.manual_title')}>
          <p className="muted" style={{ marginTop: 0, fontSize: 13 }}>{t('ssh.manual_help')}</p>
          <pre className="mono" style={{ margin: 0, padding: 10, background: 'var(--surface-2)', borderRadius: 8, fontSize: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{`mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '${key.public}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`}</pre>
        </Card>
      )}
      {acc.tested && <p className="muted" style={{ fontSize: 12 }}>{t('ssh.last_test')}: {clock(acc.tested)}</p>}
      {term && <TerminalModal agentId={agentId} name={name} onClose={() => setTerm(false)} />}
    </div>
  );
}
