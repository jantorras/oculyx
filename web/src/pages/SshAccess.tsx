import { Section } from '../components/overlay';
import { useState } from 'react';
import { api, usePoll, clock } from '../lib';
import { useT } from '../i18n';
import { Empty } from '../components/ui';
import { TerminalModal } from '../components/Terminal';
import { ask } from '../components/overlay';

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

  const saveAccess = (patch: Partial<{ host: string; port: number; user: string; keyId: number | null }>) =>
    api(`/agents/${agentId}/ssh`, { method: 'PUT', body: { host: f.host, port: Number(f.port), user: f.user, keyId: f.keyId ? Number(f.keyId) : null, ...patch } });
  const createKey = () => run('key', async () => {
    const k = await api<any>('/ssh/keys', { body: { name: `panel-${name}`.slice(0, 40) } });
    await saveAccess({ keyId: k.id });
    setForm(null);
  });
  const useKey = (id: string) => run('key', async () => { await saveAccess({ keyId: id ? Number(id) : null }); setForm(null); });
  const lock = (body: { passwords?: boolean; root?: boolean }) => run('lock', async () => {
    await api(`/agents/${agentId}/ssh/lockdown`, { body });
    return t('sshw.done_locked');
  });
  const unlock = () => run('lock', async () => { await api(`/agents/${agentId}/ssh/unlock`, { body: {} }); return t('sshw.done_unlocked'); });

  const hk = data.hostKeys ?? {};
  const pwOff = hk.passwordAuth === 'no';
  const rootMode: string = hk.permitRootLogin ?? '';
  const rootLabel = rootMode === 'no' ? t('sshw.root_no') : rootMode === 'prohibit-password' || rootMode === 'without-password' ? t('sshw.root_key') : t('sshw.root_yes');
  const ready = !!key && deployed && tested;
  const canChange = data.canHarden === true;

  const step = (n: number, done: boolean, title: string, why: string, body: React.ReactNode) => (
    <div className="row" style={{ gap: 14, alignItems: 'flex-start', padding: '14px 0', borderTop: '1px solid var(--line)' }}>
      <span style={{ width: 24, height: 24, borderRadius: 99, display: 'grid', placeItems: 'center', fontSize: 12, fontWeight: 650, flex: 'none', background: done ? 'var(--ok)' : 'var(--surface-2)', color: done ? '#04130d' : 'var(--muted)', border: '1px solid var(--line-strong)' }}>{done ? '✓' : n}</span>
      <div className="grow" style={{ minWidth: 0 }}>
        <div className="sect-title">{title}</div>
        <div className="muted" style={{ fontSize: 13, margin: '3px 0 10px', maxWidth: '70ch' }}>{why}</div>
        {body}
      </div>
    </div>
  );

  return (
    <div className="grid">
      <Section title={t('sshw.title')}>
        <p className="muted" style={{ marginTop: 0, fontSize: 13.5 }}>{t('sshw.intro')}</p>
        {!canChange && <div className="warn" style={{ marginBottom: 8 }}>{t('sshw.readonly')}</div>}
        <div className="grid g2" style={{ alignItems: 'start' }}>
        {step(1, !!key, t('sshw.s1'), t('sshw.s1_why'), key ? <span className="pill">{t('sshw.s1_done', { name: key.name })}</span> : (
          <div className="row wrap" style={{ gap: 8 }}>
            <button className="btn primary" disabled={!!busy || !f.host} onClick={createKey}>{t('sshw.s1_btn_create')}</button>
            {(keys ?? []).length > 0 && (
              <select value="" onChange={(e) => e.target.value && useKey(e.target.value)} aria-label={t('sshw.s1_btn_use')}>
                <option value="">{t('sshw.s1_btn_use')}…</option>
                {(keys ?? []).map((k) => <option key={k.id} value={k.id}>{k.name}</option>)}
              </select>
            )}
            {!f.host && <span className="muted" style={{ fontSize: 12.5 }}>{t('ssh.host')}: {t('sshw.advanced')} ↓</span>}
          </div>
        ))}
        {step(2, deployed, t('sshw.s2'), t('sshw.s2_why'), deployed ? <span className="pill">{t('sshw.s2_done', { user: hostKeys.find((k) => k.fingerprint === key?.fingerprint)?.user ?? du })}</span> : (
          <div className="row wrap" style={{ gap: 8, alignItems: 'center' }}>
            <select value={du} onChange={(e) => setDeployUser(e.target.value)} aria-label={t('sshw.s2_account')}>{users.map((u) => <option key={u}>{u}</option>)}</select>
            <button className="btn primary" disabled={!key || !canChange || !!busy} onClick={() => run('deploy', async () => { await saveAccess({ user: du }); setForm(null); const r = await api<any>(`/agents/${agentId}/ssh/deploy`, { body: { keyId: key.id, user: du } }); return r.steps?.join(' · '); })}>{t('sshw.s2_btn')}</button>
          </div>
        ))}
        {step(3, tested, t('sshw.s3'), t('sshw.s3_why'), (
          <div className="row wrap" style={{ gap: 8, alignItems: 'center' }}>
            <button className={tested ? 'btn' : 'btn primary'} disabled={!key || !deployed || !!busy} onClick={test}>{busy === 'test' ? t('ssh.testing') : tested ? t('ssh.test') : t('sshw.s3_btn')}</button>
            {tested && <span className="pill">{t('sshw.s3_done')}</span>}
            <button className="btn" disabled={!ready || !!busy} onClick={() => setTerm(true)}>{t('ssh.open_terminal')}</button>
          </div>
        ))}
        {step(4, pwOff, t('sshw.s4'), t('sshw.s4_why'), (
          <div className="grid" style={{ gap: 10 }}>
            <div className="row wrap" style={{ gap: 8, alignItems: 'center' }}>
              <span className="pill" style={{ color: pwOff ? 'var(--ok)' : undefined }}>{pwOff ? t('sshw.pw_off') : t('sshw.pw_on')}</span>
              {pwOff
                ? <button className="btn" disabled={!canChange || !!busy} onClick={() => void ask({ title: t('sshw.pw_btn_on'), confirm: t('sshw.pw_btn_on') }).then(async (ok) => { if (ok) await unlock(); })}>{t('sshw.pw_btn_on')}</button>
                : <button className="btn primary" disabled={!ready || !canChange || !!busy} onClick={() => lock({ passwords: true, root: rootMode === 'yes' })}>{busy === 'lock' ? t('sshw.working') : t('sshw.pw_btn_off')}</button>}
              {!ready && !pwOff && <span className="muted" style={{ fontSize: 12.5 }}>{t('sshw.need_steps')}</span>}
            </div>
            <div className="muted" style={{ fontSize: 12.5 }}>{t('sshw.s4_safety')}</div>
            <div className="row wrap" style={{ gap: 8, alignItems: 'center' }}>
              <span className="muted" style={{ fontSize: 13 }}>{t('sshw.root_label')}: <b>{rootLabel}</b></span>
              {rootMode === 'yes' && <button className="btn sm" disabled={!ready || !canChange || !!busy} onClick={() => lock({ root: true })}>{t('sshw.root_btn')}</button>}
            </div>
            <div className="muted" style={{ fontSize: 12.5 }}>{t('sshw.root_why')}</div>
          </div>
        ))}
        </div>
        {pwOff && <div role="status" style={{ color: 'var(--ok)', marginTop: 6 }}>{t('sshw.locked')}</div>}
        {msg && <div className={msg.ok ? '' : 'error'} role={msg.ok ? 'status' : 'alert'} style={{ marginTop: 10, color: msg.ok ? 'var(--ok)' : undefined }}>{msg.text}</div>}
      </Section>

      <details open={!acc.host}>
        <summary className="muted" style={{ cursor: 'pointer', marginBottom: 10 }}>{t('sshw.advanced')}</summary>
        <Section title={t('ssh.connection')}>
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
          {acc.hostkey && <p className="muted mono" style={{ fontSize: 11.5, margin: '10px 0 0' }}>{t('ssh.pinned')}: {acc.hostkey} <button className="btn sm" style={{ marginLeft: 8 }} onClick={() => run('reset', async () => { await api(`/agents/${agentId}/ssh`, { method: 'PUT', body: { resetHostKey: true } }); })}>{t('ssh.forget')}</button></p>}
          <div className="row" style={{ gap: 8, marginTop: 12 }}>
            <button className="btn primary" disabled={!!busy || !form} onClick={save}>{t('common.save')}</button>
          </div>
        </Section>
      </details>

      <Section title={t('ssh.authorized')} flush actions={data.canHarden && key && users.length > 0 ? (
        <div className="row" style={{ gap: 6 }}>
          <select value={du} onChange={(e) => setDeployUser(e.target.value)} aria-label={t('ssh.user')}>{users.map((u) => <option key={u}>{u}</option>)}</select>
          <button className="btn sm primary" disabled={!!busy} onClick={() => run('deploy', async () => { const r = await api<any>(`/agents/${agentId}/ssh/deploy`, { body: { keyId: key.id, user: du } }); return r.steps?.join(' · '); })}>{t('ssh.deploy')}</button>
        </div>
      ) : undefined}>
        {data.hostKeysError ? <Empty>{data.hostKeysError}</Empty> : hostKeys.length === 0 ? <Empty>{t('ssh.no_authorized')}</Empty> : (
          <div className="table-wrap"><table className="tbl-dense">
            <thead><tr><th>{t('ssh.user')}</th><th>{t('ssh.fingerprint')}</th><th>{t('ssh.comment')}</th><th /></tr></thead>
            <tbody>{hostKeys.map((k, i) => (
              <tr key={i}>
                <td style={{ fontWeight: 600 }}>{k.user}</td>
                <td className="mono muted" style={{ fontSize: 12 }}>{k.fingerprint}{(keys ?? []).some((x) => x.fingerprint === k.fingerprint) && <span className="pill" style={{ marginLeft: 8 }}>{t('ssh.panel_key')}</span>}</td>
                <td className="muted">{k.comment || '-'}</td>
                <td className="r">{data.canHarden && <button className="btn sm danger" disabled={!!busy} onClick={() => void ask({ title: t('ssh.revoke'), body: t('ssh.confirm_revoke'), confirm: t('ssh.revoke'), danger: true }).then(async (ok) => { if (ok) await run('revoke', async () => { await api(`/agents/${agentId}/ssh/revoke`, { body: { user: k.user, fingerprint: k.fingerprint } }); }); })}>{t('ssh.revoke')}</button>}</td>
              </tr>
            ))}</tbody>
          </table></div>
        )}
      </Section>
      {!data.canHarden && key && (
        <Section title={t('ssh.manual_title')}>
          <p className="muted" style={{ marginTop: 0, fontSize: 13 }}>{t('ssh.manual_help')}</p>
          <pre className="mono" style={{ margin: 0, padding: 10, background: 'var(--surface-2)', borderRadius: 8, fontSize: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{`mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '${key.public}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys`}</pre>
        </Section>
      )}
      {acc.tested && <p className="muted" style={{ fontSize: 12 }}>{t('ssh.last_test')}: {clock(acc.tested)}</p>}
      {term && <TerminalModal agentId={agentId} name={name} onClose={() => setTerm(false)} />}
    </div>
  );
}
