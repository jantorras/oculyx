import { useState } from 'react';
import { api, usePoll, clock } from '../lib';
import { useT } from '../i18n';
import { Card, Icon } from '../components/ui';

const NAME_RE = /^[A-Za-z0-9._-]{0,60}$/;

interface Fresh {
  token: string;
  expires: number;
  label: string;
  allow: boolean;
  docker: boolean;
  native: boolean;
  os: 'linux' | 'windows';
}

function copyText(text: string): Promise<void> {
  if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
  // plain-http LAN installs have no async clipboard API
  return new Promise((resolve) => {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
    resolve();
  });
}

export function AddHost() {
  const t = useT();
  const { data: settings, refresh: refreshSettings } = usePoll(() => api<any>('/settings'), 60000);
  const { data: tokens, refresh: refreshTokens } = usePoll(() => api<any[]>('/enroll'), 10000);
  const [label, setLabel] = useState('');
  const [allow, setAllow] = useState(false);
  const [docker, setDocker] = useState(true);
  const [native, setNative] = useState(false);
  const [os, setOs] = useState<'linux' | 'windows'>('linux');
  const [fresh, setFresh] = useState<Fresh | null>(null);
  const [tab, setTab] = useState<'one' | 'inspect'>('one');
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState('');
  const [editUrl, setEditUrl] = useState<string | null>(null);

  const { data: status } = usePoll(() => (fresh ? api<any>(`/enroll/${fresh.token}/status`) : Promise.resolve(null)), 2000, [fresh?.token]);

  const base = ((settings?.['server.public_url'] as string) || location.origin).replace(/\/+$/, '');
  let host = '';
  try {
    host = new URL(base).hostname;
  } catch {
    /* ignore */
  }
  const isLocal = /^(localhost|127\.|\[?::1\]?$)/.test(host);

  const nameBad = !NAME_RE.test(label);
  async function generate(e: React.FormEvent) {
    e.preventDefault();
    if (nameBad) return;
    setError('');
    try {
      const r = await api<{ token: string; expires: number }>('/enroll', { body: { label } });
      setFresh({ token: r.token, expires: r.expires, label, allow, docker: docker && !native && os === 'linux', native: native && os === 'linux', os });
      setTab('one');
    } catch (err) {
      setError(t(`err.${(err as Error).message}`));
    }
  }

  const flags = (f: Fresh) => `--token ${f.token}${f.label ? ` --name ${f.label}` : ''}${f.native ? ' --native' : ''}${f.allow ? ' --allow-actions' : ''}${f.docker ? ' --install-docker' : ''}`;
  const winArgs = (f: Fresh) => `-Token '${f.token}'${f.label ? ` -Name '${f.label}'` : ''}${f.allow ? ' -AllowActions' : ''}`;
  const oneLiner = (f: Fresh) =>
    f.os === 'windows'
      ? `[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; & ([scriptblock]::Create((irm '${base}/install.ps1'))) ${winArgs(f)}`
      : `curl -fsSL ${base}/install.sh | $(command -v sudo) bash -s -- ${flags(f)}`;
  const inspect = (f: Fresh) => f.os === 'windows'
    ? `irm '${base}/install.ps1' -OutFile oculyx-install.ps1\nnotepad oculyx-install.ps1      # read it first\npowershell -ExecutionPolicy Bypass -File .\\oculyx-install.ps1 ${winArgs(f)}`
    : `curl -fsSLo oculyx-install.sh ${base}/install.sh\nless oculyx-install.sh      # read it first (press q to quit)\n$(command -v sudo) bash oculyx-install.sh ${flags(f)}`;

  const connected = status?.state === 'enrolled' && status.agent?.hasData;
  const expired = status?.state === 'expired';
  const stage = !fresh ? 1 : connected ? 3 : 2;

  async function saveUrl() {
    await api('/settings', { method: 'PUT', body: { 'server.public_url': (editUrl ?? '').trim() } });
    setEditUrl(null);
    refreshSettings();
  }
  async function copy(text: string) {
    await copyText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }
  function reset() {
    setFresh(null);
    setLabel('');
    refreshTokens();
  }

  const pending = (tokens ?? []).filter((x) => x.used_by == null && (!x.expires || x.expires > Date.now()));

  return (
    <div className="wizard">
      <ol className="stepper" aria-label={t('add.title')}>
        {[t('add.step1'), t('add.step2'), t('add.step3')].map((s, i) => (
          <li key={s} className={stage === i + 1 ? 'on' : stage > i + 1 ? 'done' : ''} aria-current={stage === i + 1 ? 'step' : undefined}>
            <span className="n">{stage > i + 1 ? Icon.check : i + 1}</span>
            {s}
          </li>
        ))}
      </ol>

      {/* server address used inside the generated commands */}
      <div className={`addr ${isLocal ? 'warn' : ''}`}>
        <span className="muted">{t('add.server_addr')}</span>
        {editUrl == null ? (
          <>
            <code>{base}</code>
            <button className="btn sm ghost" onClick={() => setEditUrl(base)}>{t('add.edit')}</button>
          </>
        ) : (
          <>
            <input name="public_url" autoComplete="off" spellCheck={false} value={editUrl} onChange={(e) => setEditUrl(e.target.value)} placeholder="https://oculyx.example.com…" aria-label={t('add.server_addr')} />
            <button className="btn sm primary" onClick={saveUrl}>{t('common.save')}</button>
            <button className="btn sm ghost" onClick={() => setEditUrl(null)}>{t('common.close')}</button>
          </>
        )}
      </div>
      {isLocal && <div className="banner warn" role="status">{t('add.local_warn', { url: base })}</div>}

      {stage === 1 && (
        <Card title={t('add.step1')}>
          <p className="muted" style={{ marginTop: 0 }}>{t('add.intro')}</p>
          <form className="grid" onSubmit={generate} style={{ maxWidth: 560 }}>
            <label className="field">
              {t('add.name')}
              <input name="label" autoComplete="off" spellCheck={false} placeholder={t('add.name_ph')} value={label} onChange={(e) => setLabel(e.target.value)} aria-invalid={nameBad} aria-describedby="name-help" />
              <span id="name-help" className={nameBad ? 'error' : 'muted'} style={{ fontSize: 12 }}>{nameBad ? t('add.name_bad') : t('add.name_help')}</span>
            </label>
            <fieldset className="modes">
              <legend>{t('add.os')}</legend>
              <label className={`mode ${os === 'linux' ? 'on' : ''}`}>
                <input type="radio" name="os" checked={os === 'linux'} onChange={() => setOs('linux')} />
                <span><b>Linux</b><small>{t('add.os_linux_help')}</small></span>
              </label>
              <label className={`mode ${os === 'windows' ? 'on' : ''}`}>
                <input type="radio" name="os" checked={os === 'windows'} onChange={() => setOs('windows')} />
                <span><b>Windows</b><small>{t('add.os_windows_help')}</small></span>
              </label>
            </fieldset>
            {os === 'linux' && (
            <fieldset className="modes">
              <legend>{t('add.mode')}</legend>
              <label className={`mode ${!native ? 'on' : ''}`}>
                <input type="radio" name="mode" checked={!native} onChange={() => setNative(false)} />
                <span><b>{t('add.mode_docker')}</b><small>{t('add.mode_docker_help')}</small></span>
              </label>
              <label className={`mode ${native ? 'on' : ''}`}>
                <input type="radio" name="mode" checked={native} onChange={() => setNative(true)} />
                <span><b>{t('add.mode_native')}</b><small>{t('add.mode_native_help')}</small></span>
              </label>
            </fieldset>
            )}
            {os === 'linux' && !native && (
              <label className="check">
                <input type="checkbox" checked={docker} onChange={(e) => setDocker(e.target.checked)} />
                <span><b>{t('add.docker')}</b><small>{t('add.docker_help')}</small></span>
              </label>
            )}
            <label className="check">
              <input type="checkbox" checked={allow} onChange={(e) => setAllow(e.target.checked)} />
              <span><b>{t('add.allow')}</b><small>{t('add.allow_help')}</small></span>
            </label>
            {error && <div className="error" role="alert">{error}</div>}
            <div><button className="btn primary" disabled={nameBad}>{t('add.generate')} {Icon.arrow}</button></div>
          </form>
        </Card>
      )}

      {stage === 2 && fresh && (
        <Card title={t('add.run_title')} actions={<span className="muted" style={{ fontSize: 12.5 }}>{t('add.expires', { time: clock(fresh.expires) })}</span>}>
          <p className="muted" style={{ marginTop: 0 }}>{fresh.os === 'windows' ? t('add.win_run_help') : `${t('add.run_help')} ${t('add.sudo_note')}`}</p>
          <div className="seg" role="tablist" style={{ marginBottom: 12 }}>
            <button role="tab" aria-selected={tab === 'one'} className={tab === 'one' ? 'active' : ''} onClick={() => setTab('one')}>{t('add.tab_one')}</button>
            <button role="tab" aria-selected={tab === 'inspect'} className={tab === 'inspect' ? 'active' : ''} onClick={() => setTab('inspect')}>{t('add.tab_inspect')}</button>
          </div>
          {tab === 'inspect' && <p className="muted" style={{ margin: '0 0 10px', fontSize: 13 }}>{t('add.inspect_help')}</p>}
          <div className="cmd">
            <pre className="codebox" tabIndex={0}>{tab === 'one' ? oneLiner(fresh) : inspect(fresh)}</pre>
            <button className="btn copy" onClick={() => copy(tab === 'one' ? oneLiner(fresh) : inspect(fresh))}>
              {copied ? Icon.check : Icon.doc}
              <span aria-live="polite">{copied ? t('common.copied') : t('common.copy')}</span>
            </button>
          </div>

          <div className="waiting" aria-live="polite">
            {expired ? (
              <div className="banner warn">{t('add.expired')} <button className="btn sm" onClick={reset}>{t('add.regenerate')}</button></div>
            ) : (
              <>
                <div className="row" style={{ gap: 10 }}>
                  <span className="pulse" aria-hidden />
                  <b>{t('add.waiting')}</b>
                </div>
                <ul className="progress">
                  <li className="done">{Icon.check}{t('add.s_token')}</li>
                  <li className={status?.state === 'enrolled' ? 'done' : 'active'}>{status?.state === 'enrolled' ? Icon.check : <i className="dotp" />}{t('add.s_contact')}</li>
                  <li className={connected ? 'done' : status?.state === 'enrolled' ? 'active' : ''}>{connected ? Icon.check : <i className="dotp" />}{t('add.s_data')}</li>
                </ul>
              </>
            )}
          </div>
          <details className="tips">
            <summary>{t('add.tips')}</summary>
            <ul>
              <li>{t('add.tip_update')}</li>
              <li>{t('add.tip_remove')}</li>
              <li>{t('add.tip_firewall', { url: base })}</li>
            </ul>
          </details>
          <div style={{ marginTop: 14 }}><button className="btn ghost sm" onClick={reset}>{t('add.regenerate')}</button></div>
        </Card>
      )}

      {stage === 3 && status?.agent && (
        <section className="card quiet" role="status">
          <span className="quiet-ico">{Icon.check}</span>
          <h2>{t('add.done_title', { name: status.agent.name })}</h2>
          <p className="muted">{status.agent.info?.os} · {t('add.done_body')}</p>
          <div className="row" style={{ justifyContent: 'center', flexWrap: 'wrap' }}>
            <a className="btn primary" href={`#/hosts/${status.agent.id}`}>{t('add.open_host')} {Icon.arrow}</a>
            <button className="btn" onClick={reset}>{t('add.add_another')}</button>
          </div>
        </section>
      )}

      {pending.length > 0 && (
        <details className="pending">
          <summary>{t('add.pending')} ({pending.length})</summary>
          <ul>
            {pending.map((x) => (
              <li key={x.token}>
                <span className="grow"><b>{x.label}</b> <span className="muted mono">{x.token.slice(0, 8)}…</span></span>
                <span className="muted" style={{ fontSize: 12 }}>{x.expires ? clock(x.expires) : ''}</span>
                <button className="btn sm danger" onClick={async () => { await api(`/enroll/${x.token}`, { method: 'DELETE' }); refreshTokens(); }}>{t('add.revoke')}</button>
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}
