import { Section } from '../components/overlay';
import { useState } from 'react';
import { api, usePoll } from '../lib';
import { useT } from '../i18n';

import { toast } from '../components/overlay';

/** Settings, AI: provider, budget and where the assistant is used. The API key is write-only. */
export function AiSettings() {
  const t = useT();
  const { data, refresh } = usePoll(() => api<any>('/ai/settings'), 30000);
  const [f, setF] = useState<Record<string, any>>({});
  const [key, setKey] = useState('');
  const [busy, setBusy] = useState('');
  const [testMsg, setTestMsg] = useState<{ ok: boolean; text: string } | null>(null);
  if (!data) return null;

  const v = (k: string) => (k in f ? f[k] : data[k]);
  const set = (k: string, val: unknown) => setF({ ...f, [k]: val });
  const prov: 'anthropic' | 'openai' | 'ollama' = v('provider');
  const def = data.defaults[prov];
  const dirty = Object.keys(f).length > 0 || !!key;

  const save = async () => {
    setBusy('save');
    try {
      await api('/ai/settings', { method: 'PUT', body: { ...f, ...(key ? { apiKey: key } : {}) } });
      setF({});
      setKey('');
      refresh();
      toast(t('common.saved'));
    } catch (e: any) {
      toast(e.message, 'error');
    } finally {
      setBusy('');
    }
  };
  const test = async () => {
    if (dirty) await save();
    setBusy('test');
    setTestMsg(null);
    try {
      const r = await api<any>('/ai/test', { body: {} });
      setTestMsg({ ok: true, text: r.reply });
      refresh();
    } catch (e: any) {
      setTestMsg({ ok: false, text: e.detail || e.message });
    } finally {
      setBusy('');
    }
  };
  const digestNow = async () => {
    setBusy('digest');
    try {
      await api('/ai/digest', { body: {} });
      toast(t('aiset.digest_sent'));
    } catch (e: any) {
      toast(e.detail || e.message, 'error');
    } finally {
      setBusy('');
    }
  };

  const u = data.usage;
  const cap = Number(v('capMonth')) || null;
  const pct = cap ? Math.min(100, (u.cost / cap) * 100) : 0;
  const needsKey = prov !== 'ollama';
  const toggle = (k: string, label: string, hint?: string, off?: boolean) => (
    <label className="optrow">
      <span className="grow"><b>{label}</b>{hint && <span className="muted small" style={{ display: 'block' }}>{hint}</span>}</span>
      <button type="button" className={`toggle ${v(k) ? 'on' : ''}`} role="switch" aria-checked={!!v(k)} disabled={off} onClick={() => set(k, !v(k))}><i /></button>
    </label>
  );

  return (
    <div className="grid g2">
      <Section title={t('aiset.provider')}>
        <div className="grid" style={{ gap: 14 }}>
          {toggle('enabled', t('aiset.enable'), t('aiset.enable_hint'))}
          <div className="grid g2">
            <label className="field">{t('aiset.provider_label')}
              <select value={prov} onChange={(e) => setF({ ...f, provider: e.target.value, model: '', baseUrl: '', priceIn: '', priceOut: '' })}>
                <option value="anthropic">Claude (Anthropic)</option>
                <option value="openai">OpenAI / compatible (OpenRouter, Groq, Gemini…)</option>
                <option value="ollama">Ollama (local)</option>
              </select>
            </label>
            <label className="field">{t('aiset.model')}
              <input value={v('model') === def.model && !('model' in f) ? '' : v('model')} placeholder={def.model} onChange={(e) => set('model', e.target.value)} spellCheck={false} />
            </label>
          </div>
          {prov !== 'anthropic' && (
            <label className="field">{t('aiset.base_url')}
              <input value={v('baseUrl') === def.baseUrl && !('baseUrl' in f) ? '' : v('baseUrl')} placeholder={def.baseUrl} onChange={(e) => set('baseUrl', e.target.value)} spellCheck={false} />
            </label>
          )}
          {needsKey && (
            <label className="field">{t('aiset.key')}
              <input type="password" value={key} onChange={(e) => setKey(e.target.value)} autoComplete="off" placeholder={data.hasKey ? t('aiset.key_saved') : 'sk-…'} />
              {data.hasKey && <button type="button" className="btn sm" style={{ justifySelf: 'start', marginTop: 6 }} onClick={async () => { await api('/ai/settings', { method: 'PUT', body: { clearKey: true } }); refresh(); }}>{t('aiset.key_remove')}</button>}
            </label>
          )}
          <div className="row wrap" style={{ gap: 10 }}>
            <button className="btn" disabled={!!busy} onClick={test}>{busy === 'test' ? t('sshw.working') : t('aiset.test')}</button>
            {testMsg && <span className={testMsg.ok ? 'muted' : 'error'} role={testMsg.ok ? 'status' : 'alert'}>{testMsg.ok ? `${t('aiset.works')}: ${testMsg.text}` : testMsg.text}</span>}
          </div>
        </div>
      </Section>

      <Section title={t('aiset.cost')}>
        <p className="muted small" style={{ marginTop: 0 }}>{t('aiset.cost_help')}</p>
        <div className="grid g3">
          <label className="field">{t('aiset.price_in')}<input type="number" min={0} step="0.01" value={v('priceIn')} onChange={(e) => set('priceIn', e.target.value)} /></label>
          <label className="field">{t('aiset.price_out')}<input type="number" min={0} step="0.01" value={v('priceOut')} onChange={(e) => set('priceOut', e.target.value)} /></label>
          <label className="field">{t('aiset.cap')}<input type="number" min={0} step="0.5" value={v('capMonth') ?? ''} placeholder={t('aiset.no_cap')} onChange={(e) => set('capMonth', e.target.value)} /></label>
        </div>
        <div style={{ marginTop: 16 }}>
          <div className="row spread small"><span>{t('aiset.this_month')}</span><span className="num">{u.cost.toFixed(3)}{cap ? ` / ${cap}` : ''}  ·  {u.calls} {t('aiset.calls')}  ·  {Math.round((u.inTokens + u.outTokens) / 1000)}k tokens</span></div>
          {cap && <div className="bar" style={{ marginTop: 6 }}><i style={{ width: `${pct}%`, background: pct > 85 ? 'var(--bad)' : 'var(--accent)' }} /></div>}
        </div>
      </Section>

      <Section title={t('aiset.where')} fullWidth>
        <div className="grid g2" style={{ gap: 12 }}>
          {toggle('alerts', t('aiset.alerts'), t('aiset.alerts_hint'))}
          <label className="field">{t('aiset.alert_min')}
            <select value={v('alertMinSeverity')} onChange={(e) => set('alertMinSeverity', e.target.value)}>
              {['critical', 'high', 'medium'].map((s) => <option key={s} value={s}>{t(`sev.${s}`)}</option>)}
            </select>
          </label>
          {toggle('telegram', t('aiset.telegram'), data.telegramConfigured ? t('aiset.telegram_hint') : t('aiset.telegram_need'), !data.telegramConfigured)}
          <div className="row wrap" style={{ gap: 10, alignItems: 'end' }}>
            <label className="field">{t('aiset.digest')}
              <select value={v('digestHour') ?? ''} onChange={(e) => set('digestHour', e.target.value)}>
                <option value="">{t('aiset.digest_off')}</option>
                {Array.from({ length: 24 }, (_, h) => <option key={h} value={h}>{String(h).padStart(2, '0')}:00</option>)}
              </select>
            </label>
            <button className="btn" disabled={!!busy} onClick={digestNow}>{t('aiset.digest_now')}</button>
          </div>
          <label className="field">{t('aiset.language')}
            <select value={v('language')} onChange={(e) => set('language', e.target.value)}>
              <option value="ca">Català</option><option value="es">Español</option><option value="en">English</option>
            </select>
          </label>
        </div>
      </Section>

      <div className="notice" style={{ gridColumn: '1 / -1' }}>{t('aiset.privacy')}</div>
      <div className="row" style={{ gridColumn: '1 / -1' }}><button className="btn primary" disabled={!dirty || !!busy} onClick={save}>{t('common.save')}</button></div>
    </div>
  );
}
