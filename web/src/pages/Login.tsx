import { useState } from 'react';
import { api, setToken } from '../lib';
import { useT, useI18n, LANGS, type Lang } from '../i18n';
import { Logo } from '../components/ui';
import type { User } from '../App';

export function Login({ onLogin }: { onLogin: (u: User) => void }) {
  const t = useT();
  const { lang, setLang } = useI18n();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      const r = await api<{ token: string; user: User }>('/auth/login', { body: { username, password } });
      setToken(r.token);
      onLogin(r.user);
    } catch (err) {
      setError(t(`err.${(err as Error).message}`));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login">
      <form className="card" onSubmit={submit}>
        <div className="brand">
          <Logo /> oculyx
        </div>
        <div>
          <h1 style={{ fontSize: 19 }}>{t('auth.title')}</h1>
          <p className="muted" style={{ margin: '4px 0 0' }}>
            {t('auth.subtitle')}
          </p>
        </div>
        <label className="field">
          {t('auth.username')}
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus required />
        </label>
        <label className="field">
          {t('auth.password')}
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
        </label>
        {error && <div className="error" role="alert">{error}</div>}
        <button className="btn primary" disabled={busy} style={{ justifyContent: 'center', padding: '9px' }}>
          {t('auth.login')}
        </button>
        <div className="row" style={{ justifyContent: 'center' }}>
          {LANGS.map((l) => (
            <button key={l.code} type="button" className={`btn ghost sm ${lang === l.code ? '' : ''}`} style={lang === l.code ? { color: 'var(--accent)' } : undefined} onClick={() => setLang(l.code as Lang)}>
              {l.label}
            </button>
          ))}
        </div>
      </form>
    </div>
  );
}
