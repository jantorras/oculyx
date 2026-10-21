import { useState } from 'react';
import { api, setToken } from '../lib';
import { useT, useI18n, LANGS, type Lang } from '../i18n';
import { Icon, Logo } from '../components/ui';
import type { User } from '../App';

export function Login({ onLogin }: { onLogin: (u: User) => void }) {
  const t = useT();
  const { lang, setLang } = useI18n();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

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
    <main className="login">
      <aside className="login-brand-panel" aria-label="Oculyx">
        <div className="login-brand-content">
          <div className="brand"><Logo /> oculyx</div>
          <p className="login-tagline">{t('auth.subtitle')}</p>
          <ul className="login-features">
            <li>{Icon.overview}<span>{t('auth.feature_monitoring')}</span></li>
            <li>{Icon.shield}<span>{t('auth.feature_security')}</span></li>
            <li>{Icon.docker}<span>{t('auth.feature_docker')}</span></li>
          </ul>
        </div>
      </aside>
      <section className="login-form-panel" aria-labelledby="login-title">
        <form className="card login-card" onSubmit={submit} aria-busy={busy}>
          <div className="brand login-mobile-brand"><Logo /> oculyx</div>
          <div className="login-heading">
            <h1 id="login-title">{t('auth.title')}</h1>
            <p>{t('auth.signin_hint')}</p>
          </div>
          <label className="field" htmlFor="login-username">
            {t('auth.username')}
            <input id="login-username" name="username" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" autoFocus required />
          </label>
          <div className="login-password-field">
            <label htmlFor="login-password">{t('auth.password')}</label>
            <div className="login-password-control">
              <input id="login-password" name="password" type={showPassword ? 'text' : 'password'} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
              <button type="button" className="login-password-toggle" aria-label={t(showPassword ? 'auth.hide_password' : 'auth.show_password')} aria-controls="login-password" onClick={() => setShowPassword((shown) => !shown)}>
                {t(showPassword ? 'auth.hide' : 'auth.show')}
              </button>
            </div>
          </div>
          <div className={`login-error${error ? ' has-error' : ''}`} role="alert">{error}</div>
          <button type="submit" className="btn primary login-submit" disabled={busy}>
            {busy ? t('auth.signing_in') : t('auth.login')}
          </button>
          <div className="login-languages" role="group" aria-label={t('common.language')}>
            {LANGS.map((l) => (
              <button key={l.code} type="button" lang={l.code} className="btn ghost sm" aria-pressed={lang === l.code} onClick={() => setLang(l.code as Lang)}>
                {l.label}
              </button>
            ))}
          </div>
        </form>
      </section>
    </main>
  );
}
