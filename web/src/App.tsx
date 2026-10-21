import { createContext, useContext, useEffect, useState, type ReactNode } from 'react';
import { api, getToken, setToken, useRoute, useTheme, usePoll } from './lib';
import { useI18n, LANGS, useT, type Lang } from './i18n';
import { Icon, Logo } from './components/ui';
import { Login } from './pages/Login';
import { Overview } from './pages/Overview';
import { HostDetail } from './pages/HostDetail';
import { Containers } from './pages/Containers';
import { Security } from './pages/Security';
import { Alerts } from './pages/Alerts';
import { Events } from './pages/Events';
import { Settings } from './pages/Settings';
import { Servers } from './pages/Servers';
import { Overlays } from './components/overlay';
import { Assistant } from './pages/Assistant';
import { Policies } from './pages/Policies';
import { Checks } from './pages/Checks';

export interface User {
  id: number;
  username: string;
  role: 'admin' | 'operator' | 'viewer';
  lang: string;
}
const UserCtx = createContext<User>(null as unknown as User);
export const useUser = () => useContext(UserCtx);
export const canOperate = (u: User) => u.role !== 'viewer';

export function App() {
  const [user, setUser] = useState<User | null>(null);
  const [checking, setChecking] = useState(!!getToken());
  const { setLang } = useI18n();

  useEffect(() => {
    if (!getToken()) return;
    api<User>('/me')
      .then((u) => {
        setUser(u);
        if (['en', 'es', 'ca'].includes(u.lang) && !localStorage.getItem('oculyx.lang')) setLang(u.lang as Lang);
      })
      .catch(() => setToken(null))
      .finally(() => setChecking(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (checking) return null;
  if (!user) return <Login onLogin={setUser} />;
  return (
    <UserCtx.Provider value={user}>
      <Shell
        onLogout={() => {
          setToken(null);
          setUser(null);
        }}
      />
    </UserCtx.Provider>
  );
}

function Shell({ onLogout }: { onLogout: () => void }) {
  const [fullRoute] = useRoute();
  const route = fullRoute.split('?')[0];
  const { lang, setLang } = useI18n();
  const t = useT();
  const user = useUser();
  const [theme, toggleTheme] = useTheme();
  const [open, setOpen] = useState(false);
  const { data: openAlerts } = usePoll(() => api<any[]>('/alerts?state=open'), 10000);

  useEffect(() => setOpen(false), [route]);

  const nav: [string, string, ReactNode, boolean?][] = [
    ['/', 'nav.overview', Icon.overview],
    ['/servers', 'nav.servers', Icon.overview],
    ['/containers', 'nav.containers', Icon.docker],
    ['/security', 'nav.security', Icon.shield],
    ['/assistant', 'nav.assistant', Icon.chat],
    ['/alerts', 'nav.alerts', Icon.bell],
    ['/checks', 'nav.checks', Icon.shield],
    ['/policies', 'nav.policies', Icon.sliders],
    ['/events', 'nav.events', Icon.log],
    ['/settings', 'nav.settings', Icon.gear],
  ];

  const active = (p: string) => (p === '/' ? route === '/' || route.startsWith('/hosts') : route.startsWith(p));
  const pickLang = (l: Lang) => {
    setLang(l);
    void api('/me', { method: 'PATCH', body: { lang: l } }).catch(() => {});
  };

  let page: ReactNode;
  if (route.startsWith('/hosts/')) page = <HostDetail id={Number(route.split('/')[2])} tab={route.split('/')[3]} />;
  else if (route === '/servers') page = <Servers />;
  else if (route === '/containers') page = <Containers />;
  else if (route === '/security') page = <Security />;
  else if (route === '/assistant') page = <Assistant />;
  else if (route === '/alerts') page = <Alerts />;
  else if (route === '/policies') page = <Policies />;
  else if (route === '/checks') page = <Checks />;
  else if (route === '/events') page = <Events />;
  else if (route.startsWith('/settings')) page = <Settings tab={route.split('/')[2]} />;
  else page = <Overview />;

  return (
    <div className="app">
      <a className="skip" href="#main" onClick={(e) => { e.preventDefault(); document.getElementById('main')?.focus(); }}>{t('common.skip')}</a>
      <aside className={`side ${open ? 'open' : ''}`}>
        <div className="brand">
          <Logo /> oculyx
        </div>
        {user.role === 'admin' && (
          <a className="btn primary side-add" href="#/settings/enroll">
            + {t('add.cta')}
          </a>
        )}
        <nav className="nav">
          {nav.map(([to, key, icon]) => (
            <a key={to} href={`#${to}`} className={active(to) ? 'active' : ''}>
              {icon}
              {t(key)}
              {to === '/alerts' && openAlerts && openAlerts.length > 0 && <span className="count">{openAlerts.length}</span>}
            </a>
          ))}
        </nav>
        <div className="foot">
          <div className="row spread">
            <div style={{ minWidth: 0 }}>
              <div style={{ fontWeight: 600 }}>{user.username}</div>
              <div className="muted" style={{ fontSize: 12 }}>
                {t(`role.${user.role}`)}
              </div>
            </div>
            <button className="btn ghost sm" onClick={toggleTheme} aria-label={t('common.theme')} title={theme}>
              {theme === 'dark' ? Icon.sun : Icon.moon}
            </button>
          </div>
          <select value={lang} onChange={(e) => pickLang(e.target.value as Lang)} aria-label={t('common.language')} style={{ width: '100%' }}>
            {LANGS.map((l) => (
              <option key={l.code} value={l.code}>
                {l.label}
              </option>
            ))}
          </select>
          <button className="btn sm" onClick={onLogout}>
            {t('auth.logout')}
          </button>
        </div>
      </aside>
      <main className="main" id="main" tabIndex={-1}>
        <button className="btn menu-btn" style={{ marginBottom: 14 }} onClick={() => setOpen(!open)} aria-label={t('common.menu')} aria-expanded={open}>
          {Icon.menu}
        </button>
        {page}
      </main>
      <Overlays />
    </div>
  );
}
