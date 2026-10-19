import { createContext, useContext, useState, type ReactNode } from 'react';
import { en } from './en';
import { es } from './es';
import { ca } from './ca';

export type Lang = 'en' | 'es' | 'ca';
export const LANGS: { code: Lang; label: string }[] = [
  { code: 'ca', label: 'Català' },
  { code: 'es', label: 'Español' },
  { code: 'en', label: 'English' },
];
const dicts: Record<Lang, Record<string, string>> = { en, es, ca };

function detect(): Lang {
  try {
    const saved = localStorage.getItem('oculyx.lang') as Lang | null;
    if (saved && saved in dicts) return saved;
  } catch {
    /* ignore */
  }
  const nav = navigator.language.slice(0, 2);
  return nav in dicts ? (nav as Lang) : 'en';
}

interface Ctx {
  lang: Lang;
  setLang: (l: Lang) => void;
  t: (key: string, vars?: Record<string, string | number>) => string;
}
const I18n = createContext<Ctx>(null as unknown as Ctx);

export function I18nProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(detect);
  const setLang = (l: Lang) => {
    setLangState(l);
    document.documentElement.lang = l;
    try {
      localStorage.setItem('oculyx.lang', l);
    } catch {
      /* ignore */
    }
  };
  const t: Ctx['t'] = (key, vars) => {
    let s = dicts[lang][key] ?? en[key] ?? key;
    if (vars) for (const [k, v] of Object.entries(vars)) s = s.replaceAll(`{${k}}`, String(v));
    return s;
  };
  return <I18n.Provider value={{ lang, setLang, t }}>{children}</I18n.Provider>;
}

export const useI18n = () => useContext(I18n);
export const useT = () => useContext(I18n).t;
