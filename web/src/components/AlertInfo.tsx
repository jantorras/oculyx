import { useState } from 'react';
import { api } from '../lib';
import { useI18n } from '../i18n';

type Entry = { meaning: string; todo: string };
let cache: Promise<Record<string, Record<string, Entry>>> | null = null;
const load = () => (cache ??= api('/alert-info').catch(() => { cache = null; return {}; }));

/** Plain-language explanation of an alert type: what it means and what to do first. */
export function AlertInfo({ rule, compact }: { rule: string; compact?: boolean }) {
  const { lang, t } = useI18n();
  const [cat, setCat] = useState<Record<string, Record<string, Entry>> | null>(null);
  if (cat === null) {
    void load().then(setCat);
    return null;
  }
  const e = cat[rule.split(':')[0]];
  const x = e && (e[lang] ?? e.en);
  if (!x) return null;
  return (
    <div className={`alert-info ${compact ? 'compact' : 'sect'}`}>
      <p>{x.meaning}</p>
      {!compact && <div className="todo"><h4 className="sect-title">{t('alerts.what_to_do')}</h4><p>{x.todo}</p></div>}
    </div>
  );
}
