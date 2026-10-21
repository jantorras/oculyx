import { useT } from '../i18n';

export type Sev = 'critical' | 'high' | 'medium' | 'low';
export interface PolicyConfig {
  thresholds?: { cpu?: number; mem?: number; disk?: number };
  samples?: number;
  minSeverity?: string;
  rules?: Record<string, { enabled?: boolean; severity?: Sev }>;
}
export interface Effective {
  thresholds: { cpu: number; mem: number; disk: number };
  samples: number;
  minSeverity: string;
  rules: Record<string, { enabled: boolean; severity: Sev }>;
}
export interface RuleMeta { id: string; group: string; defaultSeverity: Sev }

export const RULE_GROUPS = ['resources', 'availability', 'access', 'accounts', 'persistence', 'processes', 'system'];
const SEVS: Sev[] = ['critical', 'high', 'medium', 'low'];

/** True when the config sets nothing at all. */
export const isEmpty = (c: PolicyConfig) => !c.thresholds && c.samples === undefined && !c.minSeverity && !c.rules;

/**
 * Edits a sparse config. Every field can be left empty to inherit: `inherited` is what applies then,
 * so the user always sees what "inherit" means before overriding it.
 */
export function PolicyEditor({ value, onChange, inherited, rules, from }: {
  value: PolicyConfig;
  onChange: (c: PolicyConfig) => void;
  inherited: Effective;
  rules: RuleMeta[];
  from: string;
}) {
  const t = useT();
  const setTh = (k: 'cpu' | 'mem' | 'disk', v: string) => {
    const th = { ...value.thresholds };
    if (v === '') delete th[k];
    else th[k] = Math.min(100, Math.max(1, Number(v)));
    onChange({ ...value, thresholds: Object.keys(th).length ? th : undefined });
  };
  const setRule = (id: string, patch: { enabled?: boolean | null; severity?: Sev | null }) => {
    const cur = { ...value.rules?.[id] };
    if (patch.enabled !== undefined) patch.enabled === null ? delete cur.enabled : (cur.enabled = patch.enabled);
    if (patch.severity !== undefined) patch.severity === null ? delete cur.severity : (cur.severity = patch.severity);
    const all = { ...value.rules };
    if (Object.keys(cur).length) all[id] = cur;
    else delete all[id];
    onChange({ ...value, rules: Object.keys(all).length ? all : undefined });
  };
  const inh = (s: string) => `${t('pol.inherit')} (${s})`;
  const onoff = (b: boolean) => (b ? t('pol.on') : t('pol.off'));

  return (
    <div className="grid" style={{ gap: 18 }}>
      <section className="sect">
        <h3 className="sect-title">{t('pol.limits')}</h3>
        <p className="muted small" style={{ margin: '0 0 10px' }}>{t('pol.limits_help', { from })}</p>
        <div className="pol-limits">
          {(['cpu', 'mem', 'disk'] as const).map((k) => (
            <label className="field" key={k}>{k === 'cpu' ? 'CPU %' : k === 'mem' ? `${t('host.memory')} %` : `${t('host.disk')} %`}
              <input type="number" min={1} max={100} value={value.thresholds?.[k] ?? ''} placeholder={String(inherited.thresholds[k])} onChange={(e) => setTh(k, e.target.value)} />
            </label>
          ))}
          <label className="field">{t('pol.samples')}
            <input type="number" min={1} max={20} value={value.samples ?? ''} placeholder={String(inherited.samples)} onChange={(e) => onChange({ ...value, samples: e.target.value === '' ? undefined : Math.min(20, Math.max(1, Number(e.target.value))) })} />
          </label>
          <label className="field">{t('pol.min_sev')}
            <select value={value.minSeverity ?? ''} onChange={(e) => onChange({ ...value, minSeverity: e.target.value || undefined })}>
              <option value="">{inh(t(`sev.${inherited.minSeverity}`))}</option>
              {['low', 'medium', 'high', 'critical'].map((s) => <option key={s} value={s}>{t(`sev.${s}`)}</option>)}
            </select>
          </label>
        </div>
      </section>

      {RULE_GROUPS.map((g) => {
        const list = rules.filter((r) => r.group === g);
        if (!list.length) return null;
        return (
          <section key={g} className="sect">
            <h3 className="sect-title">{t(`rulegrp.${g}`)}</h3>
            <div className="pol-rules">
              {list.map((r) => {
                const v = value.rules?.[r.id] ?? {};
                const inhR = inherited.rules[r.id];
                const changed = v.enabled !== undefined || v.severity !== undefined;
                return (
                  <div key={r.id} className={`pol-rule ${changed ? 'changed' : ''} ${(v.enabled ?? inhR.enabled) ? '' : 'off'}`}>
                    <div className="grow">
                      <div className="t">{t(`rule.${r.id}`)}</div>
                      <div className="muted small">{t(`ruledesc.${r.id}`)}</div>
                    </div>
                    <select aria-label={`${t(`rule.${r.id}`)}: ${t('pol.state')}`} value={v.enabled === undefined ? '' : v.enabled ? '1' : '0'} onChange={(e) => setRule(r.id, { enabled: e.target.value === '' ? null : e.target.value === '1' })}>
                      <option value="">{inh(onoff(inhR.enabled))}</option>
                      <option value="1">{t('pol.on')}</option>
                      <option value="0">{t('pol.off')}</option>
                    </select>
                    <select aria-label={`${t(`rule.${r.id}`)}: ${r.id === 'finding' ? t('pol.min_finding') : t('pol.severity')}`} title={r.id === 'finding' ? t('pol.min_finding') : t('pol.severity')} value={v.severity ?? ''} onChange={(e) => setRule(r.id, { severity: (e.target.value || null) as Sev | null })}>
                      <option value="">{inh(t(`sev.${inhR.severity}`))}</option>
                      {SEVS.map((s) => <option key={s} value={s}>{t(`sev.${s}`)}</option>)}
                    </select>
                  </div>
                );
              })}
            </div>
          </section>
        );
      })}
    </div>
  );
}
