import { useEffect, useMemo, useState } from 'react';
import { api, usePoll, ago } from '../lib';
import { useT } from '../i18n';
import { useUser } from '../App';
import { Card, Empty, Modal, Skeleton } from '../components/ui';
import { toast } from '../components/overlay';

type Sev = 'critical' | 'high' | 'medium' | 'low';
interface LogRule { name: string; file: string; pattern: string; severity: Sev }
interface Patch {
  fim?: { enabled?: boolean; paths?: string[]; exclude?: string[]; everyMin?: number };
  cve?: { enabled?: boolean };
  sca?: { enabled?: boolean };
  inventory?: { enabled?: boolean };
  logs?: { enabled?: boolean; presets?: string[]; custom?: LogRule[] };
}
interface HostStatus {
  id: number; name: string; online: boolean; profile: string | null; checks: Required<{ [K in keyof Patch]: any }>;
  sca: { ts: number; score: number; fail: number; pass: number } | null;
  inventory: { ts: number; packages: number; services: number } | null;
  vulns: { ts: number; status: string; critical: number; high: number; medium: number; low: number; unknown: number; error: string } | null;
}
interface Profile { id: number; name: string; config: { checks?: Patch }; hosts: number[] }

const CHECKS = ['sca', 'cve', 'inventory', 'fim', 'logs'] as const;
type CheckId = (typeof CHECKS)[number];
const RECOMMENDED: CheckId[] = ['sca', 'cve', 'inventory'];
const FIM_PRESETS: Record<string, string[]> = {
  web: ['/var/www', '/etc/nginx', '/etc/apache2'],
  access: ['/etc/ssh', '/root/.ssh', '/etc/sudoers.d'],
  binaries: ['/usr/local/bin', '/usr/local/sbin', '/etc/cron.d'],
  docker: ['/etc/docker', '/etc/containerd'],
};
const LOG_PRESETS = ['web_attacks', 'oom', 'disk_errors'];

const uniq = <T,>(a: T[], key: (x: T) => string = String) => { const s = new Set<string>(); return a.filter((x) => !s.has(key(x)) && s.add(key(x))); };
/** Booleans and numbers overwrite; lists add up (same rule the server uses across layers). */
export function mergePatch(a: Patch = {}, b: Patch = {}): Patch {
  const out: any = { ...a };
  for (const k of Object.keys(b) as (keyof Patch)[]) {
    const x: any = { ...(a as any)[k] };
    for (const [f, v] of Object.entries((b as any)[k])) x[f] = Array.isArray(v) ? uniq([...(x[f] ?? []), ...v], (i: any) => (typeof i === 'string' ? i : i.name)) : v;
    out[k] = x;
  }
  return out;
}

/** Security checks: a guided setup and the results per server. */
export function Checks() {
  const t = useT();
  const [tab, setTab] = useState<'setup' | 'servers'>('servers');
  const [target, setTarget] = useState<number | null>(null);
  const { data, refresh } = usePoll(() => api<{ hosts: HostStatus[] }>('/checks'), 10000);
  const pol = usePoll(() => api<{ profiles: Profile[]; hosts: { id: number; name: string }[] }>('/policies'), 15000);
  useEffect(() => { if (data && data.hosts.every((h) => !h.sca && !h.inventory)) setTab('setup'); }, [!!data]); // eslint-disable-line
  if (!data || !pol.data) return <Skeleton />;
  return (
    <div style={{ maxWidth: 1100 }}>
      <div className="topbar">
        <div className="grow">
          <h1>{t('nav.checks')}</h1>
          <div className="sub">{t('chk.subtitle')}</div>
        </div>
      </div>
      <div className="tabs" role="tablist">
        {(['servers', 'setup'] as const).map((k) => <button key={k} role="tab" aria-selected={tab === k} className={tab === k ? 'active' : ''} onClick={() => { setTab(k); if (k === 'servers') setTarget(null); }}>{t(`chk.tab_${k}`)}</button>)}
      </div>
      {tab === 'setup'
        ? <Wizard hosts={data.hosts} profiles={pol.data.profiles} initialHost={target} onDone={() => { refresh(); pol.refresh(); setTab('servers'); }} />
        : <Servers hosts={data.hosts} refresh={refresh} onEdit={(id) => { setTarget(id); setTab('setup'); }} />}
    </div>
  );
}

/* ---------------- step by step setup ---------------- */

function Wizard({ hosts, profiles, initialHost, onDone }: { hosts: HostStatus[]; profiles: Profile[]; initialHost: number | null; onDone: () => void }) {
  const t = useT();
  const [step, setStep] = useState(0);
  const [on, setOn] = useState<Set<CheckId>>(new Set(RECOMMENDED));
  const [paths, setPaths] = useState<string[]>([]);
  const [exclude, setExclude] = useState('*.log\n*.tmp\ncache/');
  const [every, setEvery] = useState(10);
  const [presets, setPresets] = useState<Set<string>>(new Set(['web_attacks']));
  const [custom, setCustom] = useState<LogRule[]>([]);
  const [mode, setMode] = useState<'hosts' | 'profile'>('hosts');
  const [sel, setSel] = useState<Set<number>>(new Set(initialHost ? [initialHost] : hosts.map((h) => h.id)));
  const [profileId, setProfileId] = useState<number | 'new'>(profiles[0]?.id ?? 'new');
  const [newName, setNewName] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const detail = on.has('fim') || on.has('logs');
  const steps = [t('chk.step_what'), ...(detail ? [t('chk.step_details')] : []), t('chk.step_where'), t('chk.step_review')];
  const idx = (n: 'what' | 'details' | 'where' | 'review') => (n === 'what' ? 0 : n === 'details' ? 1 : n === 'where' ? (detail ? 2 : 1) : steps.length - 1);
  const names = new Map(hosts.map((h) => [h.id, h.name]));

  const patch: Patch = useMemo(() => {
    const p: Patch = { sca: { enabled: on.has('sca') }, cve: { enabled: on.has('cve') }, inventory: { enabled: on.has('inventory') } };
    p.fim = { enabled: on.has('fim'), ...(on.has('fim') ? { paths, exclude: exclude.split('\n').map((x) => x.trim()).filter(Boolean), everyMin: every } : {}) };
    p.logs = { enabled: on.has('logs'), ...(on.has('logs') ? { presets: [...presets], custom: custom.filter((c) => c.name && c.file && c.pattern) } : {}) };
    return p;
  }, [on, paths, exclude, every, presets, custom]);

  const toggle = (id: CheckId) => setOn((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const toggleIn = <T,>(set: Set<T>, v: T, put: (s: Set<T>) => void) => { const n = new Set(set); n.has(v) ? n.delete(v) : n.add(v); put(n); };
  const fimOk = !on.has('fim') || paths.length > 0;
  const whereOk = mode === 'hosts' ? sel.size > 0 : profileId !== 'new' || newName.trim().length > 0;

  const apply = async () => {
    setBusy(true);
    setErr('');
    try {
      if (mode === 'hosts') {
        for (const id of sel) {
          const cur = await api<{ overrides: any }>(`/agents/${id}/policy`);
          await api(`/agents/${id}/policy`, { method: 'PUT', body: { overrides: { ...cur.overrides, checks: mergePatch(cur.overrides.checks, patch) } } });
        }
      } else {
        const prof = profileId === 'new' ? null : profiles.find((p) => p.id === profileId)!;
        const body = { name: prof?.name ?? newName.trim(), description: '', config: { ...(prof?.config ?? {}), checks: mergePatch(prof?.config.checks, patch) } };
        const r = prof ? await api<{ id: number }>(`/profiles/${prof.id}`, { method: 'PUT', body: { ...body, description: (prof as any).description ?? '' } }) : await api<{ id: number }>('/profiles', { method: 'POST', body });
        if (sel.size) await api(`/profiles/${r.id}/hosts`, { method: 'PUT', body: { agentIds: [...new Set([...(prof?.hosts ?? []), ...sel])] } });
      }
      toast(t('chk.applied'));
      onDone();
    } catch (e: any) {
      setErr(e.message === 'name_taken' ? t('pol.name_taken') : e.message);
    } finally {
      setBusy(false);
    }
  };

  const nav = (canNext: boolean, last = false) => (
    <div className="row" style={{ gap: 10, marginTop: 18 }}>
      {step > 0 && <button className="btn" onClick={() => setStep(step - 1)}>{t('chk.back')}</button>}
      {last
        ? <button className="btn primary" disabled={busy} onClick={apply}>{t('chk.apply')}</button>
        : <button className="btn primary" disabled={!canNext} onClick={() => setStep(step + 1)}>{t('chk.next')}</button>}
      {err && <span className="error" role="alert">{err}</span>}
    </div>
  );

  return (
    <div className="wiz">
      <ol className="wiz-steps" aria-label={t('chk.steps')}>
        {steps.map((s, i) => <li key={s} className={i === step ? 'cur' : i < step ? 'done' : ''}><span>{i + 1}</span>{s}</li>)}
      </ol>

      {step === idx('what') && (
        <>
          <p className="muted" style={{ marginTop: 0 }}>{t('chk.intro')}</p>
          <div className="chk-cards">
            {CHECKS.map((id) => (
              <article key={id} className={`chk-card ${on.has(id) ? 'on' : ''}`}>
                <header>
                  <h3>{t(`chk.${id}.name`)}</h3>
                  {RECOMMENDED.includes(id) ? <span className="tag ok">{t('chk.recommended')}</span> : <span className="tag">{t('chk.needs_input')}</span>}
                  <button type="button" className={`toggle ${on.has(id) ? 'on' : ''}`} role="switch" aria-checked={on.has(id)} aria-label={t(`chk.${id}.name`)} onClick={() => toggle(id)}><i /></button>
                </header>
                <dl>
                  <dt>{t('chk.what')}</dt><dd>{t(`chk.${id}.what`)}</dd>
                  <dt>{t('chk.why')}</dt><dd>{t(`chk.${id}.why`)}</dd>
                  <dt>{t('chk.cost')}</dt><dd>{t(`chk.${id}.cost`)}</dd>
                </dl>
              </article>
            ))}
          </div>
          {nav(on.size > 0)}
        </>
      )}

      {detail && step === idx('details') && (
        <div className="grid" style={{ gap: 18 }}>
          {on.has('fim') && (
            <Card title={t('chk.fim.name')}>
              <p className="muted small" style={{ marginTop: 0 }}>{t('chk.fim.help')}</p>
              <h4 className="sec-title">{t('chk.fim.quick')}</h4>
              <div className="chips">
                {Object.entries(FIM_PRESETS).map(([k, list]) => {
                  const active = list.every((p) => paths.includes(p));
                  return <button key={k} type="button" className={`chip-btn ${active ? 'active' : ''}`} aria-pressed={active} onClick={() => setPaths(active ? paths.filter((p) => !list.includes(p)) : uniq([...paths, ...list]))}>{t(`chk.fim.p_${k}`)}<small>{list.join('  ')}</small></button>;
                })}
              </div>
              <label className="field" style={{ marginTop: 14 }}>{t('chk.fim.paths')}
                <textarea rows={4} value={paths.join('\n')} placeholder="/var/www/html" onChange={(e) => setPaths(e.target.value.split('\n').map((x) => x.trim()))} spellCheck={false} />
                <span className="muted small">{t('chk.fim.paths_help')}</span>
              </label>
              <div className="grid g2" style={{ marginTop: 12 }}>
                <label className="field">{t('chk.fim.exclude')}
                  <textarea rows={3} value={exclude} onChange={(e) => setExclude(e.target.value)} spellCheck={false} />
                  <span className="muted small">{t('chk.fim.exclude_help')}</span>
                </label>
                <label className="field">{t('chk.fim.every')}
                  <select value={every} onChange={(e) => setEvery(Number(e.target.value))}>{[5, 10, 30, 60].map((m) => <option key={m} value={m}>{t('chk.fim.every_n', { n: m })}</option>)}</select>
                  <span className="muted small">{t('chk.fim.first')}</span>
                </label>
              </div>
            </Card>
          )}
          {on.has('logs') && (
            <Card title={t('chk.logs.name')}>
              <p className="muted small" style={{ marginTop: 0 }}>{t('chk.logs.help')}</p>
              <div className="pol-hosts" style={{ gridTemplateColumns: '1fr', maxHeight: 'none' }}>
                {LOG_PRESETS.map((p) => (
                  <label key={p} className="pol-host" style={{ alignItems: 'flex-start' }}>
                    <input type="checkbox" checked={presets.has(p)} onChange={() => toggleIn(presets, p, setPresets)} style={{ marginTop: 3 }} />
                    <span style={{ whiteSpace: 'normal' }}><b>{t(`chk.logs.p_${p}`)}</b><span className="muted small" style={{ display: 'block' }}>{t(`chk.logs.p_${p}_d`)}</span></span>
                  </label>
                ))}
              </div>
              <h4 className="sec-title" style={{ marginTop: 16 }}>{t('chk.logs.custom')}</h4>
              <p className="muted small" style={{ marginTop: 0 }}>{t('chk.logs.custom_help')}</p>
              {custom.map((c, i) => (
                <div key={i} className="logrule">
                  <input placeholder={t('chk.logs.rule_name')} aria-label={t('chk.logs.rule_name')} value={c.name} onChange={(e) => setCustom(custom.map((x, j) => (j === i ? { ...x, name: e.target.value } : x)))} />
                  <input placeholder="/var/log/myapp/error.log" aria-label={t('chk.logs.rule_file')} value={c.file} onChange={(e) => setCustom(custom.map((x, j) => (j === i ? { ...x, file: e.target.value } : x)))} spellCheck={false} />
                  <input placeholder="ERROR|Exception" aria-label={t('chk.logs.rule_text')} value={c.pattern} onChange={(e) => setCustom(custom.map((x, j) => (j === i ? { ...x, pattern: e.target.value } : x)))} spellCheck={false} />
                  <select aria-label={t('pol.severity')} value={c.severity} onChange={(e) => setCustom(custom.map((x, j) => (j === i ? { ...x, severity: e.target.value as Sev } : x)))}>{['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{t(`sev.${s}`)}</option>)}</select>
                  <button className="btn sm danger" onClick={() => setCustom(custom.filter((_, j) => j !== i))} aria-label={t('pol.delete')}>×</button>
                </div>
              ))}
              <button className="btn sm" onClick={() => setCustom([...custom, { name: '', file: '', pattern: '', severity: 'medium' }])}>+ {t('chk.logs.add')}</button>
            </Card>
          )}
          {nav(fimOk)}
          {!fimOk && <p className="muted small" style={{ margin: 0 }}>{t('chk.fim.need_path')}</p>}
        </div>
      )}

      {step === idx('where') && (
        <Card title={t('chk.where_title')}>
          <p className="muted small" style={{ marginTop: 0 }}>{t('chk.where_help')}</p>
          <div className="radios">
            <label className={`radio ${mode === 'hosts' ? 'on' : ''}`}><input type="radio" name="mode" checked={mode === 'hosts'} onChange={() => setMode('hosts')} /><span><b>{t('chk.where_hosts')}</b><span className="muted small" style={{ display: 'block' }}>{t('chk.where_hosts_d')}</span></span></label>
            <label className={`radio ${mode === 'profile' ? 'on' : ''}`}><input type="radio" name="mode" checked={mode === 'profile'} onChange={() => setMode('profile')} /><span><b>{t('chk.where_profile')}</b><span className="muted small" style={{ display: 'block' }}>{t('chk.where_profile_d')}</span></span></label>
          </div>
          {mode === 'profile' && (
            <div className="grid g2" style={{ marginTop: 12 }}>
              <label className="field">{t('pol.profile')}
                <select value={profileId} onChange={(e) => setProfileId(e.target.value === 'new' ? 'new' : Number(e.target.value))}>
                  {profiles.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                  <option value="new">+ {t('pol.new')}</option>
                </select>
              </label>
              {profileId === 'new' && <label className="field">{t('pol.name')}<input value={newName} maxLength={60} onChange={(e) => setNewName(e.target.value)} /></label>}
            </div>
          )}
          <h4 className="sec-title" style={{ marginTop: 16 }}>{mode === 'hosts' ? t('chk.which_hosts') : t('chk.also_add')}</h4>
          {hosts.length === 0 ? <Empty>{t('pol.no_hosts')}</Empty> : (
            <div className="pol-hosts">
              {hosts.map((h) => (
                <label key={h.id} className="pol-host"><input type="checkbox" checked={sel.has(h.id)} onChange={() => toggleIn(sel, h.id, setSel)} /><span>{h.name}</span>{!h.online && <span className="muted small">{t('chk.offline_note')}</span>}</label>
              ))}
            </div>
          )}
          {nav(whereOk)}
        </Card>
      )}

      {step === idx('review') && (
        <Card title={t('chk.review_title')}>
          <p className="muted small" style={{ marginTop: 0 }}>{t('chk.review_help')}</p>
          <ul className="review">
            {CHECKS.map((id) => <li key={id} className={on.has(id) ? 'yes' : 'no'}><b>{t(`chk.${id}.name`)}</b> {on.has(id) ? t('chk.r_on') : t('chk.r_off')}
              {id === 'fim' && on.has('fim') && <span className="muted small"> {t('chk.r_fim', { n: paths.length, m: every })}</span>}
              {id === 'logs' && on.has('logs') && <span className="muted small"> {t('chk.r_logs', { n: presets.size + custom.filter((c) => c.name && c.pattern).length })}</span>}
            </li>)}
          </ul>
          <p style={{ marginBottom: 4 }}><b>{t('chk.r_where')}:</b> {mode === 'hosts' ? t('chk.r_hosts', { n: sel.size }) : t('chk.r_profile', { name: profileId === 'new' ? newName : profiles.find((p) => p.id === profileId)?.name ?? '' })}</p>
          {sel.size > 0 && <p className="muted small" style={{ marginTop: 0 }}>{[...sel].map((i) => names.get(i)).join(', ')}</p>}
          <p className="muted small">{t('chk.r_next')}</p>
          {nav(true, true)}
        </Card>
      )}
    </div>
  );
}

/* ---------------- results per server ---------------- */

function Servers({ hosts, refresh, onEdit }: { hosts: HostStatus[]; refresh: () => void; onEdit: (id: number) => void }) {
  const t = useT();
  const [open, setOpen] = useState<HostStatus | null>(null);
  if (!hosts.length) return <Empty>{t('pol.no_hosts')}</Empty>;
  const scoreCls = (s: number) => (s >= 80 ? 'ok' : s >= 60 ? 'warn' : 'bad');
  return (
    <>
      <Card flush>
        <table className="rows">
          <thead><tr><th>{t('pol.host')}</th><th>{t('chk.sca.short')}</th><th>{t('chk.cve.short')}</th><th>{t('chk.inventory.short')}</th><th>{t('chk.watching')}</th><th /></tr></thead>
          <tbody>
            {hosts.map((h) => (
              <tr key={h.id}>
                <td><button className="linkish" onClick={() => setOpen(h)}><b>{h.name}</b></button>{!h.online && <span className="muted small"> · {t('chk.offline')}</span>}</td>
                <td>{h.checks.sca.enabled ? (h.sca ? <span className={`score ${scoreCls(h.sca.score)}`}>{h.sca.score}<small>/100</small></span> : <span className="muted small">{t('chk.waiting')}</span>) : <span className="muted small">{t('pol.off')}</span>}</td>
                <td>{!h.checks.cve.enabled ? <span className="muted small">{t('pol.off')}</span> : !h.vulns ? <span className="muted small">{t('chk.waiting')}</span> : h.vulns.status === 'ok'
                  ? <span>{h.vulns.critical ? <span className="tag bad">{h.vulns.critical} {t('sev.critical')}</span> : null} {h.vulns.high ? <span className="tag warn">{h.vulns.high} {t('sev.high')}</span> : null} {!h.vulns.critical && !h.vulns.high ? <span className="tag ok">{t('chk.none_serious')}</span> : null}</span>
                  : <span className="muted small" title={h.vulns.error}>{h.vulns.status === 'unsupported' ? t('chk.cve_unsupported') : t('chk.cve_error')}</span>}</td>
                <td>{h.checks.inventory.enabled ? (h.inventory ? <span className="muted">{t('chk.n_packages', { n: h.inventory.packages })}</span> : <span className="muted small">{t('chk.waiting')}</span>) : <span className="muted small">{t('pol.off')}</span>}</td>
                <td className="muted small">{[h.checks.fim.enabled && h.checks.fim.paths.length ? t('chk.n_paths', { n: h.checks.fim.paths.length }) : '', h.checks.logs.enabled ? t('chk.n_logrules', { n: h.checks.logs.presets.length + h.checks.logs.custom.length }) : ''].filter(Boolean).join(' · ') || '—'}</td>
                <td style={{ textAlign: 'right' }}><button className="btn sm" onClick={() => onEdit(h.id)}>{t('chk.change')}</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      {open && <HostChecks host={open} onClose={() => { setOpen(null); refresh(); }} />}
    </>
  );
}

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

function HostChecks({ host, onClose }: { host: HostStatus; onClose: () => void }) {
  const t = useT();
  const user = useUser();
  const { data, refresh } = usePoll(() => api<any>(`/agents/${host.id}/checks`), 8000);
  const [tab, setTab] = useState<'sca' | 'cve' | 'inv'>('sca');
  const [showPass, setShowPass] = useState(false);
  const run = async (which: string) => {
    try {
      await api(`/agents/${host.id}/checks/run`, { method: 'POST', body: { which } });
      toast(t('chk.running'));
      setTimeout(refresh, 4000);
    } catch (e: any) {
      toast(e.message === 'agent_offline' ? t('chk.offline') : e.message, 'error');
    }
  };
  const controls: any[] = data?.sca?.controls ?? [];
  const shown = controls.filter((c) => c.status === 'fail' || (showPass && c.status === 'pass')).sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  const items: any[] = data?.vulns?.items ?? [];
  return (
    <Modal wide title={host.name} onClose={onClose}>
      {!data ? <Skeleton /> : (
        <>
          <div className="tabs" role="tablist">
            {([['sca', t('chk.sca.short')], ['cve', t('chk.cve.short')], ['inv', t('chk.inventory.short')]] as const).map(([k, l]) => <button key={k} role="tab" aria-selected={tab === k} className={tab === k ? 'active' : ''} onClick={() => setTab(k)}>{l}</button>)}
          </div>
          {tab === 'sca' && (
            !data.sca ? <Empty>{t('chk.no_data')}</Empty> : (
              <>
                <div className="row spread" style={{ marginBottom: 10 }}>
                  <div><span className="score big">{data.sca.score}<small>/100</small></span> <span className="muted small">{t('chk.updated', { t: ago(data.sca.ts) })}</span></div>
                  <div className="row" style={{ gap: 8 }}>
                    <label className="row small" style={{ gap: 6 }}><input type="checkbox" checked={showPass} onChange={(e) => setShowPass(e.target.checked)} style={{ width: 'auto' }} />{t('chk.show_passed')}</label>
                    {user.role === 'admin' && <button className="btn sm" onClick={() => run('sca')}>{t('chk.run_now')}</button>}
                  </div>
                </div>
                <p className="muted small" style={{ marginTop: 0 }}>{t('chk.sca.explain_score')}</p>
                {shown.length === 0 ? <Empty>{t('chk.all_pass')}</Empty> : shown.map((c) => (
                  <details key={c.id} className={`ctl ${c.status}`}>
                    <summary><span className={`pill ${c.status === 'fail' ? (c.severity === 'high' ? 'high' : 'medium') : 'ok'}`}>{c.status === 'fail' ? t(`sev.${c.severity}`) : t('chk.passed')}</span> {c.title}</summary>
                    <div className="ctl-body"><p><b>{t('chk.why')}:</b> {c.why}</p>{c.status === 'fail' && <p><b>{t('chk.how_fix')}:</b> {c.fix}</p>}{c.detail && <p className="muted small mono">{c.detail}</p>}</div>
                  </details>
                ))}
              </>
            )
          )}
          {tab === 'cve' && (
            !data.vulns ? <Empty>{host.checks.cve.enabled ? t('chk.no_data') : t('chk.cve_off')}</Empty> : data.vulns.status !== 'ok' ? (
              <div className="notice">{data.vulns.status === 'unsupported' ? t('chk.cve_unsupported_long', { os: data.vulns.os?.id ?? '' }) : t('chk.cve_error_long', { e: data.vulns.error ?? '' })}</div>
            ) : (
              <>
                <div className="row spread" style={{ marginBottom: 8 }}>
                  <span className="muted small">{t('chk.cve_summary', { n: items.length, p: data.vulns.packages, t: ago(data.vulns.ts) })}</span>
                  {user.role === 'admin' && <button className="btn sm" onClick={() => run('cve')}>{t('chk.run_now')}</button>}
                </div>
                {items.length === 0 ? <Empty>{t('chk.cve_none')}</Empty> : (
                  <table className="rows"><thead><tr><th>{t('pol.severity')}</th><th>{t('chk.package')}</th><th>ID</th><th>{t('chk.fixed_in')}</th></tr></thead>
                    <tbody>{items.slice(0, 150).map((v) => (
                      <tr key={`${v.id}${v.pkg}`}><td><span className={`pill ${v.severity === 'critical' || v.severity === 'high' ? 'high' : v.severity === 'medium' ? 'medium' : 'ok'}`}>{v.severity === 'unknown' ? t('chk.unknown') : t(`sev.${v.severity}`)}</span></td>
                        <td><b>{v.pkg}</b> <span className="muted small">{v.version}</span><div className="muted small">{v.summary}</div></td>
                        <td className="mono small">{v.aliases?.[0] ?? v.id}</td><td className="mono small">{v.fixed || '—'}</td></tr>
                    ))}</tbody></table>
                )}
                <p className="muted small">{t('chk.cve.privacy')}</p>
              </>
            )
          )}
          {tab === 'inv' && (
            !data.inventory ? <Empty>{t('chk.no_data')}</Empty> : (
              <>
                <div className="row spread"><span>{data.inventory.os?.name || data.inventory.os?.id} · {t('chk.n_packages', { n: data.inventory.packages })}</span>{user.role === 'admin' && <button className="btn sm" onClick={() => run('inventory')}>{t('chk.run_now')}</button>}</div>
                <h4 className="sec-title" style={{ marginTop: 14 }}>{t('chk.services_on', { n: data.inventory.services.length })}</h4>
                <div className="chips">{data.inventory.services.map((s: string) => <span key={s} className="tag">{s}</span>)}</div>
                <p className="muted small">{t('chk.inventory.explain')}</p>
              </>
            )
          )}
        </>
      )}
    </Modal>
  );
}
