import { useEffect, useRef, useState } from 'react';
import { api, usePoll } from '../lib';
import { useT, useI18n } from '../i18n';
import { useUser } from '../App';
import { toast, ask } from '../components/overlay';

type Proposal = { id: string; agentId: number; host: string; op: string; args: Record<string, unknown>; reason: string };
type Turn = { role: 'user' | 'assistant'; content: string; proposals?: Proposal[]; error?: boolean };

/** Chat with the fleet assistant. It reads the panel's data and can only propose actions; an admin confirms them. */
export function Assistant() {
  const t = useT();
  const { lang } = useI18n();
  const user = useUser();
  const { data: status } = usePoll(() => api<{ ready: boolean }>('/ai/status'), 30000);
  const [turns, setTurns] = useState<Turn[]>([]);
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [usage, setUsage] = useState<any>(null);
  const [done, setDone] = useState<Set<string>>(new Set());
  const end = useRef<HTMLDivElement>(null);
  useEffect(() => { end.current?.scrollIntoView({ block: 'end' }); }, [turns, busy]);

  const send = async (q: string) => {
    const msg = q.trim();
    if (!msg || busy) return;
    const next: Turn[] = [...turns, { role: 'user', content: msg }];
    setTurns(next);
    setText('');
    setBusy(true);
    try {
      const r = await api<any>('/ai/chat', { body: { messages: next.filter((x) => !x.error).map((x) => ({ role: x.role, content: x.content })), language: lang } });
      setTurns([...next, { role: 'assistant', content: r.reply, proposals: r.proposals }]);
      setUsage(r.usage);
    } catch (e: any) {
      setTurns([...next, { role: 'assistant', error: true, content: e.detail || e.message }]);
    } finally {
      setBusy(false);
    }
  };

  const confirmProposal = async (p: Proposal) => {
    if (!(await ask({ title: t('ai.confirm_title', { op: p.op, host: p.host }), body: `${JSON.stringify(p.args)}  ·  ${p.reason}`, confirm: t('ai.run'), danger: true }))) return;
    try {
      const r = await api<{ steps: string[] }>(`/ai/proposals/${p.id}/confirm`, { body: {} });
      toast(r.steps.join(' · '));
      setDone(new Set(done).add(p.id));
    } catch (e: any) {
      toast(e.message === 'proposal_expired' ? t('ai.expired') : e.message, 'error');
    }
  };

  const ideas = [t('ai.idea1'), t('ai.idea2'), t('ai.idea3')];
  const notReady = status && !status.ready;

  return (
    <div className="page" style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0, gap: 12 }}>
      <div className="page-head">
        <div className="grow">
          <h1>{t('nav.assistant')}</h1>
          <div className="sub">{t('ai.subtitle')}</div>
        </div>
        {usage && <span className="muted small">{t('ai.usage_line', { cost: usage.cost.toFixed(3), calls: usage.calls })}</span>}
      </div>

      {notReady && (
        <div className="notice">
          {t('ai.not_ready')} {user.role === 'admin' && <a href="#/settings/ai" style={{ color: 'var(--accent)' }}>{t('ai.go_setup')}</a>}
        </div>
      )}

      <div className="chat-log sect" role="log" aria-live="polite" style={{ flex: 1, minHeight: 0, overflow: 'auto', overflowWrap: 'anywhere' }}>
        {turns.length === 0 && (
          <div className="chat-empty">
            <p className="muted">{t('ai.intro')}</p>
            <div className="ideas">{ideas.map((i) => <button key={i} className="btn" disabled={!!notReady} onClick={() => send(i)}>{i}</button>)}</div>
          </div>
        )}
        {turns.map((m, i) => (
          <div key={i} className={`turn ${m.role} ${m.error ? 'err' : ''}`}>
            <div className="who">{m.role === 'user' ? user.username : t('nav.assistant')}</div>
            <div className="bubble">{m.content}</div>
            {m.proposals?.map((p) => (
              <div key={p.id} className="proposal">
                <div className="grow">
                  <div className="p-title">{t('ai.proposed')}: <b>{p.op}</b> · {p.host}</div>
                  <div className="muted small mono">{Object.keys(p.args).length ? JSON.stringify(p.args) : ''}</div>
                  <div className="muted small">{p.reason}</div>
                </div>
                {done.has(p.id) ? <span className="tag ok">{t('ai.done')}</span>
                  : user.role === 'admin' ? <button className="btn primary sm" onClick={() => confirmProposal(p)}>{t('ai.review')}</button>
                  : <span className="muted small">{t('ai.admin_only')}</span>}
              </div>
            ))}
          </div>
        ))}
        {busy && <div className="turn assistant"><div className="who">{t('nav.assistant')}</div><div className="bubble typing"><i /><i /><i /></div></div>}
        <div ref={end} />
      </div>

      <form className="chat-input filterbar" style={{ position: 'static', flexShrink: 0 }} onSubmit={(e) => { e.preventDefault(); void send(text); }}>
        <textarea value={text} rows={1} placeholder={t('ai.placeholder')} aria-label={t('ai.placeholder')} maxLength={1500} disabled={!!notReady}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); void send(text); } }} />
        <button className="btn primary" disabled={busy || !text.trim() || !!notReady}>{t('ai.send')}</button>
      </form>
      <p className="muted small" style={{ margin: '8px 2px 0' }}>{t('ai.disclaimer')}</p>
    </div>
  );
}
