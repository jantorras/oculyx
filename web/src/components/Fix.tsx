import { useEffect, useState } from 'react';
import { api } from '../lib';
import { useT } from '../i18n';
import { Modal } from './ui';

interface Preview {
  title: string;
  steps: string[];
  warning?: string;
  confirm?: boolean;
  args?: Record<string, unknown>;
}

/** Shows what a one-click fix will do, asks for confirmation when it can lock you out, then runs it on the agent. */
export function FixDialog({ agentId, fix, onClose, onDone }: { agentId: number; fix: string; onClose: () => void; onDone: () => void }) {
  const t = useT();
  const [pv, setPv] = useState<Preview | null>(null);
  const [err, setErr] = useState('');
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<string[] | null>(null);

  useEffect(() => {
    api<Preview>(`/agents/${agentId}/fix/preview`, { body: { fix } }).then(setPv).catch((e) => setErr(e.message));
  }, [agentId, fix]);

  const run = async () => {
    setBusy(true);
    setErr('');
    try {
      const r = await api<{ steps: string[] }>(`/agents/${agentId}/fix`, { body: { fix, args: { ...(pv?.args ?? {}), confirm: ack } } });
      setResult(r.steps);
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title={pv?.title ?? t('fix.title')} onClose={onClose}>
      {!pv && !err && <div className="muted">{t('fix.loading')}</div>}
      {pv && !result && (
        <>
          <div className="muted" style={{ fontSize: 13 }}>{t('fix.will_do')}</div>
          <ul className="steps">{pv.steps.map((s, i) => <li key={i}><span className="mono">{s}</span></li>)}</ul>
          {pv.warning && <div className="warn">{pv.warning}</div>}
          {pv.confirm && (
            <label className="row" style={{ gap: 8, alignItems: 'flex-start', fontSize: 13 }}>
              <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} style={{ marginTop: 3 }} />
              <span>{t('fix.ack')}</span>
            </label>
          )}
        </>
      )}
      {result && (
        <>
          <div style={{ color: 'var(--ok)', fontWeight: 600 }}>{t('fix.done')}</div>
          <ul className="steps">{result.map((s, i) => <li key={i}><span className="mono">{s}</span></li>)}</ul>
        </>
      )}
      {err && <div className="error" role="alert">{err}</div>}
      <div className="row" style={{ justifyContent: 'flex-end', gap: 8 }}>
        <button className="btn" onClick={onClose}>{result ? t('common.close') : t('common.cancel')}</button>
        {pv && !result && <button className="btn primary" disabled={busy || (pv.confirm && !ack)} onClick={run}>{busy ? t('fix.running') : t('fix.apply')}</button>}
      </div>
    </Modal>
  );
}
