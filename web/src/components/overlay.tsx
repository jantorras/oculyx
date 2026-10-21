import { useEffect, useRef, useState, type ReactNode } from 'react';
import { useT } from '../i18n';
import { Modal } from './ui';

/* ---------- toasts and confirmation dialogs, callable from anywhere (no provider plumbing) ---------- */
type Toast = { id: number; kind: 'ok' | 'error'; text: string };
type Ask = { title: string; body?: ReactNode; confirm?: string; danger?: boolean; resolve: (v: boolean) => void };

let toastSet: ((f: (t: Toast[]) => Toast[]) => void) | null = null;
let askSet: ((a: Ask | null) => void) | null = null;
let seq = 0;

export function toast(text: string, kind: Toast['kind'] = 'ok') {
  const id = ++seq;
  toastSet?.((t) => [...t.slice(-3), { id, kind, text }]);
  setTimeout(() => toastSet?.((t) => t.filter((x) => x.id !== id)), kind === 'error' ? 9000 : 4500);
}

/** Promise based replacement for window.confirm. */
export function ask(o: Omit<Ask, 'resolve'>): Promise<boolean> {
  return new Promise((resolve) => (askSet ? askSet({ ...o, resolve }) : resolve(window.confirm(o.title))));
}

/** Mount once near the root. */
export function Overlays() {
  const t = useT();
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [dlg, setDlg] = useState<Ask | null>(null);
  useEffect(() => {
    toastSet = setToasts;
    askSet = setDlg;
    return () => { toastSet = null; askSet = null; };
  }, []);
  const close = (v: boolean) => { dlg?.resolve(v); setDlg(null); };
  return (
    <>
      <div className="toasts" role="region" aria-live="polite">
        {toasts.map((x) => (
          <div key={x.id} className={`toast ${x.kind}`} role={x.kind === 'error' ? 'alert' : 'status'}>
            <span className="grow">{x.text}</span>
            <button className="btn ghost sm" onClick={() => setToasts((l) => l.filter((y) => y.id !== x.id))} aria-label={t('common.close')}>×</button>
          </div>
        ))}
      </div>
      {dlg && (
        <Modal title={dlg.title} onClose={() => close(false)}>
          {dlg.body && <div className="muted" style={{ fontSize: 13.5 }}>{dlg.body}</div>}
          <div className="row" style={{ justifyContent: 'flex-end', gap: 8 }}>
            <button className="btn" onClick={() => close(false)}>{t('common.cancel')}</button>
            <button className={`btn ${dlg.danger ? 'danger' : 'primary'}`} autoFocus onClick={() => close(true)}>{dlg.confirm ?? t('common.confirm')}</button>
          </div>
        </Modal>
      )}
    </>
  );
}

/* ---------- row action menu ---------- */
export type MenuItem = { label: string; onClick: () => void; danger?: boolean; disabled?: boolean; hint?: string } | 'sep';

export function Menu({ items, label }: { items: MenuItem[]; label: string }) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top?: number; bottom?: number; right: number } | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  // the popup is fixed to the viewport so scrolling table containers cannot clip it
  const toggle = () => {
    if (!open) {
      const r = ref.current?.getBoundingClientRect();
      if (r) setPos(r.bottom + 260 > window.innerHeight && r.top > 260 ? { bottom: window.innerHeight - r.top + 4, right: window.innerWidth - r.right } : { top: r.bottom + 4, right: window.innerWidth - r.right });
    }
    setOpen(!open);
  };
  useEffect(() => {
    if (!open) return;
    const t0 = Date.now();
    const close = () => Date.now() - t0 > 300 && setOpen(false);
    window.addEventListener('scroll', close, true);
    window.addEventListener('resize', close);
    const away = (e: MouseEvent) => !ref.current?.contains(e.target as Node) && setOpen(false);
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && setOpen(false);
    document.addEventListener('mousedown', away);
    document.addEventListener('keydown', esc);
    return () => { document.removeEventListener('mousedown', away); document.removeEventListener('keydown', esc); window.removeEventListener('scroll', close, true); window.removeEventListener('resize', close); };
  }, [open]);
  return (
    <div className="menu" ref={ref}>
      <button className="btn ghost sm icon" aria-label={label} aria-haspopup="menu" aria-expanded={open} onClick={toggle}>
        <svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor" aria-hidden><circle cx="5" cy="12" r="1.7" /><circle cx="12" cy="12" r="1.7" /><circle cx="19" cy="12" r="1.7" /></svg>
      </button>
      {open && (
        <div className="menu-pop" role="menu" style={{ position: 'fixed', top: pos?.top ?? 'auto', bottom: pos?.bottom ?? 'auto', right: pos?.right, left: 'auto' }}>
          {items.map((it, i) => it === 'sep'
            ? <hr key={i} />
            : <button key={i} role="menuitem" className={it.danger ? 'danger' : ''} disabled={it.disabled} onClick={() => { setOpen(false); it.onClick(); }}>
                <span>{it.label}</span>{it.hint && <small>{it.hint}</small>}
              </button>)}
        </div>
      )}
    </div>
  );
}
