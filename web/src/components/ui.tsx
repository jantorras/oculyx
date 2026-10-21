import { useEffect, type ReactNode } from 'react';
import { useT } from '../i18n';
import { scoreTone } from '../lib';

const I = (d: string) => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
    <path d={d} />
  </svg>
);
export const Icon = {
  overview: I('M3 12h4l3-8 4 16 3-8h4'),
  hosts: I('M4 5h16v6H4zM4 13h16v6H4zM8 8h.01M8 16h.01'),
  sliders: I('M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M14 4v4M8 10v4M16 16v4'),
  chat: I('M21 12a8 8 0 01-11.7 7.1L4 20l1-4.6A8 8 0 1121 12zM8.5 11.5h.01M12 11.5h.01M15.5 11.5h.01'),
  docker: I('M3 13h18M5 13V9h3v4M9 13V9h3v4M13 13V9h3v4M9 9V6h3v3M2 13c1 5 5 7 10 7 6 0 9-3 10-7'),
  shield: I('M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z'),
  checks: I('M9 4h10v17H5V4h4M9 3h6v4H9zM8 12l2 2 4-4M8 18h8'),
  close: I('M6 6l12 12M18 6L6 18'),
  bell: I('M6 9a6 6 0 1112 0c0 6 2 7 2 7H4s2-1 2-7M10 20a2 2 0 004 0'),
  log: I('M5 4h14v16H5zM9 9h6M9 13h6M9 17h3'),
  gear: I('M12 15a3 3 0 100-6 3 3 0 000 6zM19 12l2-1-2-4-2 1a7 7 0 00-2-1V5h-4v2a7 7 0 00-2 1L7 7 5 11l2 1v2l-2 1 2 4 2-1a7 7 0 002 1v2h4v-2a7 7 0 002-1l2 1 2-4-2-1z'),
  menu: I('M4 6h16M4 12h16M4 18h16'),
  play: I('M7 5l12 7-12 7z'),
  stop: I('M6 6h12v12H6z'),
  restart: I('M4 12a8 8 0 108-8M4 4v5h5'),
  doc: I('M6 3h9l4 4v14H6zM14 3v5h5'),
  sun: I('M12 17a5 5 0 100-10 5 5 0 000 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4'),
  moon: I('M21 13A9 9 0 1111 3a7 7 0 0010 10z'),
  check: I('M5 12.5l4.5 4.5L19 7.5'),
  clock: I('M12 7v5l3 2M21 12a9 9 0 11-18 0 9 9 0 0118 0z'),
  arrow: I('M5 12h14M13 6l6 6-6 6'),
};

export const Logo = () => (
  <svg width="26" height="26" viewBox="0 0 32 32" aria-hidden>
    <circle cx="16" cy="16" r="12" fill="none" stroke="var(--accent)" strokeWidth="2.4" />
    <circle cx="16" cy="16" r="4.2" fill="var(--accent)" />
    <path d="M16 2v5M16 25v5M2 16h5M25 16h5" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round" opacity="0.5" />
  </svg>
);

export function SevPill({ sev }: { sev: string }) {
  const t = useT();
  return <span className={`pill ${sev}`}>{t(`sev.${sev}`)}</span>;
}

export function StatusDot({ online }: { online: boolean }) {
  const t = useT();
  return (
    <span className="row" style={{ gap: 7 }}>
      <i className={`dot ${online ? 'on' : 'off'}`} />
      <span className="muted">{online ? t('status.online') : t('status.offline')}</span>
    </span>
  );
}

export function Score({ value, large }: { value: number | null; large?: boolean }) {
  return (
    <span className={`score ${value == null ? 'na' : scoreTone(value)} ${large ? 'lg' : ''}`} style={{ ['--p' as string]: value ?? 0 }} title={value == null ? '' : `${value}/100`}>
      {value ?? '–'}
    </span>
  );
}

export function Meter({ value, text }: { value: number | null | undefined; text?: string }) {
  if (value == null) return <span className="muted">-</span>;
  const tone = value >= 90 ? 'bad' : value >= 75 ? 'warn' : '';
  return (
    <div className="meter">
      <span className="n">{text ?? `${value.toFixed(0)}%`}</span>
      <div className="bar">
        <i className={tone} style={{ width: `${Math.min(100, value)}%` }} />
      </div>
    </div>
  );
}

export function Kpi({ label, value, unit, hint, tone, icon }: { label: string; value: ReactNode; unit?: string; hint?: ReactNode; tone?: string; icon: ReactNode }) {
  return (
    <div className="card kpi" style={tone ? ({ ['--k' as string]: `var(--${tone})` } as React.CSSProperties) : undefined}>
      <span className="label">{label}</span>
      <span className="ico">{icon}</span>
      <span className="value">{value}{unit && <small> {unit}</small>}</span>
      {hint && <span className="hint">{hint}</span>}
    </div>
  );
}

export function Tile({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: ReactNode; tone?: string }) {
  return (
    <div className="card tile">
      <span className="label">{label}</span>
      <span className="value" style={tone ? { color: `var(--${tone})` } : undefined}>
        {value}
      </span>
      {hint && <span className="hint">{hint}</span>}
    </div>
  );
}

export const Empty = ({ children }: { children: ReactNode }) => <div className="empty">{children}</div>;

export function Card({ title, actions, children, flush }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; flush?: boolean }) {
  return (
    <section className="card">
      {(title || actions) && (
        <header>
          <h2 className="grow">{title}</h2>
          {actions}
        </header>
      )}
      <div className={flush ? '' : 'body'}>{children}</div>
    </section>
  );
}

/** Layout-shaped placeholder shown while the first request is in flight. */
export function Skeleton({ kpis = 4, blocks = 2 }: { kpis?: number; blocks?: number }) {
  return (
    <div aria-busy="true" aria-live="polite">
      <div className="sk sk-title" />
      <div className="grid g4" style={{ marginBottom: 16 }}>
        {Array.from({ length: kpis }, (_, i) => <div key={i} className="sk sk-kpi" />)}
      </div>
      <div className="grid g2">
        {Array.from({ length: blocks }, (_, i) => <div key={i} className="sk sk-block" />)}
      </div>
    </div>
  );
}

/** Centered dialog with a dimmed backdrop; Esc and a backdrop click close it. */
export function Modal({ title, onClose, children, wide }: { title: ReactNode; onClose: () => void; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`modal ${wide ? 'wide' : ''}`} role="dialog" aria-modal="true" aria-label={typeof title === 'string' ? title : undefined}>
        <header><h2 className="grow">{title}</h2><button className="btn sm" onClick={onClose} aria-label="Close">×</button></header>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}
