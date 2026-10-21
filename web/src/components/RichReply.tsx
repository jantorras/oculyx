import type { ReactNode } from 'react';
import { useT } from '../i18n';
import { Icon } from './ui';

// Keep this contract identical to server/src/richreply.ts; the web never imports server code.
export type Sev = 'critical' | 'high' | 'medium' | 'low' | 'ok' | 'info';
export type Block =
  | { type: 'summary'; sev?: Sev; title?: string; text: string }
  | { type: 'stats'; title?: string; items: { label: string; value: string; sev?: Sev }[] }
  | { type: 'findings'; title?: string; items: { sev: Sev; title: string; detail?: string; host?: string }[] }
  | { type: 'steps'; title?: string; items: { text: string; detail?: string }[] }
  | { type: 'text'; text: string };

/** Only recognize paired inline markers. All content remains escaped React text. */
function inline(text: string): ReactNode[] {
  return text.split(/(`[^`\n]+`|\*\*(?:(?!\*\*)[^\n])+\*\*)/g).map((part, i) => {
    if (part.startsWith('`') && part.endsWith('`') && part.length > 2) return <code key={i}>{part.slice(1, -1)}</code>;
    if (part.startsWith('**') && part.endsWith('**') && part.length > 4) {
      return <strong key={i}>{part.slice(2, -2).split(/(`[^`\n]+`)/g).map((s, j) => s.startsWith('`') && s.endsWith('`') ? <code key={j}>{s.slice(1, -1)}</code> : s)}</strong>;
    }
    return part;
  });
}

function Paragraphs({ text }: { text: string }) {
  return <>{text.split(/\n\s*\n/).filter((p) => p.trim()).map((p, i) => <p key={i}>{inline(p)}</p>)}</>;
}

function Severity({ sev }: { sev: Sev }) {
  const t = useT();
  return <span className={`rr-severity rr-${sev}`}><span className="rr-icon" aria-hidden="true">{sev === 'ok' ? Icon.check : sev === 'info' ? Icon.chat : Icon.bell}</span>{t(`ai.severity.${sev}`)}</span>;
}

export function RichReply({ blocks, fallback }: { blocks: Block[]; fallback: string }) {
  const t = useT();
  if (!blocks.length) return <div className="bubble">{fallback}</div>;

  return <div className="rich-reply">{blocks.map((block, i) => {
    switch (block.type) {
      case 'summary':
        return <section key={i} className={`rr-summary rr-${block.sev ?? 'info'}`}>
          <Severity sev={block.sev ?? 'info'} />
          {block.title && <h3>{inline(block.title)}</h3>}
          <div className="rr-summary-text"><Paragraphs text={block.text} /></div>
        </section>;
      case 'stats':
        return <section key={i} className="rr-section" aria-label={block.title || t('ai.stats')}>
          {block.title && <h3>{inline(block.title)}</h3>}
          <dl className="rr-stats">{block.items.map((item, j) => <div key={j} className={`rr-stat rr-${item.sev ?? 'info'}`}>
            <dt>{inline(item.label)}</dt><dd><span>{inline(item.value)}</span>{item.sev && <Severity sev={item.sev} />}</dd>
          </div>)}</dl>
        </section>;
      case 'findings':
        return <section key={i} className="rr-section" aria-label={block.title || t('ai.findings')}>
          {block.title && <h3>{inline(block.title)}</h3>}
          <ul className="rr-findings">{block.items.map((item, j) => <li key={j} className={`rr-finding rr-${item.sev}`}>
            <div className="rr-card-meta"><Severity sev={item.sev} />{item.host && <span className="rr-host"><span className="rr-icon" aria-hidden="true">{Icon.hosts}</span>{item.host}</span>}</div>
            <h4>{inline(item.title)}</h4>
            {item.detail && <div className="rr-detail"><Paragraphs text={item.detail} /></div>}
          </li>)}</ul>
        </section>;
      case 'steps':
        return <section key={i} className="rr-section" aria-label={block.title || t('ai.steps')}>
          {block.title && <h3>{inline(block.title)}</h3>}
          <ol className="rr-steps">{block.items.map((item, j) => <li key={j}>
            <span className="rr-step-number" aria-hidden="true">{j + 1}</span>
            <div><div className="rr-step-text">{inline(item.text)}</div>{item.detail && <div className="rr-detail"><Paragraphs text={item.detail} /></div>}</div>
          </li>)}</ol>
        </section>;
      case 'text':
        return <div key={i} className="rr-text"><Paragraphs text={block.text} /></div>;
    }
  })}</div>;
}
