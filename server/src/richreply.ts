/**
 * Shared contract for "rich" AI replies. The model writes a small, fixed markdown template;
 * parseReply() turns it into blocks that the web UI (cards, grids, icons) and Telegram (HTML) both render.
 * Unknown or malformed input must degrade to a single { type: 'text' } block, never throw.
 *
 * Template (tags always English, prose in the user's language; every part is optional):
 *   > [high] One sentence: the overall state          summary, optional severity tag
 *   ## Title                                           titles the next stats/findings/steps block
 *   KPI: Disk = 81% [high]                             stat tile (or a 2-column pipe table)
 *   - [critical] Title | host | detail                 finding card (host and detail optional)
 *   1. Do this | why                                   step (detail optional)
 */
export type Sev = 'critical' | 'high' | 'medium' | 'low' | 'ok' | 'info';

export type Block =
  /** headline of the answer: overall state in one or two sentences */
  | { type: 'summary'; sev?: Sev; title?: string; text: string }
  /** compact key figures shown as a grid of tiles (disk 81%, 3 hosts online...) */
  | { type: 'stats'; title?: string; items: { label: string; value: string; sev?: Sev }[] }
  /** problems / items needing attention, one card each, most severe first */
  | { type: 'findings'; title?: string; items: { sev: Sev; title: string; detail?: string; host?: string }[] }
  /** ordered things to do next */
  | { type: 'steps'; title?: string; items: { text: string; detail?: string }[] }
  /** anything else; inline **bold** and `code` markers are kept as written */
  | { type: 'text'; text: string };

const SEV_WORDS: Record<string, Sev> = {
  critical: 'critical', crit: 'critical', severe: 'critical', fatal: 'critical',
  high: 'high', error: 'high', major: 'high',
  medium: 'medium', med: 'medium', warning: 'medium', warn: 'medium', moderate: 'medium',
  low: 'low', minor: 'low',
  ok: 'ok', good: 'ok', healthy: 'ok', success: 'ok', pass: 'ok',
  info: 'info', information: 'info', note: 'info', notice: 'info',
};

const MAX_INPUT = 20_000;
const MAX_ITEMS = 60;
const MAX_BLOCKS = 40;

const plain = (s: string) => s.replace(/\*\*(.+?)\*\*/g, '$1').replace(/\s+/g, ' ').trim();
const unbold = (s: string) => s.replace(/\*\*(.+?)\*\*/g, '$1').trim();
const sevOf = (w: string): Sev | undefined => SEV_WORDS[w.trim().toLowerCase()];

/** Leading "[tag]" (optionally bold) with a known severity word. */
function leadTag(s: string): { sev?: Sev; rest: string } {
  const m = /^\s*(?:\*\*)?\[\s*([A-Za-z]+)\s*\](?:\*\*)?\s*[:\-–—]?\s*/.exec(s);
  const sev = m ? sevOf(m[1]) : undefined;
  return m && sev ? { sev, rest: s.slice(m[0].length) } : { rest: s.trim() };
}

/** Trailing "[tag]" with a known severity word. */
function tailTag(s: string): { sev?: Sev; rest: string } {
  const m = /\s*(?:\*\*)?\[\s*([A-Za-z]+)\s*\](?:\*\*)?\s*$/.exec(s);
  const sev = m ? sevOf(m[1]) : undefined;
  return m && sev ? { sev, rest: s.slice(0, m.index).trim() } : { rest: s.trim() };
}

const RE_HEADING = /^\s{0,3}#{1,6}\s+(.*?)\s*#*\s*$/;
const RE_QUOTE = /^\s{0,3}>\s?(.*)$/;
const RE_KPI = /^\s*[-*•]?\s*(?:\*\*)?KPI(?:\*\*)?\s*[:=]\s*(.+)$/i;
const RE_BULLET = /^(\s*)[-*•+]\s+(.*)$/;
const RE_NUM = /^(\s*)\d{1,3}[.)]\s+(.*)$/;
const RE_RULE = /^\s*([-*_])\1{2,}\s*$/;
const RE_FENCE = /^\s*(```|~~~)/;
const RE_TABLE_ROW = /^\s*\|.*\|\s*$/;
const RE_SEPARATOR_ROW = /^[\s|:\-]+$/;

type Stat = { label: string; value: string; sev?: Sev };
type Run =
  | { kind: 'text'; lines: string[] }
  | { kind: 'quote'; lines: string[] }
  | { kind: 'stats'; items: Stat[] }
  | { kind: 'table'; rows: string[][] }
  | { kind: 'bullets'; base: number; raw: string[]; items: { tag?: Sev; body: string; extra: string[] }[] }
  | { kind: 'steps'; base: number; items: { text: string; detail?: string }[] };

function cells(line: string): string[] {
  return line.trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map((c) => c.trim());
}

function parseKpi(body: string): Stat | null {
  const { sev, rest } = tailTag(body);
  const eq = rest.indexOf('=');
  const i = eq >= 0 ? eq : rest.indexOf(':');
  if (i <= 0) return null;
  const label = plain(rest.slice(0, i));
  const value = unbold(rest.slice(i + 1));
  return label && value ? { label: label.slice(0, 80), value: value.slice(0, 120), ...(sev ? { sev } : {}) } : null;
}

function finding(sev: Sev, body: string): { sev: Sev; title: string; detail?: string; host?: string } {
  const parts = body.split('|').map((p) => p.trim());
  const title = plain(parts[0] ?? '');
  let host: string | undefined;
  let detail: string | undefined;
  if (parts.length >= 3) {
    host = plain(parts[1]) || undefined;
    detail = parts.slice(2).join(' | ').trim() || undefined;
  } else if (parts.length === 2) {
    // two parts: a short single token is the host, anything longer is the detail
    if (parts[1] && !/\s/.test(parts[1]) && parts[1].length <= 48) host = parts[1];
    else detail = parts[1] || undefined;
  }
  return { sev, title: title || 'Finding', ...(detail ? { detail } : {}), ...(host ? { host } : {}) };
}

export function parseReply(text: string): Block[] {
  try {
    return parse(text);
  } catch {
    const t = String(text ?? '').trim();
    return t ? [{ type: 'text', text: t }] : [];
  }
}

function tableStats(rows: string[][]): Stat[] {
  const isSep = (c: string[]) => RE_SEPARATOR_ROW.test(c.join('|'));
  const sepAt = rows.findIndex((c) => isSep(c) && c.some((x) => x.includes('-')));
  const data = rows.filter((c) => !isSep(c));
  const body = sepAt > 0 ? data.slice(1) : data; // the row before the separator is the header
  const items: Stat[] = [];
  for (const c of body) {
    if (c.length < 2 || !c[0]) continue;
    let value = c[1];
    let sev: Sev | undefined;
    const t = tailTag(value);
    if (t.sev) { sev = t.sev; value = t.rest; }
    const extra = c.slice(2).filter(Boolean);
    if (!sev && extra.length) {
      const s = sevOf(extra[extra.length - 1].replace(/[[\]*]/g, ''));
      if (s) { sev = s; extra.pop(); }
    }
    if (extra.length) value = [value, ...extra].join(' · ');
    items.push({ label: plain(c[0]).slice(0, 80), value: unbold(value).slice(0, 120), ...(sev ? { sev } : {}) });
  }
  return items;
}

function parse(input: string): Block[] {
  let src = String(input ?? '').replace(/\r\n?/g, '\n').slice(0, MAX_INPUT).trim();
  if (!src) return [];
  // some models wrap the whole answer in a ```markdown fence
  const wrapped = /^```(?:markdown|md|text)?[ \t]*\n([\s\S]*?)\n?```$/i.exec(src);
  if (wrapped && !wrapped[1].includes('```')) src = wrapped[1].trim();

  const blocks: Block[] = [];
  let title: string | undefined;
  let run: Run | null = null;
  let inFence = false;

  const takeTitle = () => { const t = title; title = undefined; return t; };
  const textBlock = (t: string) => { if (t.trim()) blocks.push({ type: 'text', text: t.trim() }); };

  const flush = () => {
    const r = run;
    run = null;
    if (!r) return;
    switch (r.kind) {
      case 'text': {
        const body = r.lines.join('\n').trim();
        const t = takeTitle();
        if (body) textBlock(t ? `**${t}**\n${body}` : body);
        else if (t) textBlock(`**${t}**`);
        break;
      }
      case 'quote': {
        const { sev, rest } = leadTag(r.lines.join(' ').trim());
        if (rest) {
          const t = takeTitle();
          blocks.push({ type: 'summary', ...(sev ? { sev } : {}), ...(t ? { title: t } : {}), text: rest });
        }
        break;
      }
      case 'stats':
        if (r.items.length) { const t = takeTitle(); blocks.push({ type: 'stats', ...(t ? { title: t } : {}), items: r.items.slice(0, MAX_ITEMS) }); }
        break;
      case 'table': {
        const items = tableStats(r.rows);
        if (items.length) { const t = takeTitle(); blocks.push({ type: 'stats', ...(t ? { title: t } : {}), items: items.slice(0, MAX_ITEMS) }); }
        else textBlock(r.rows.map((c) => c.join(' | ')).join('\n'));
        break;
      }
      case 'bullets': {
        const t = takeTitle();
        if (r.items.some((i) => i.tag)) {
          blocks.push({
            type: 'findings', ...(t ? { title: t } : {}),
            items: r.items.slice(0, MAX_ITEMS).map((i) => {
              const f = finding(i.tag ?? 'info', i.body);
              const more = i.extra.join(' ').trim();
              if (more) f.detail = f.detail ? `${f.detail} ${more}` : more;
              return f;
            }),
          });
        } else {
          const body = r.raw.join('\n').trim();
          textBlock(t ? `**${t}**\n${body}` : body);
        }
        break;
      }
      case 'steps': {
        const t = takeTitle();
        blocks.push({ type: 'steps', ...(t ? { title: t } : {}), items: r.items.slice(0, MAX_ITEMS) });
        break;
      }
    }
  };

  const flushTitleAsText = () => { const t = takeTitle(); if (t) textBlock(`**${t}**`); };
  const normBullet = (l: string) => l.replace(/^(\s*)[*•+]\s/, '$1- ');

  for (const line of src.split('\n')) {
    if (RE_FENCE.test(line)) {
      // code fences are kept verbatim inside a text block
      if (run?.kind !== 'text') { flush(); run = { kind: 'text', lines: [] }; }
      run.lines.push(line);
      inFence = !inFence;
      continue;
    }
    if (inFence) { if (run?.kind === 'text') run.lines.push(line); continue; }

    if (!line.trim() || RE_RULE.test(line)) {
      if (run?.kind === 'text') run.lines.push('');
      else if (run?.kind === 'quote') flush();
      continue; // other runs survive blank lines so numbered lists and KPI groups stay together
    }

    const indent = line.length - line.trimStart().length;

    // indented continuation of a bullet or step
    if (run && (run.kind === 'steps' || run.kind === 'bullets') && indent > run.base && run.items.length) {
      const cont = line.trim().replace(/^[-*•+]\s+/, '').replace(/^\d{1,3}[.)]\s+/, '');
      if (run.kind === 'steps') {
        const it = run.items[run.items.length - 1];
        it.detail = it.detail ? `${it.detail} ${cont}` : cont;
      } else {
        run.items[run.items.length - 1].extra.push(cont);
        run.raw.push(normBullet(line));
      }
      continue;
    }

    let m: RegExpExecArray | null;

    if ((m = RE_HEADING.exec(line))) {
      flush(); flushTitleAsText();
      title = plain(m[1]).slice(0, 100) || undefined;
      continue;
    }
    if ((m = RE_QUOTE.exec(line))) {
      if (run?.kind !== 'quote') { flush(); run = { kind: 'quote', lines: [] }; }
      run.lines.push(m[1]);
      continue;
    }
    if ((m = RE_KPI.exec(line))) {
      const k = parseKpi(m[1]);
      if (k) {
        if (run?.kind !== 'stats') { flush(); run = { kind: 'stats', items: [] }; }
        run.items.push(k);
        continue;
      }
    }
    if (RE_TABLE_ROW.test(line)) {
      if (run?.kind !== 'table') { flush(); run = { kind: 'table', rows: [] }; }
      run.rows.push(cells(line));
      continue;
    }
    if ((m = RE_NUM.exec(line))) {
      if (run?.kind !== 'steps') { flush(); run = { kind: 'steps', base: m[1].length, items: [] }; }
      const [head, ...rest] = m[2].split('|');
      const detail = rest.join('|').trim();
      run.items.push({ text: unbold(head) || '-', ...(detail ? { detail } : {}) });
      continue;
    }
    if ((m = RE_BULLET.exec(line))) {
      if (run?.kind !== 'bullets') { flush(); run = { kind: 'bullets', base: m[1].length, raw: [], items: [] }; }
      const { sev, rest } = leadTag(m[2]);
      run.items.push({ ...(sev ? { tag: sev } : {}), body: sev ? rest : m[2], extra: [] });
      run.raw.push(normBullet(line));
      continue;
    }
    // plain prose
    if (run?.kind !== 'text') { flush(); run = { kind: 'text', lines: [] }; }
    run.lines.push(line.trimEnd());
  }
  flush();
  flushTitleAsText();

  const out = blocks.slice(0, MAX_BLOCKS);
  return out.length ? out : [{ type: 'text', text: src }];
}
