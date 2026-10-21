import type { Block, Sev } from './richreply.ts';
import { parseReply } from './richreply.ts';

export const SEVERITY_EMOJI: Record<Sev, string> = {
  critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', ok: '🟢', info: '⚪',
};
const icon = (sev?: string) => SEVERITY_EMOJI[sev as Sev] ?? SEVERITY_EMOJI.info;
const separator = '\n\n────────\n\n';

export function escapeHtml(text: string): string {
  return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/** Only our own markup is emitted; model-supplied HTML is always literal text. */
function inline(text: string): string {
  return text.split(/(`[^`\n]+`|\*\*[^*\n]+\*\*)/g).map((part) => {
    if (part.startsWith('`') && part.endsWith('`')) return `<code>${escapeHtml(part.slice(1, -1))}</code>`;
    if (part.startsWith('**') && part.endsWith('**')) return `<b>${escapeHtml(part.slice(2, -2))}</b>`;
    return escapeHtml(part);
  }).join('');
}

export function blocksToTelegramHtml(blocks: Block[]): string {
  return blocks.map((block) => {
    switch (block.type) {
      case 'summary': return `${icon(block.sev)} <b>${escapeHtml(block.title ?? 'Summary')}</b>\n${inline(block.text)}`;
      case 'stats': {
        // Two columns, padded before escaping so entity lengths do not affect alignment.
        const cells = block.items.map((item) => `${icon(item.sev)} ${item.label}: ${item.value}`.replace(/\s+/g, ' '));
        const width = Math.max(0, ...cells.filter((_, i) => i % 2 === 0).map((s) => Array.from(s).length));
        const rows: string[] = [];
        for (let i = 0; i < cells.length; i += 2) {
          rows.push(cells[i] + (cells[i + 1] ? ' '.repeat(width - Array.from(cells[i]).length + 3) + cells[i + 1] : ''));
        }
        return `📊 <b>${escapeHtml(block.title ?? 'Stats')}</b>\n<pre>${escapeHtml(rows.join('\n'))}</pre>`;
      }
      case 'findings': return `🔎 <b>${escapeHtml(block.title ?? 'Findings')}</b>\n` + block.items.map((item) =>
        `${icon(item.sev)} <b>${escapeHtml(item.title)}</b>${item.host ? `\n🖥 <code>${escapeHtml(item.host)}</code>` : ''}${item.detail ? `\n${inline(item.detail)}` : ''}`,
      ).join('\n\n');
      case 'steps': return `🛠 <b>${escapeHtml(block.title ?? 'Next steps')}</b>\n` + block.items.map((item, i) =>
        `<b>${i + 1}.</b> ${inline(item.text)}${item.detail ? `\n<i>${inline(item.detail)}</i>` : ''}`,
      ).join('\n\n');
      case 'text': return inline(block.text);
    }
  }).filter(Boolean).join(separator);
}

export interface TelegramAlert {
  severity: string;
  host: string;
  rule: string;
  message: string;
  why?: string;
  guidance?: string;
}

export function alertToTelegramHtml(a: TelegramAlert): string {
  return `${icon(a.severity)} <b>${escapeHtml(a.severity.toUpperCase())} · Alert</b>\n\n` +
    `🖥 <b>Host</b> <code>${escapeHtml(a.host)}</code>\n` +
    `🔎 <b>Rule</b> ${escapeHtml(a.rule)}\n\n${inline(a.message)}` +
    (a.guidance ? `\n\n🛠 ${inline(a.guidance)}` : '') +
    (a.why ? `\n\n💡 <b>Why</b>\n<blockquote>${inline(a.why)}</blockquote>` : '');
}

export function digestToTelegramHtml(title: string, body: string): string {
  return `📋 <b>${escapeHtml(title)}</b>\n\n${blocksToTelegramHtml(parseReply(body))}`;
}

export function statusToTelegramHtml(body: string, title = 'Fleet status'): string {
  return `🖥 <b>${escapeHtml(title)}</b>\n\n${blocksToTelegramHtml(parseReply(body))}`;
}

export function telegramHtmlToText(html: string): string {
  return html.replace(/<[^>]*>/g, '').replace(/&(amp|lt|gt|quot|#39);/g, (_, entity: string) =>
    ({ amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'" })[entity]!);
}

/** Split only between tokens, balancing open tags in every independently sent chunk.
 * The raw HTML budget is conservative: Telegram counts text after entity parsing.
 */
export function splitMessage(html: string, limit = 4096): string[] {
  if (!Number.isInteger(limit) || limit < 32) throw new RangeError('Message limit must be at least 32');
  if (!html) return [];
  const tokens = html.match(/<[^>]*>|&(?:#\d+|#x[\da-f]+|[a-z]+);|[^<&]|[<&]/giu) ?? [];
  const chunks: string[] = [];
  const stack: { tag: string; open: string }[] = [];
  const close = () => stack.slice().reverse().map(({ tag }) => `</${tag}>`).join('');
  let chunk = '';
  let hasContent = false;
  for (const token of tokens) {
    const opening = /^<([a-z]+)(?:\s[^>]*)?>$/i.exec(token);
    const closing = /^<\/([a-z]+)>$/i.exec(token);
    const nextClose = opening ? `</${opening[1]}>` + close() : closing ? close().replace(`</${closing[1]}>`, '') : close();
    if (chunk.length + token.length + nextClose.length > limit) {
      if (!hasContent) throw new RangeError('HTML nesting or token exceeds message limit');
      chunks.push(chunk + close());
      chunk = stack.map(({ open }) => open).join('');
      hasContent = false;
      if (chunk.length + token.length + nextClose.length > limit) throw new RangeError('HTML token exceeds message limit');
    }
    chunk += token;
    if (opening) stack.push({ tag: opening[1], open: token });
    else if (closing) stack.pop();
    else hasContent = true;
  }
  if (chunk) chunks.push(chunk + close());
  return chunks;
}
