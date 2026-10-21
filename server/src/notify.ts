import type { Db } from './db.ts';
import { alertToTelegramHtml, blocksToTelegramHtml, escapeHtml, splitMessage, telegramHtmlToText } from './telegramfmt.ts';
import type { TelegramAlert } from './telegramfmt.ts';
import { parseReply } from './richreply.ts';

export interface Notice {
  severity: string;
  title: string;
  body: string;
  alert?: TelegramAlert;
}

const ICON: Record<string, string> = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪', ok: '🟢' };

/** Fire-and-forget delivery to the webhook and Telegram targets configured in settings. */
export async function notify(db: Db, n: Notice): Promise<void> {
  const webhook = db.setting('notify.webhook');
  const tgToken = db.setting('notify.telegram_token');
  const tgChat = db.setting('notify.telegram_chat');
  const text = `${ICON[n.severity] ?? ''} ${n.title}\n${n.body}`.trim();
  const jobs: Promise<unknown>[] = [];
  if (webhook) {
    jobs.push(
      fetch(webhook, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ text, content: text, severity: n.severity, title: n.title, body: n.body }),
        signal: AbortSignal.timeout(5000),
      }),
    );
  }
  if (tgToken && tgChat) {
    jobs.push((async () => {
      const html = n.alert ? alertToTelegramHtml(n.alert) : `📋 <b>${escapeHtml(n.title)}</b>\n\n${blocksToTelegramHtml(parseReply(n.body))}`;
      for (const part of splitMessage(html)) {
        const send = (body: object) => fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ chat_id: tgChat, ...body }), signal: AbortSignal.timeout(5000),
        });
        const response = await send({ text: part, parse_mode: 'HTML' });
        const result = await response.json().catch(() => ({})) as { ok?: boolean; description?: string };
        if (!result.ok && /can.?t parse entities/i.test(result.description ?? '')) {
          await send({ text: telegramHtmlToText(part) });
        }
      }
    })());
  }
  await Promise.allSettled(jobs);
}
