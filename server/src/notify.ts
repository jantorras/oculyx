import type { Db } from './db.ts';

export interface Notice {
  severity: string;
  title: string;
  body: string;
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
        body: JSON.stringify({ text, content: text, ...n }),
        signal: AbortSignal.timeout(5000),
      }),
    );
  }
  if (tgToken && tgChat) {
    jobs.push(
      fetch(`https://api.telegram.org/bot${tgToken}/sendMessage`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ chat_id: tgChat, text }),
        signal: AbortSignal.timeout(5000),
      }),
    );
  }
  await Promise.allSettled(jobs);
}
