import type { Db } from './db.ts';
import type { Ai, Proposal } from './ai.ts';

/**
 * Telegram bot (long polling, no public URL needed). Only the chat configured for notifications may talk to it.
 * Cheap commands (/status, /alerts) answer without AI; anything else goes to the assistant.
 */
interface Deps {
  db: Db;
  ai: Ai;
  status: () => string;
  alertsText: () => string;
  /** runs an admin operation on a host, audited as the Telegram chat */
  run: (p: Proposal) => Promise<string>;
}

const MAX = 3900;

export class TelegramBot {
  private d: Deps;
  private running = false;
  private offset = 0;
  private history: { role: 'user' | 'assistant'; content: string }[] = [];
  private lastMsg = 0;
  constructor(d: Deps) { this.d = d; }

  private cfg() {
    return { token: this.d.db.setting('notify.telegram_token'), chat: this.d.db.setting('notify.telegram_chat'), on: this.d.db.setting('ai.telegram') === '1' };
  }

  start() {
    if (this.running) return;
    this.running = true;
    void this.loop();
  }
  stop() { this.running = false; }

  private async api(token: string, method: string, body: unknown, timeoutMs = 10_000): Promise<any> {
    const r = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs),
    });
    return r.json().catch(() => ({}));
  }

  private async send(token: string, chat: string, text: string, proposals: Proposal[] = []) {
    const keyboard = proposals.length
      ? { inline_keyboard: proposals.map((p) => [{ text: `Confirm: ${p.op} on ${p.host}`.slice(0, 60), callback_data: `ok:${p.id}` }, { text: 'Cancel', callback_data: `no:${p.id}` }]) }
      : undefined;
    const lines = proposals.map((p) => `\n> ${p.op} ${JSON.stringify(p.args)} on ${p.host}\n  ${p.reason}`).join('');
    await this.api(token, 'sendMessage', { chat_id: chat, text: (text + lines).slice(0, MAX) || '...', reply_markup: keyboard });
  }

  private async loop() {
    let wait = 2000;
    while (this.running) {
      const { token, chat, on } = this.cfg();
      if (!on || !token || !chat) { await new Promise((r) => setTimeout(r, 5000)); continue; }
      try {
        const res = await this.api(token, 'getUpdates', { offset: this.offset, timeout: 25, allowed_updates: ['message', 'callback_query'] }, 35_000);
        if (!res.ok) throw new Error(res.description ?? 'telegram error');
        wait = 2000;
        for (const u of res.result ?? []) {
          this.offset = u.update_id + 1;
          await this.handle(token, chat, u).catch(() => undefined);
        }
      } catch {
        await new Promise((r) => setTimeout(r, wait));
        wait = Math.min(wait * 2, 60_000);
      }
    }
  }

  private async handle(token: string, chat: string, u: any) {
    const cb = u.callback_query;
    const from = String(cb?.message?.chat?.id ?? u.message?.chat?.id ?? '');
    if (from !== String(chat)) return; // strangers get no answer at all
    if (cb) {
      const [verb, id] = String(cb.data ?? '').split(':');
      const p = this.d.ai.proposals.get(id);
      await this.api(token, 'answerCallbackQuery', { callback_query_id: cb.id });
      if (!p || p.used || Date.now() - p.created > 15 * 60_000) return this.send(token, chat, 'That proposal expired.');
      p.used = true;
      if (verb !== 'ok') return this.send(token, chat, 'Cancelled.');
      try { await this.send(token, chat, await this.d.run(p)); } catch (e) { await this.send(token, chat, `Failed: ${(e as Error).message}`); }
      return;
    }
    const text = String(u.message?.text ?? '').trim();
    if (!text) return;
    if (/^\/(start|help)\b/.test(text)) return this.send(token, chat, '/status: fleet at a glance\n/alerts: open alerts\nAnything else: ask me about your servers.');
    if (/^\/status\b/.test(text)) return this.send(token, chat, this.d.status());
    if (/^\/alerts\b/.test(text)) return this.send(token, chat, this.d.alertsText());
    if (Date.now() - this.lastMsg < 1500) return; // flood guard: every answer can cost money
    this.lastMsg = Date.now();
    await this.api(token, 'sendChatAction', { chat_id: chat, action: 'typing' });
    this.history.push({ role: 'user', content: text });
    this.history = this.history.slice(-8);
    try {
      const r = await this.d.ai.chat(this.history, 'telegram');
      this.history.push({ role: 'assistant', content: r.reply });
      await this.send(token, chat, r.reply, r.proposals);
    } catch (e) {
      this.history.pop();
      await this.send(token, chat, `AI: ${(e as Error).message}`);
    }
  }
}
