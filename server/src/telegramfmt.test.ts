import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Block, Sev } from './richreply.ts';
import { alertToTelegramHtml, blocksToTelegramHtml, digestToTelegramHtml, escapeHtml, SEVERITY_EMOJI, splitMessage, statusToTelegramHtml, telegramHtmlToText } from './telegramfmt.ts';
import { TelegramBot } from './telegram.ts';
import { notify } from './notify.ts';
import type { Db } from './db.ts';
import type { Proposal } from './ai.ts';

test('escapes all untrusted HTML characters, including host quotes', () => {
  const value = `<host a="x" b='y'>&`;
  assert.equal(escapeHtml(value), '&lt;host a=&quot;x&quot; b=&#39;y&#39;&gt;&amp;');
  const html = alertToTelegramHtml({ severity: 'high', host: value, rule: value, message: value, why: value, guidance: value });
  assert.equal(html.split(escapeHtml(value)).length - 1, 5);
  assert.ok(!html.includes('<host'));
});

test('renders every severity in alerts and findings', () => {
  for (const sev of Object.keys(SEVERITY_EMOJI) as Sev[]) {
    assert.ok(alertToTelegramHtml({ severity: sev, host: 'h', rule: 'r', message: 'm' }).startsWith(SEVERITY_EMOJI[sev]));
    assert.ok(blocksToTelegramHtml([{ type: 'findings', items: [{ sev, title: 'Issue' }] }]).includes(SEVERITY_EMOJI[sev]));
  }
});

test('empty blocks and messages are empty', () => {
  assert.equal(blocksToTelegramHtml([]), '');
  assert.deepEqual(splitMessage(''), []);
});

test('renders all block variants, safe inline styles, and two stats columns', () => {
  const blocks: Block[] = [
    { type: 'summary', title: '<Summary>', sev: 'high', text: '**Bold** and `<script>`' },
    { type: 'stats', title: '<Stats>', items: [{ label: 'CPU', value: '80%', sev: 'medium' }, { label: 'RAM', value: '<20%', sev: 'ok' }, { label: 'Disk', value: '50%' }] },
    { type: 'findings', title: '<Findings>', items: [{ sev: 'critical', title: '<Issue>', host: '<host>', detail: '<detail>' }] },
    { type: 'steps', title: '<Steps>', items: [{ text: '<restart>', detail: '<why>' }] },
    { type: 'text', text: '<b>unsafe</b> **safe** `code`' },
  ];
  const html = blocksToTelegramHtml(blocks);
  assert.ok(html.includes('<b>Bold</b> and <code>&lt;script&gt;</code>'));
  assert.match(html, /<pre>🟡 CPU: 80% +🟢 RAM: &lt;20%\n⚪ Disk: 50%<\/pre>/);
  assert.ok(html.includes('<b>1.</b> &lt;restart&gt;'));
  assert.ok(html.includes('&lt;b&gt;unsafe&lt;/b&gt; <b>safe</b> <code>code</code>'));
  for (const field of ['Summary', 'Stats', 'Findings', 'Issue', 'host', 'detail', 'Steps', 'why']) assert.ok(html.includes(`&lt;${field}&gt;`));
});

test('digest and status parse structured replies and escape titles', () => {
  assert.ok(digestToTelegramHtml('<digest>', '> [ok] Healthy\nKPI: CPU = 10%').includes('<pre>⚪ CPU: 10%</pre>'));
  assert.ok(statusToTelegramHtml('<host>', '<status>').includes('&lt;status&gt;'));
});

test('long HTML is split into balanced chunks without breaking entities or emoji', () => {
  const html = `<b>Header</b><blockquote><i>${escapeHtml('🟠 <host> & "quoted" '.repeat(900))}</i></blockquote>`;
  const chunks = splitMessage(html);
  assert.ok(chunks.length > 1);
  for (const chunk of chunks) {
    assert.ok(chunk.length <= 4096);
    const stack: string[] = [];
    for (const tag of chunk.match(/<[^>]+>/g) ?? []) {
      if (tag.startsWith('</')) assert.equal(stack.pop(), tag.slice(2, -1));
      else stack.push(tag.slice(1, -1));
    }
    assert.deepEqual(stack, []);
    assert.ok(!/[\uD800-\uDBFF]$|^[\uDC00-\uDFFF]/u.test(telegramHtmlToText(chunk)));
    assert.ok(!chunk.replace(/&(?:amp|lt|gt|quot|#39);/g, '').includes('&'));
  }
  assert.equal(chunks.map(telegramHtmlToText).join(''), telegramHtmlToText(html));
});

test('split also preserves long plain text and exact boundary messages', () => {
  assert.deepEqual(splitMessage('a'.repeat(4096)), ['a'.repeat(4096)]);
  assert.equal(splitMessage('a'.repeat(9000)).join(''), 'a'.repeat(9000));
  assert.throws(() => splitMessage('a', 10), RangeError);
});

test('bot retries rejected HTML as plain text and keeps proposal keyboard', async () => {
  const bot = new TelegramBot({} as ConstructorParameters<typeof TelegramBot>[0]);
  const calls: { text: string; parse_mode?: string; reply_markup?: unknown }[] = [];
  // Replace the transport itself: this test cannot send any network request.
  const transport = bot as unknown as {
    api: (...args: unknown[]) => Promise<unknown>;
    send: (token: string, chat: string, html: string, proposals: Proposal[]) => Promise<void>;
  };
  transport.api = async (_token, _method, body) => {
    calls.push(body as typeof calls[number]);
    return calls.length === 1 ? { ok: false, description: "Bad Request: can't parse entities" } : { ok: true };
  };
  await transport.send('fake', 'fake', '<b>Safe &amp; sound</b>', [
    { id: 'p1', op: 'restart', host: '<host>', args: {}, reason: '<reason>' } as Proposal,
  ]);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].parse_mode, 'HTML');
  assert.equal(calls[1].parse_mode, undefined);
  assert.ok(calls[0].text.includes('&lt;host&gt;'));
  assert.ok(calls[1].text.includes('Safe & sound'));
  assert.deepEqual(calls[1].reply_markup, calls[0].reply_markup);
  assert.ok(JSON.stringify(calls[0].reply_markup).includes('ok:p1'));
  assert.ok(JSON.stringify(calls[0].reply_markup).includes('no:p1'));
});

test('notifications preserve webhook payload and use HTML alert cards and digest blocks', async (t) => {
  const calls: { url: string; body: Record<string, unknown> }[] = [];
  t.mock.method(globalThis, 'fetch', async (url: string, options: RequestInit) => {
    calls.push({ url, body: JSON.parse(String(options.body)) });
    return { json: async () => ({ ok: true }) };
  });
  const settings: Record<string, string> = { 'notify.webhook': 'https://example.invalid/webhook', 'notify.telegram_token': 'fake', 'notify.telegram_chat': 'fake' };
  const db = { setting: (key: string) => settings[key] ?? '' } as Db;
  await notify(db, { severity: 'high', title: 'Original title', body: 'Original body',
    alert: { severity: 'high', host: '<host>', rule: 'cpu', message: '<message>', why: '<why>' },
  });
  assert.deepEqual(calls[0].body, { text: '🟠 Original title\nOriginal body', content: '🟠 Original title\nOriginal body', severity: 'high', title: 'Original title', body: 'Original body' });
  assert.equal(calls[1].body.parse_mode, 'HTML');
  assert.ok(String(calls[1].body.text).includes('<blockquote>&lt;why&gt;</blockquote>'));
  await notify(db, { severity: 'info', title: 'Digest', body: 'KPI: CPU = 10%\nKPI: RAM = 20%' });
  assert.ok(String(calls[3].body.text).includes('<pre>⚪ CPU: 10%   ⚪ RAM: 20%</pre>'));
});
