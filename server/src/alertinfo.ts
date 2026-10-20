import { readFileSync } from 'node:fs';

/** What every alert means and what to do about it, in each language (alertinfo.json). */
type Entry = { meaning: string; todo: string };
const CATALOG: Record<string, Record<string, Entry>> = JSON.parse(readFileSync(new URL('./alertinfo.json', import.meta.url), 'utf8'));

export const alertCatalog = () => CATALOG;

/** `rule` is the stored alert rule, e.g. "ssh_bruteforce:ab12cd34" or "finding:Redis exposed". */
export function alertInfo(rule: string, lang: string): Entry | null {
  const id = rule.split(':')[0];
  const e = CATALOG[id];
  return e ? (e[lang] ?? e.en) : null;
}
