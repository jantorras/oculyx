import { useState } from 'react';
import { api, usePoll } from '../lib';
import { useT } from '../i18n';
import { Card, Empty } from '../components/ui';

/** Day-to-day administration of one host: blocked IPs, accounts, services, firewall, updates and reboot. */
export function HostAdmin({ agentId }: { agentId: number }) {
  const t = useT();
  const { data, error, refresh } = usePoll(() => api<any>(`/agents/${agentId}/admin`), 15000, [agentId]);
  const [busy, setBusy] = useState('');
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [ip, setIp] = useState('');
  const [port, setPort] = useState('');
  const [svcQ, setSvcQ] = useState('');
  const [onlyActive, setOnlyActive] = useState(false);

  if (error && !data) return <p className="error" role="alert">{t(`err.${error}`) === `err.${error}` ? String(error) : t(`err.${error}`)}</p>;
  if (!data) return <p className="muted">{t('common.loading')}</p>;
  const can: boolean = data.canManage;

  const run = async (label: string, op: string, args: Record<string, unknown> = {}, ask?: string) => {
    if (ask && !confirm(ask)) return;
    setBusy(label);
    setMsg(null);
    try {
      const r = await api<{ steps: string[] }>(`/agents/${agentId}/admin`, { body: { op, args } });
      setMsg({ ok: true, text: (r.steps ?? []).join(' · ') || t('common.saved') });
      refresh();
    } catch (e) {
      const m = (e as Error).message;
      if (op === 'ip.block' && !args.force && /connected over SSH/.test(m) && confirm(`${m}

${t('adm.confirm_force')}`)) {
        setBusy('');
        return run(label, op, { ...args, force: true });
      }
      setMsg({ ok: false, text: m });
    } finally {
      setBusy('');
    }
  };
  const disabled = !can || !!busy;
  const blockIp = (v: string) => run(`ip:${v}`, 'ip.block', { ip: v }, t('adm.confirm_block', { ip: v }));

  const q = svcQ.trim().toLowerCase();
  const services = (data.services as any[]).filter((s) => (!onlyActive || s.active === 'active') && (!q || `${s.unit} ${s.description}`.toLowerCase().includes(q))).slice(0, 80);
  const btn = (label: string, onClick: () => void, cls = 'btn sm', off = disabled) => <button className={cls} disabled={off} onClick={onClick}>{label}</button>;

  return (
    <div className="grid" style={{ maxWidth: 1100 }}>
      {!can && <div className="warn">{t('sshw.readonly')}</div>}
      {msg && <div className={msg.ok ? '' : 'error'} role={msg.ok ? 'status' : 'alert'} style={{ color: msg.ok ? 'var(--ok)' : undefined }}>{msg.text}</div>}

      <Card title={t('adm.ips')}>
        <p className="muted" style={{ marginTop: 0, fontSize: 13 }}>{t('adm.ips_help')}</p>
        <form className="row wrap" style={{ gap: 8, marginBottom: 14 }} onSubmit={(e) => { e.preventDefault(); if (ip.trim()) { void blockIp(ip.trim()); setIp(''); } }}>
          <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="203.0.113.7  /  198.51.100.0/24" spellCheck={false} style={{ width: 320, maxWidth: '100%' }} aria-label="IP" />
          <button className="btn primary" disabled={disabled || !ip.trim()}>{t('adm.block')}</button>
        </form>
        <div className="muted" style={{ fontSize: 12, textTransform: 'uppercase', letterSpacing: '.04em', marginBottom: 6 }}>{t('adm.attackers')}</div>
        {data.attackers.length === 0 ? <Empty>{t('adm.no_attackers')}</Empty> : (
          <div className="table-wrap"><table><tbody>
            {data.attackers.map((a: any) => {
              const isBlocked = (data.banned as string[]).includes(a.ip);
              return (
                <tr key={a.ip}>
                  <td className="mono">{a.ip}</td>
                  <td className="muted num">{a.attempts} {t('adm.attempts')}</td>
                  <td className="r">{isBlocked ? <span className="pill">{t('adm.blocked')}</span> : btn(t('adm.block'), () => blockIp(a.ip))}</td>
                </tr>
              );
            })}
          </tbody></table></div>
        )}
        <div className="muted" style={{ fontSize: 12, textTransform: 'uppercase', letterSpacing: '.04em', margin: '16px 0 6px' }}>{t('adm.blocked_list')}</div>
        {(data.banned as string[]).length === 0 ? <Empty>{t('adm.none_blocked')}</Empty> : (
          <div className="row wrap" style={{ gap: 8 }}>
            {(data.banned as string[]).map((b) => <span key={b} className="pill mono" style={{ display: 'inline-flex', gap: 8, alignItems: 'center' }}>{b}<button className="btn sm" disabled={disabled} onClick={() => run(`unb:${b}`, 'ip.unblock', { ip: b })}>{t('adm.unblock')}</button></span>)}
          </div>
        )}
      </Card>

      <Card title={t('adm.users')} flush>
        <div className="table-wrap"><table>
          <thead><tr><th>{t('ssh.user')}</th><th>uid</th><th>{t('adm.state')}</th><th /></tr></thead>
          <tbody>{(data.users as any[]).map((u) => {
            const self = u.user === data.sshUser;
            const row = (what: string) => `${what}: ${u.user}`;
            return (
              <tr key={u.user}>
                <td style={{ fontWeight: 600 }}>{u.user}{self && <span className="pill" style={{ marginLeft: 8 }}>{t('adm.panel_account')}</span>}</td>
                <td className="muted num">{u.uid}</td>
                <td>
                  {u.locked && <span className="pill" style={{ marginRight: 6 }}>{t('adm.locked')}</span>}
                  {u.sudo && <span className="pill" style={{ marginRight: 6 }}>sudo</span>}
                  {!u.login && <span className="muted" style={{ fontSize: 12 }}>{t('adm.no_shell')}</span>}
                </td>
                <td className="r">
                  {u.uid !== 0 && (
                    <div className="row wrap" style={{ gap: 6, justifyContent: 'flex-end' }}>
                      {u.locked ? btn(t('adm.unlock'), () => run(row('unlock'), 'user.unlock', { user: u.user })) : btn(t('adm.lock'), () => run(row('lock'), 'user.lock', { user: u.user }, t('adm.confirm_lock', { user: u.user })))}
                      {btn(t('adm.kick'), () => run(row('kick'), 'user.kill-sessions', { user: u.user }, t('adm.confirm_kick', { user: u.user })))}
                      {btn(t('adm.expire'), () => run(row('expire'), 'user.expire-password', { user: u.user }))}
                      {u.sudo ? btn(t('adm.sudo_off'), () => run(row('sudo'), 'user.sudo', { user: u.user, enable: false }, t('adm.confirm_sudo_off', { user: u.user }))) : btn(t('adm.sudo_on'), () => run(row('sudo'), 'user.sudo', { user: u.user, enable: true }, t('adm.confirm_sudo_on', { user: u.user })))}
                      {btn(t('common.delete'), () => run(row('del'), 'user.delete', { user: u.user, confirm: true }, t('adm.confirm_delete', { user: u.user })), 'btn sm danger')}
                    </div>
                  )}
                </td>
              </tr>
            );
          })}</tbody>
        </table></div>
        {(data.sessions as any[]).length > 0 && (
          <div className="body muted" style={{ fontSize: 13, borderTop: '1px solid var(--line)' }}>
            <b>{t('adm.sessions')}:</b> {(data.sessions as any[]).map((s) => `${s.user}@${s.tty}${s.from ? ` (${s.from})` : ''}`).join(', ')}
          </div>
        )}
      </Card>

      <Card title={t('adm.firewall')}>
        <div className="row wrap" style={{ gap: 8, alignItems: 'center', marginBottom: 10 }}>
          <span className="pill" style={{ color: data.firewall.active ? 'var(--ok)' : undefined }}>{data.firewall.active ? t('adm.fw_on') : t('adm.fw_off')}</span>
          {!data.firewall.active && <a className="btn sm" href={`#/hosts/${agentId}/security`}>{t('adm.fw_enable')}</a>}
        </div>
        {data.firewall.active && (
          <>
            <form className="row wrap" style={{ gap: 8, marginBottom: 12 }} onSubmit={(e) => { e.preventDefault(); if (port) { void run('fw:open', 'fw.open', { port: Number(port), proto: 'tcp' }); setPort(''); } }}>
              <input type="number" min={1} max={65535} value={port} onChange={(e) => setPort(e.target.value)} placeholder="443" style={{ width: 120 }} aria-label="port" />
              <button className="btn primary" disabled={disabled || !port}>{t('adm.open_port')}</button>
            </form>
            {(data.firewall.rules as string[]).length === 0 ? <Empty>{t('adm.no_rules')}</Empty> : (
              <div className="table-wrap"><table><tbody>{(data.firewall.rules as string[]).map((r) => {
                const m = r.match(/^(\d+)(?:\/(tcp|udp))?\s+ALLOW IN\s+Anywhere$/);
                return (
                  <tr key={r}><td className="mono" style={{ fontSize: 12.5 }}>{r}</td>
                    <td className="r">{m && btn(t('adm.close_port'), () => run('fw:close', 'fw.close', { port: Number(m[1]), proto: m[2] ?? 'tcp' }, t('adm.confirm_close', { port: m[1] })))}</td></tr>
                );
              })}</tbody></table></div>
            )}
          </>
        )}
      </Card>

      <Card title={t('adm.services')} flush>
        <div className="body row wrap" style={{ gap: 10, alignItems: 'center' }}>
          <input type="search" value={svcQ} onChange={(e) => setSvcQ(e.target.value)} placeholder={t('adm.search')} style={{ width: 300, maxWidth: '100%' }} aria-label="search" />
          <label className="row" style={{ gap: 6, fontSize: 13, whiteSpace: 'nowrap', flexWrap: 'nowrap' }}><input type="checkbox" checked={onlyActive} onChange={(e) => setOnlyActive(e.target.checked)} />{t('adm.only_running')}</label>
        </div>
        <div className="table-wrap"><table>
          <tbody>{services.map((s) => (
            <tr key={s.unit}>
              <td><div style={{ fontWeight: 600 }}>{s.unit.replace(/\.service$/, '')}</div><div className="muted" style={{ fontSize: 12 }}>{s.description}</div></td>
              <td><span className="pill" style={{ color: s.active === 'active' ? 'var(--ok)' : s.active === 'failed' ? 'var(--crit, #f0616d)' : undefined }}>{s.active}</span> <span className="muted" style={{ fontSize: 12 }}>{s.enabled}</span></td>
              <td className="r"><div className="row" style={{ gap: 6, justifyContent: 'flex-end' }}>
                {s.active === 'active'
                  ? <>{btn(t('adm.restart'), () => run(`svc:${s.unit}`, 'svc.restart', { unit: s.unit }, t('adm.confirm_svc', { unit: s.unit, verb: t('adm.restart') })))}{btn(t('adm.stop'), () => run(`svc:${s.unit}`, 'svc.stop', { unit: s.unit }, t('adm.confirm_svc', { unit: s.unit, verb: t('adm.stop') })))}</>
                  : btn(t('adm.start'), () => run(`svc:${s.unit}`, 'svc.start', { unit: s.unit }))}
                {s.enabled === 'enabled' ? btn(t('adm.disable'), () => run(`svc:${s.unit}`, 'svc.disable', { unit: s.unit }, t('adm.confirm_svc', { unit: s.unit, verb: t('adm.disable') }))) : s.enabled === 'disabled' ? btn(t('adm.enable'), () => run(`svc:${s.unit}`, 'svc.enable', { unit: s.unit })) : null}
              </div></td>
            </tr>
          ))}</tbody>
        </table></div>
      </Card>

      <Card title={t('adm.system')}>
        <div className="row wrap" style={{ gap: 12, alignItems: 'center' }}>
          <div className="grow" style={{ minWidth: 220 }}>
            <div style={{ fontWeight: 600 }}>{t('adm.updates')}</div>
            <div className="muted" style={{ fontSize: 13 }}>{data.updates ? t('adm.updates_n', { n: data.updates.pending, s: data.updates.security }) : t('adm.updates_unknown')}</div>
          </div>
          <button className="btn primary" disabled={disabled || (data.updates && data.updates.pending === 0)} onClick={() => run('upd', 'updates.apply', { confirm: true }, t('adm.confirm_updates'))}>{busy === 'upd' ? t('sshw.working') : t('adm.apply_updates')}</button>
        </div>
        <div className="row wrap" style={{ gap: 12, alignItems: 'center', marginTop: 16, paddingTop: 16, borderTop: '1px solid var(--line)' }}>
          <div className="grow" style={{ minWidth: 220 }}>
            <div style={{ fontWeight: 600 }}>{t('adm.reboot')} {data.rebootRequired && <span className="pill" style={{ marginLeft: 6 }}>{t('adm.reboot_needed')}</span>}</div>
            <div className="muted" style={{ fontSize: 13 }}>{t('adm.reboot_help')}</div>
          </div>
          {btn(t('adm.cancel_reboot'), () => run('rb', 'system.cancel-reboot'), 'btn')}
          <button className="btn danger" disabled={disabled} onClick={() => run('rb', 'system.reboot', { confirm: true }, t('adm.confirm_reboot'))}>{t('adm.reboot_btn')}</button>
        </div>
      </Card>
    </div>
  );
}
