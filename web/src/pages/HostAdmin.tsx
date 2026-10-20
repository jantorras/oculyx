import { useState, type ReactNode } from 'react';
import { api, usePoll } from '../lib';
import { useT } from '../i18n';
import { Empty } from '../components/ui';
import { Menu, ask, toast } from '../components/overlay';

type Section = 'accounts' | 'services' | 'network' | 'system';

/** Day-to-day administration of one host, one topic at a time: accounts, services, network and system. */
export function HostAdmin({ agentId }: { agentId: number }) {
  const t = useT();
  const { data, error, refresh } = usePoll(() => api<any>(`/agents/${agentId}/admin`), 15000, [agentId]);
  const [section, setSection] = useState<Section>('accounts');
  const [busy, setBusy] = useState('');
  const [ip, setIp] = useState('');
  const [port, setPort] = useState('');
  const [svcQ, setSvcQ] = useState('');
  const [onlyActive, setOnlyActive] = useState(false);

  if (error && !data) return <p className="error" role="alert">{String(error)}</p>;
  if (!data) return <p className="muted">{t('common.loading')}</p>;
  const can: boolean = data.canManage;
  const lock = !can || !!busy;

  const run = async (label: string, op: string, args: Record<string, unknown> = {}): Promise<void> => {
    setBusy(label);
    try {
      const r = await api<{ steps: string[] }>(`/agents/${agentId}/admin`, { body: { op, args } });
      toast((r.steps ?? []).join(' · ') || t('common.saved'));
      refresh();
    } catch (e) {
      const m = (e as Error).message;
      if (op === 'ip.block' && !args.force && /connected over SSH/.test(m) && (await ask({ title: t('adm.ssh_peer_title'), body: m, confirm: t('adm.block'), danger: true }))) {
        setBusy('');
        return run(label, op, { ...args, force: true });
      }
      toast(m, 'error');
    } finally {
      setBusy('');
    }
  };
  /** Ask first, then run. */
  const sure = async (title: string, body: ReactNode, label: string, op: string, args: Record<string, unknown>, confirm: string, danger = false) => {
    if (await ask({ title, body, confirm, danger })) await run(label, op, args);
  };

  const users: any[] = data.users;
  const services: any[] = data.services;
  const failed = services.filter((s) => s.active === 'failed').length;
  const banned: string[] = data.banned;
  const nav: { id: Section; label: string; badge?: string | number; warn?: boolean }[] = [
    { id: 'accounts', label: t('adm.users'), badge: users.length },
    { id: 'services', label: t('adm.services'), badge: failed || undefined, warn: failed > 0 },
    { id: 'network', label: t('adm.network'), badge: banned.length || undefined },
    { id: 'system', label: t('adm.system'), badge: data.updates?.pending || undefined, warn: data.rebootRequired },
  ];

  const head = (title: string, help: string) => (
    <div className="sec-head">
      <div className="grow"><h2>{title}</h2><p className="muted">{help}</p></div>
    </div>
  );

  const q = svcQ.trim().toLowerCase();
  const shown = services.filter((s) => (!onlyActive || s.active === 'active') && (!q || `${s.unit} ${s.description}`.toLowerCase().includes(q))).slice(0, 100);

  return (
    <div className="admin-layout">
      <nav className="subnav" aria-label={t('adm.tab')}>
        {nav.map((n) => (
          <button key={n.id} className={section === n.id ? 'active' : ''} onClick={() => setSection(n.id)}>
            <span>{n.label}</span>
            {n.badge !== undefined && <i className={n.warn ? 'warn' : ''}>{n.badge}</i>}
          </button>
        ))}
      </nav>

      <div className="admin-body">
        {!can && <div className="notice">{t('sshw.readonly')}</div>}

        {section === 'accounts' && (
          <section>
            {head(t('adm.users'), t('adm.users_help'))}
            <div className="panel">
              <table className="rows">
                <thead><tr><th>{t('ssh.user')}</th><th>{t('adm.access')}</th><th /></tr></thead>
                <tbody>{users.map((u) => {
                  const self = u.user === data.sshUser;
                  const sess = (data.sessions as any[]).filter((s) => s.user === u.user);
                  const items: any[] = u.uid === 0 ? [] : [
                    u.locked
                      ? { label: t('adm.unlock'), onClick: () => run(`u:${u.user}`, 'user.unlock', { user: u.user }) }
                      : { label: t('adm.lock'), onClick: () => sure(t('adm.lock_title', { user: u.user }), t('adm.confirm_lock', { user: u.user }), `u:${u.user}`, 'user.lock', { user: u.user }, t('adm.lock')) },
                    { label: t('adm.kick'), disabled: sess.length === 0, onClick: () => sure(t('adm.kick'), t('adm.confirm_kick', { user: u.user }), `u:${u.user}`, 'user.kill-sessions', { user: u.user }, t('adm.kick')) },
                    { label: t('adm.expire'), onClick: () => run(`u:${u.user}`, 'user.expire-password', { user: u.user }) },
                    u.sudo
                      ? { label: t('adm.sudo_off'), onClick: () => sure(t('adm.sudo_off'), t('adm.confirm_sudo_off', { user: u.user }), `u:${u.user}`, 'user.sudo', { user: u.user, enable: false }, t('adm.sudo_off'), true) }
                      : { label: t('adm.sudo_on'), onClick: () => sure(t('adm.sudo_on'), t('adm.confirm_sudo_on', { user: u.user }), `u:${u.user}`, 'user.sudo', { user: u.user, enable: true }, t('adm.sudo_on'), true) },
                    'sep',
                    { label: t('common.delete'), danger: true, onClick: () => sure(t('adm.delete_title', { user: u.user }), t('adm.confirm_delete', { user: u.user }), `u:${u.user}`, 'user.delete', { user: u.user, confirm: true }, t('common.delete'), true) },
                  ];
                  return (
                    <tr key={u.user}>
                      <td><div className="who"><b>{u.user}</b><span className="mono muted">uid {u.uid}</span></div></td>
                      <td>
                        <div className="tags">
                          {u.sudo && <span className="tag">sudo</span>}
                          {u.locked && <span className="tag bad">{t('adm.locked')}</span>}
                          {!u.login && <span className="tag mute">{t('adm.no_shell')}</span>}
                          {self && <span className="tag accent">{t('adm.panel_account')}</span>}
                          {sess.length > 0 && <span className="tag ok">{t('adm.n_sessions', { n: sess.length })}</span>}
                        </div>
                      </td>
                      <td className="act">{items.length > 0 && <Menu label={t('adm.more')} items={lock ? items.map((i) => (i === 'sep' ? i : { ...i, disabled: true })) : items} />}</td>
                    </tr>
                  );
                })}</tbody>
              </table>
            </div>
          </section>
        )}

        {section === 'services' && (
          <section>
            {head(t('adm.services'), t('adm.services_help'))}
            <div className="toolbar">
              <input type="search" value={svcQ} onChange={(e) => setSvcQ(e.target.value)} placeholder={t('adm.search')} aria-label={t('adm.search')} />
              <label className="check"><input type="checkbox" checked={onlyActive} onChange={(e) => setOnlyActive(e.target.checked)} />{t('adm.only_running')}</label>
            </div>
            <div className="panel">
              <table className="rows">
                <thead><tr><th>{t('adm.services')}</th><th>{t('adm.state')}</th><th>{t('adm.boot')}</th><th /></tr></thead>
                <tbody>{shown.map((s) => {
                  const on = s.active === 'active';
                  const bootable = s.enabled === 'enabled' || s.enabled === 'disabled';
                  const name = s.unit.replace(/\.service$/, '');
                  return (
                    <tr key={s.unit}>
                      <td><div className="who"><b>{name}</b><span className="muted desc">{s.description}</span></div></td>
                      <td><span className={`state ${on ? 'on' : s.active === 'failed' ? 'fail' : ''}`}><i />{t(`adm.st_${on ? 'running' : s.active === 'failed' ? 'failed' : 'stopped'}`)}</span></td>
                      <td>{bootable
                        ? <button className={`toggle ${s.enabled === 'enabled' ? 'on' : ''}`} role="switch" aria-checked={s.enabled === 'enabled'} aria-label={`${t('adm.boot')}: ${name}`} disabled={lock}
                            onClick={() => (s.enabled === 'enabled'
                              ? sure(t('adm.boot_off_title', { unit: name }), t('adm.boot_off_body'), `s:${s.unit}`, 'svc.disable', { unit: s.unit }, t('adm.disable'), true)
                              : run(`s:${s.unit}`, 'svc.enable', { unit: s.unit }))}><i /></button>
                        : <span className="muted">{s.enabled || '-'}</span>}</td>
                      <td className="act"><div className="row" style={{ gap: 6, justifyContent: 'flex-end' }}>
                        {on
                          ? <button className="btn sm" disabled={lock} onClick={() => sure(t('adm.restart'), t('adm.confirm_svc', { unit: name, verb: t('adm.restart') }), `s:${s.unit}`, 'svc.restart', { unit: s.unit }, t('adm.restart'))}>{t('adm.restart')}</button>
                          : <button className="btn sm primary" disabled={lock} onClick={() => run(`s:${s.unit}`, 'svc.start', { unit: s.unit })}>{t('adm.start')}</button>}
                        {on && <Menu label={t('adm.more')} items={[{ label: t('adm.stop'), danger: true, disabled: lock, onClick: () => sure(t('adm.stop'), t('adm.confirm_svc', { unit: name, verb: t('adm.stop') }), `s:${s.unit}`, 'svc.stop', { unit: s.unit }, t('adm.stop'), true) }]} />}
                      </div></td>
                    </tr>
                  );
                })}</tbody>
              </table>
              {shown.length === 0 && <Empty>{t('servers.none')}</Empty>}
            </div>
          </section>
        )}

        {section === 'network' && (
          <section>
            {head(t('adm.network'), t('adm.network_help'))}

            <h3 className="sub">{t('adm.ips')}</h3>
            <p className="muted small">{t('adm.ips_help')}</p>
            <form className="toolbar" onSubmit={(e) => { e.preventDefault(); const v = ip.trim(); if (v) { setIp(''); void sure(t('adm.block_title', { ip: v }), t('adm.confirm_block', { ip: v }), `ip:${v}`, 'ip.block', { ip: v }, t('adm.block'), true); } }}>
              <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="203.0.113.7  ·  198.51.100.0/24" spellCheck={false} aria-label="IP" />
              <button className="btn primary" disabled={lock || !ip.trim()}>{t('adm.block')}</button>
            </form>
            <div className="split">
              <div>
                <div className="cap">{t('adm.attackers')}</div>
                <div className="panel">
                  {data.attackers.length === 0 ? <Empty>{t('adm.no_attackers')}</Empty> : (
                    <table className="rows"><tbody>{data.attackers.map((a: any) => (
                      <tr key={a.ip}>
                        <td className="mono">{a.ip}</td>
                        <td className="muted num">{a.attempts} {t('adm.attempts')}</td>
                        <td className="act">{banned.includes(a.ip) ? <span className="tag bad">{t('adm.blocked')}</span>
                          : <button className="btn sm" disabled={lock} onClick={() => sure(t('adm.block_title', { ip: a.ip }), t('adm.confirm_block', { ip: a.ip }), `ip:${a.ip}`, 'ip.block', { ip: a.ip }, t('adm.block'), true)}>{t('adm.block')}</button>}</td>
                      </tr>))}</tbody></table>
                  )}
                </div>
              </div>
              <div>
                <div className="cap">{t('adm.blocked_list')}</div>
                <div className="panel">
                  {banned.length === 0 ? <Empty>{t('adm.none_blocked')}</Empty> : (
                    <table className="rows"><tbody>{banned.map((b) => (
                      <tr key={b}><td className="mono">{b}</td><td className="act"><button className="btn sm" disabled={lock} onClick={() => run(`unb:${b}`, 'ip.unblock', { ip: b })}>{t('adm.unblock')}</button></td></tr>))}</tbody></table>
                  )}
                </div>
              </div>
            </div>

            <h3 className="sub" style={{ marginTop: 28 }}>{t('adm.firewall')}</h3>
            <div className="fw-state">
              <span className={`state ${data.firewall.active ? 'on' : ''}`}><i />{data.firewall.active ? t('adm.fw_on') : t('adm.fw_off')}</span>
              {!data.firewall.active && <a className="btn sm" href={`#/hosts/${agentId}/security`}>{t('adm.fw_enable')}</a>}
            </div>
            {data.firewall.active && (
              <>
                <form className="toolbar" onSubmit={(e) => { e.preventDefault(); if (port) { const p = Number(port); setPort(''); void run('fw:open', 'fw.open', { port: p, proto: 'tcp' }); } }}>
                  <input type="number" min={1} max={65535} value={port} onChange={(e) => setPort(e.target.value)} placeholder="443" aria-label="port" style={{ width: 140 }} />
                  <button className="btn primary" disabled={lock || !port}>{t('adm.open_port')}</button>
                </form>
                <div className="panel">
                  {(data.firewall.rules as string[]).length === 0 ? <Empty>{t('adm.no_rules')}</Empty> : (
                    <table className="rows"><tbody>{(data.firewall.rules as string[]).map((r) => {
                      const m = r.match(/^(\d+)(?:\/(tcp|udp))?\s+ALLOW IN\s+Anywhere$/);
                      return (
                        <tr key={r}><td className="mono">{r}</td>
                          <td className="act">{m && <button className="btn sm" disabled={lock} onClick={() => sure(t('adm.close_title', { port: m[1] }), t('adm.confirm_close', { port: m[1] }), 'fw:close', 'fw.close', { port: Number(m[1]), proto: m[2] ?? 'tcp' }, t('adm.close_port'), true)}>{t('adm.close_port')}</button>}</td></tr>
                      );
                    })}</tbody></table>
                  )}
                </div>
              </>
            )}
          </section>
        )}

        {section === 'system' && (
          <section>
            {head(t('adm.system'), t('adm.system_help'))}
            <div className="panel list">
              <div className="item">
                <div className="grow">
                  <b>{t('adm.updates')}</b>
                  <p className="muted small">{data.updates ? t('adm.updates_n', { n: data.updates.pending, s: data.updates.security }) : t('adm.updates_unknown')}</p>
                </div>
                <button className="btn primary" disabled={lock || (data.updates && data.updates.pending === 0)} onClick={() => sure(t('adm.apply_updates'), t('adm.confirm_updates'), 'upd', 'updates.apply', { confirm: true }, t('adm.apply_updates'))}>{busy === 'upd' ? t('sshw.working') : t('adm.apply_updates')}</button>
              </div>
              <div className="item">
                <div className="grow">
                  <b>{t('adm.reboot')} {data.rebootRequired && <span className="tag warn">{t('adm.reboot_needed')}</span>}</b>
                  <p className="muted small">{t('adm.reboot_help')}</p>
                </div>
                <button className="btn" disabled={lock} onClick={() => run('rb', 'system.cancel-reboot')}>{t('adm.cancel_reboot')}</button>
                <button className="btn danger" disabled={lock} onClick={() => sure(t('adm.reboot_btn'), t('adm.confirm_reboot'), 'rb', 'system.reboot', { confirm: true }, t('adm.reboot_btn'), true)}>{t('adm.reboot_btn')}</button>
              </div>
            </div>
          </section>
        )}
      </div>
    </div>
  );
}
