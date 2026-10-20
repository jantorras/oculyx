import { useEffect, useRef, useState } from 'react';
import { Terminal as XTerm } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import { api } from '../lib';
import { useT } from '../i18n';
import { Modal } from './ui';

/** A real SSH shell on the host, tunnelled through the server (which holds the key) into the browser. */
export function TerminalModal({ agentId, name, onClose }: { agentId: number; name: string; onClose: () => void }) {
  const t = useT();
  const box = useRef<HTMLDivElement>(null);
  const [status, setStatus] = useState<'connecting' | 'open' | 'closed'>('connecting');
  const [error, setError] = useState('');
  const [fp, setFp] = useState<{ first: boolean; key: string } | null>(null);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let disposed = false;
    const term = new XTerm({
      fontFamily: '"Geist Mono Variable", ui-monospace, Menlo, Consolas, monospace',
      fontSize: 13,
      cursorBlink: true,
      scrollback: 5000,
      theme: { background: '#0b0e13', foreground: '#d8dee9', cursor: '#2dd4a0', selectionBackground: '#2dd4a055' },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    if (box.current) {
      term.open(box.current);
      fit.fit();
    }
    const dec = new TextDecoder();

    (async () => {
      try {
        const { ticket } = await api<{ ticket: string }>(`/agents/${agentId}/terminal-ticket`, { method: 'POST', body: {} });
        if (disposed) return;
        const proto = location.protocol === 'https:' ? 'wss' : 'ws';
        ws = new WebSocket(`${proto}://${location.host}/ws/terminal?ticket=${ticket}`);
        ws.binaryType = 'arraybuffer';
        ws.onopen = () => ws!.send(JSON.stringify({ cols: term.cols, rows: term.rows }));
        ws.onmessage = (ev) => {
          if (typeof ev.data === 'string') {
            const m = JSON.parse(ev.data);
            if (m.t === 'ready') {
              setStatus('open');
              setFp({ first: m.firstUse, key: m.hostkey });
              term.focus();
            } else if (m.t === 'error') setError(m.message);
            return;
          }
          term.write(new Uint8Array(ev.data));
        };
        ws.onclose = () => {
          setStatus('closed');
          term.write('\r\n\x1b[2m[' + dec.decode(new Uint8Array(0)) + 'connection closed]\x1b[0m\r\n');
        };
        term.onData((d) => ws?.readyState === WebSocket.OPEN && ws.send(JSON.stringify({ t: 'in', d })));
        term.onResize(({ cols, rows }) => ws?.readyState === WebSocket.OPEN && ws.send(JSON.stringify({ t: 'resize', cols, rows })));
      } catch (e) {
        setError((e as Error).message);
        setStatus('closed');
      }
    })();

    const onWin = () => fit.fit();
    window.addEventListener('resize', onWin);
    const ro = box.current ? new ResizeObserver(() => fit.fit()) : null;
    if (box.current) ro?.observe(box.current);
    return () => {
      disposed = true;
      window.removeEventListener('resize', onWin);
      ro?.disconnect();
      ws?.close();
      term.dispose();
    };
  }, [agentId]);

  return (
    <Modal wide title={`${t('ssh.terminal')} · ${name}`} onClose={onClose}>
      {error && <div className="error" role="alert">{t(`err.${error}`) === `err.${error}` ? error : t(`err.${error}`)}</div>}
      {fp?.first && <div className="warn">{t('ssh.hostkey_pinned', { key: fp.key })}</div>}
      <div ref={box} style={{ height: 'min(60dvh, 520px)', background: '#0b0e13', borderRadius: 8, padding: 8, overflow: 'hidden' }} aria-label={t('ssh.terminal')} />
      <div className="muted" style={{ fontSize: 12 }}>{status === 'connecting' ? t('ssh.connecting') : status === 'open' ? t('ssh.logged') : t('ssh.closed')}</div>
    </Modal>
  );
}
