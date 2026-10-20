// Opens the panel's terminal websocket, runs a command through the SSH session and checks the output.
import WebSocket from 'ws';

const url = process.argv[2];
const ws = new WebSocket(url);
let out = '';
const timer = setTimeout(() => {
  console.error('timeout; output so far:', JSON.stringify(out.slice(-300)));
  process.exit(2);
}, 25_000);

ws.on('open', () => ws.send(JSON.stringify({ cols: 100, rows: 30 })));
ws.on('message', (data, isBinary) => {
  if (!isBinary) {
    const m = JSON.parse(data.toString());
    if (m.t === 'ready') ws.send(JSON.stringify({ t: 'in', d: 'echo OCX_$((6*7))_done\n' }));
    if (m.t === 'error') {
      console.error('terminal error:', m.message);
      process.exit(3);
    }
    return;
  }
  out += data.toString();
  if (out.includes('OCX_42_done')) {
    clearTimeout(timer);
    ws.close();
    process.exit(0);
  }
});
ws.on('error', (e) => {
  console.error('ws error:', e.message);
  process.exit(4);
});
ws.on('close', () => {
  if (!out.includes('OCX_42_done')) process.exit(5);
});
