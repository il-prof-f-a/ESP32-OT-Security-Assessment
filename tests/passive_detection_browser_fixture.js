// Offline browser fixture: node tests/passive_detection_browser_fixture.js
// Open http://127.0.0.1:8768/ids?sid=fixture&run_tests=1 in a browser.
// All API operations stay in this in-memory fixture, never on a device.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const root = path.join(__dirname, '..');
let flags = {ids_enabled: true, network_presence_enabled: true, signatures_enabled: true};
let signatures = {'Modbus TCP': {Vulnerabilities: [{CVE: 'CVE-2024-12345', Name: 'Fixture signature', Packet: {Bytes: '01 02', FunctionCode: '0x03'}, Description: 'Local test record', References: ['https://example.test/reference']}]}};
let whitelist = {enabled: true, action: 'alert', ip: ['10.0.0.0/24'], mac: ['AA:BB:CC:*:*:*'], per_protocol: {'Modbus TCP': {ip: ['192.0.2.1'], mac: []}}};
let presence = {learning_mode: true, activation_delay_minutes: 10, retention_days: 30, trust_threshold_score: 0.75, min_observation_period_hours: 24};
const devices = [
  {ip_address: '192.0.2.10', mac_address: '00:11:22:33:44:55', protocols: ['Modbus TCP', 'Unknown'], presence_score: 0.8, total_packets: 10, total_read_packets: 10, last_seen_ms: 90000, is_learned_sender: true},
  {ip_address: '192.0.2.20', mac_address: '00:11:22:33:44:66', protocols: ['S7'], presence_score: 0.6, total_packets: 8, total_write_packets: 4, last_seen_ms: 80000}
];
let requests = [];
const initialState = JSON.stringify({flags, signatures, whitelist, presence});
const stats = () => ({total: Object.values(signatures).reduce((n, p) => n + p.Vulnerabilities.length, 0), by_protocol: Object.fromEntries(Object.entries(signatures).map(([p, v]) => [p, v.Vulnerabilities.length]))});
const presenceStats = () => ({devices, total_devices: devices.length, current_time_ms: 100000});
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  let body = ''; for await (const part of req) body += part;
  let data = {}; try {data = JSON.parse(body || '{}');} catch {}
  const json = (payload, status = 200) => {res.writeHead(status, {'Content-Type': 'application/json'}); res.end(JSON.stringify(payload));};
  if (url.pathname === '/fixture/requests') return json(requests);
  if (url.pathname === '/browser-tests.js') {
    res.writeHead(200, {'Content-Type': 'text/javascript'});
    return res.end(fs.readFileSync(path.join(__dirname, 'passive_detection_native.test.js')));
  }
  if (!url.pathname.startsWith('/api/')) {
    let html = fs.readFileSync(path.join(root, 'src/web/ui/passive_detection.html'), 'utf8');
    if (url.searchParams.has('run_tests')) {
      ({flags, signatures, whitelist, presence} = JSON.parse(initialState));
      requests = [];
      html = html.replace('<script>', `<script>window.__fixtureIntervals = new Map(); window.setInterval = (fn, ms) => {const id = Math.random(); window.__fixtureIntervals.set(id, fn); return id;}; window.clearInterval = id => window.__fixtureIntervals.delete(id); window.confirm = () => true;</script><script>`);
      html = html.replace('</body>', '<script src="/browser-tests.js"></script></body>');
    }
    res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'}); return res.end(html);
  }
  requests.push({path: url.pathname, method: req.method, body: data});
  if (url.pathname === '/api/passive-detection/config') {
    if (req.method === 'POST') Object.assign(flags, data);
    return json({...flags, runtime: {...flags}});
  }
  if (url.pathname === '/api/page/bootstrap') {
    switch (url.searchParams.get('name')) {
      case 'ids': return json({data: {config: {ip_whitelist: whitelist, ids: {protocol_specific: {}}}, protocols: {'1': 'Modbus TCP', '2': 'S7'}, ids_stats: {allowed: 7, alert: 2, dropped: 1}, presence_learned: {devices: [{address: '192.0.2.30', trusted: true}]}}});
      case 'network_presence': return json({data: {presence_config: presence, presence_stats: presenceStats(), presence_devices: presenceStats()}});
      case 'signatures': return json({data: {stats: stats(), list: signatures}});
    }
  }
  if (url.pathname === '/api/whitelist') {if (req.method === 'POST') whitelist = data.ip_whitelist; return json({ip_whitelist: whitelist});}
  if (url.pathname === '/api/protocols') return json({'1': 'Modbus TCP', '2': 'S7'});
  if (url.pathname === '/api/ids/stats') return json({allowed: 8, alert: 3, dropped: 1});
  if (url.pathname === '/api/ids/presence/config') {if (req.method === 'POST') Object.assign(presence, data); return json(presence);}
  if (['/api/ids/presence/stats', '/api/ids/presence/devices'].includes(url.pathname)) return json(presenceStats());
  if (url.pathname === '/api/network-presence/learned') return json({devices: [{address: '192.0.2.30', trusted: true}]});
  if (url.pathname === '/api/signatures/list' || url.pathname === '/api/signatures/download') return json(signatures);
  if (url.pathname === '/api/signatures/stats') return json(stats());
  if (url.pathname === '/api/signatures/save') signatures = data.signatures;
  if (url.pathname === '/api/signatures/upload') signatures = data;
  if (url.pathname === '/api/signatures/clear') signatures = {};
  return json({success: true, message: 'Fixture saved', signatures_added: 1, signatures_loaded: stats().total});
});
server.listen(8768, '127.0.0.1', () => console.log('Offline passive UI fixture: http://127.0.0.1:8768/ids?sid=fixture&run_tests=1'));
